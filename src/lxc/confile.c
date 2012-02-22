/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <sys/personality.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>

#include "parse.h"
#include "confile.h"
#include "utils.h"
#include "config.h"
#include "confile.h"
#include "namespace.h"

#include <lxc/log.h>
#include <lxc/conf.h>

lxc_log_define(lxc_confile, lxc);

typedef int (*config_cb)(const char *, char *, struct lxc_conf *);

struct config {
	const char *name;
	config_cb cb;
};

static const struct config *getconfig(const char *key);

static const char *get_netdev_typename(const enum lxc_network_type_t type)
{
	switch(type) {
		case LXC_NET_UNUSED:
			return "unused";
		case LXC_NET_EMPTY:
			return "empty";
		case LXC_NET_VETH:
			return "veth";
		case LXC_NET_MACVLAN:
			return "macvlan";
		case LXC_NET_PHYS:
			return "phys";
		case LXC_NET_VLAN:
			return "vlan";
		default:
			return "unknown";
	}
}

static void lxc_init_interface_attr(struct lxc_interface_attr *attr)
{
	lxc_list_init(&attr->ipv4);
	lxc_list_init(&attr->ipv6);
}

static void lxc_netdev_init_veth(struct lxc_netdev *netdev)
{
	netdev->type = LXC_NET_VETH;
	lxc_init_interface_attr(&netdev->priv.veth_attr.host_attr);
}

static int config_network_type(const char *key, char *value,
			       struct lxc_conf *lxc_conf)
{
	struct lxc_list *network = &lxc_conf->network;
	struct lxc_netdev *netdev;
	struct lxc_list *list;

	netdev = malloc(sizeof(*netdev));
	if (!netdev) {
		SYSERROR("failed to allocate memory");
		return -1;
	}

	memset(netdev, 0, sizeof(*netdev));
	lxc_init_interface_attr(&netdev->guest_attr);

	list = malloc(sizeof(*list));
	if (!list) {
		SYSERROR("failed to allocate memory");
		return -1;
	}

	lxc_list_init(list);
	list->elem = netdev;

	lxc_list_add_tail(network, list);

	if (!strcmp(value, "veth"))
		lxc_netdev_init_veth(netdev);
	else if (!strcmp(value, "macvlan"))
		netdev->type = LXC_NET_MACVLAN;
	else if (!strcmp(value, "vlan"))
		netdev->type = LXC_NET_VLAN;
	else if (!strcmp(value, "phys"))
		netdev->type = LXC_NET_PHYS;
	else if (!strcmp(value, "empty"))
		netdev->type = LXC_NET_EMPTY;
	else {
		ERROR("invalid network type %s", value);
		return -1;
	}
	return 0;
}

static int config_ip_prefix(struct in_addr *addr)
{
	if (IN_CLASSA(addr->s_addr))
		return 32 - IN_CLASSA_NSHIFT;
	if (IN_CLASSB(addr->s_addr))
		return 32 - IN_CLASSB_NSHIFT;
	if (IN_CLASSC(addr->s_addr))
		return 32 - IN_CLASSC_NSHIFT;

	return 0;
}

static struct lxc_netdev *network_netdev(const char *key, const char *value,
					 struct lxc_list *network)
{
	struct lxc_netdev *netdev;

	if (lxc_list_empty(network)) {
		ERROR("network is not created for '%s' = '%s' option",
		      key, value);
		return NULL;
	}

	netdev = lxc_list_last_elem(network);
	if (!netdev) {
		ERROR("no network device defined for '%s' = '%s' option",
		      key, value);
		return NULL;
	}

	return netdev;
}

static struct lxc_netdev *network_netdev_by_type(const char *key, const char *value,
					 struct lxc_list *network, const enum lxc_network_type_t expected_type)
{
	struct lxc_netdev *const netdev = network_netdev(key, value, network);
	if (netdev->type != expected_type) {
		ERROR("network device type %s, but expected %s for option '%s'='%s'", get_netdev_typename(netdev->type), get_netdev_typename(expected_type), key, value);
		return NULL;
	}
	return netdev;
}

static int network_ifname(char **valuep, char *value)
{
	if (strlen(value) >= IFNAMSIZ) {
		ERROR("invalid interface name: %s", value);
		return -1;
	}

	*valuep = strdup(value);
	if (!*valuep) {
		ERROR("failed to dup string '%s'", value);
		return -1;
	}

	return 0;
}

#ifndef MACVLAN_MODE_PRIVATE
#  define MACVLAN_MODE_PRIVATE 1
#endif

#ifndef MACVLAN_MODE_VEPA
#  define MACVLAN_MODE_VEPA 2
#endif

#ifndef MACVLAN_MODE_BRIDGE
#  define MACVLAN_MODE_BRIDGE 4
#endif

static int macvlan_mode(int *valuep, char *value)
{
	struct mc_mode {
		char *name;
		int mode;
	} m[] = {
		{ "private", MACVLAN_MODE_PRIVATE },
		{ "vepa", MACVLAN_MODE_VEPA },
		{ "bridge", MACVLAN_MODE_BRIDGE },
	};

	int i;

	for (i = 0; i < sizeof(m)/sizeof(m[0]); i++) {
		if (strcmp(m[i].name, value))
			continue;

		*valuep = m[i].mode;
		return 0;
	}

	return -1;
}

static int config_network_flags(const char *key, char *value,
				struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	netdev->flags |= IFF_UP;

	return 0;
}

static int config_network_link(const char *key, char *value,
			       struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	return network_ifname(&netdev->link, value);
}

static int config_network_name(const char *key, char *value,
			       struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev_by_type(key, value, &lxc_conf->network, LXC_NET_VETH);
	if (!netdev)
		return -1;

	return network_ifname(&netdev->guest_attr.name, value);
}

static int config_network_veth_pair(const char *key, char *value,
				    struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev_by_type(key, value, &lxc_conf->network, LXC_NET_MACVLAN);
	if (!netdev)
		return -1;

	return network_ifname(&netdev->priv.veth_attr.host_attr.name, value);
}

static int config_network_veth_hwaddr(const char *key, char *value,
				 struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev_by_type(key, value, &lxc_conf->network, LXC_NET_VETH);
	if (!netdev)
		return -1;

	netdev->priv.veth_attr.host_attr.hwaddr = strdup(value);
	if (!netdev->priv.veth_attr.host_attr.hwaddr) {
		SYSERROR("failed to dup string '%s'", value);
		return -1;
	}

	return 0;
}

static int config_network_macvlan_mode(const char *key, char *value,
				       struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	return macvlan_mode(&netdev->priv.macvlan_attr.mode, value);
}

static int config_network_hwaddr(const char *key, char *value,
				 struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	netdev->guest_attr.hwaddr = strdup(value);
	if (!netdev->guest_attr.hwaddr) {
		SYSERROR("failed to dup string '%s'", value);
		return -1;
	}

	return 0;
}

static int config_network_vlan_id(const char *key, char *value,
			       struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev_by_type(key, value, &lxc_conf->network, LXC_NET_VLAN);
	if (!netdev)
		return -1;

	if (get_u16(&netdev->priv.vlan_attr.vid, value, 0))
		return -1;

	return 0;
}

static int config_network_mtu(const char *key, char *value,
			      struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	netdev->mtu = strdup(value);
	if (!netdev->mtu) {
		SYSERROR("failed to dup string '%s'", value);
		return -1;
	}

	return 0;
}

static int config_parse_allocate_ipv4(char *value, struct lxc_list **plist)
{
	struct lxc_inetdev *inetdev;
	struct lxc_list *list;
	char *cursor, *slash, *addr = NULL, *bcast = NULL, *prefix = NULL;
	*plist = NULL;
	inetdev = malloc(sizeof(*inetdev));
	if (!inetdev) {
		SYSERROR("failed to allocate ipv4 address");
		return -1;
	}
	memset(inetdev, 0, sizeof(*inetdev));

	list = malloc(sizeof(*list));
	if (!list) {
		SYSERROR("failed to allocate memory");
		return -1;
	}
	*plist = list;

	lxc_list_init(list);
	list->elem = inetdev;

	addr = value;

	cursor = strstr(addr, " ");
	if (cursor) {
		*cursor = '\0';
		bcast = cursor + 1;
	}

	slash = strstr(addr, "/");
	if (slash) {
		*slash = '\0';
		prefix = slash + 1;
	}

	if (!addr) {
		ERROR("no address specified");
		return -1;
	}

	if (!inet_pton(AF_INET, addr, &inetdev->addr)) {
		SYSERROR("invalid ipv4 address: %s", value);
		return -1;
	}

	if (bcast && !inet_pton(AF_INET, bcast, &inetdev->bcast)) {
		SYSERROR("invalid ipv4 broadcast address: %s", value);
		return -1;
	}

	/* no prefix specified, determine it from the network class */
	inetdev->prefix = prefix ? atoi(prefix) :
		config_ip_prefix(&inetdev->addr);

	/* if no broadcast address, let compute one from the
	 * prefix and address
	 */
	if (!bcast) {
		inetdev->bcast.s_addr = inetdev->addr.s_addr;
		inetdev->bcast.s_addr |=
			htonl(INADDR_BROADCAST >>  inetdev->prefix);
	}
	return 0;
}

static int config_network_ipv4(const char *key, char *value,
			       struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;
	struct lxc_list *list;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	if (config_parse_allocate_ipv4(value, &list))
		return -1;
	lxc_list_add(&netdev->guest_attr.ipv4, list);

	return 0;
}

static int config_network_ipv4_gateway(const char *key, char *value,
			               struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;
	struct in_addr *gw;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	gw = malloc(sizeof(*gw));
	if (!gw) {
		SYSERROR("failed to allocate ipv4 gateway address");
		return -1;
	}

	if (!value) {
		ERROR("no ipv4 gateway address specified");
		return -1;
	}

	if (!strcmp(value, "auto")) {
		netdev->ipv4_gateway = NULL;
		netdev->ipv4_gateway_auto = true;
	} else {
		if (!inet_pton(AF_INET, value, gw)) {
			SYSERROR("invalid ipv4 gateway address: %s", value);
			return -1;
		}

		netdev->ipv4_gateway = gw;
		netdev->ipv4_gateway_auto = false;
	}

	return 0;
}

static int config_network_veth_ipv4(const char *key, char *value,
			       struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;
	struct lxc_list *list;
	netdev = network_netdev_by_type(key, value, &lxc_conf->network, LXC_NET_VETH);
	if (!netdev)
		return -1;
	if (config_parse_allocate_ipv4(value, &list))
		return -1;
	lxc_list_add(&netdev->priv.veth_attr.host_attr.ipv4, list);
	return 0;
}

static int config_parse_allocate_ipv6(char *value, struct lxc_list **plist)
{
	struct lxc_inet6dev *inet6dev;
	struct lxc_list *list;
	char *slash;
	char *netmask;
	*plist = NULL;
	inet6dev = malloc(sizeof(*inet6dev));
	if (!inet6dev) {
		SYSERROR("failed to allocate ipv6 address");
		return -1;
	}
	memset(inet6dev, 0, sizeof(*inet6dev));

	list = malloc(sizeof(*list));
	if (!list) {
		SYSERROR("failed to allocate memory");
		return -1;
	}

	lxc_list_init(list);
	list->elem = inet6dev;

	inet6dev->prefix = 64;
	slash = strstr(value, "/");
	if (slash) {
		*slash = '\0';
		netmask = slash + 1;
		inet6dev->prefix = atoi(netmask);
	}

	if (!inet_pton(AF_INET6, value, &inet6dev->addr)) {
		SYSERROR("invalid ipv6 address: %s", value);
		return -1;
	}
	return 0;
}

static int config_network_ipv6(const char *key, char *value,
			       struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;
	struct lxc_list *list;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	if (config_parse_allocate_ipv6(value, &list))
		return -1;
	lxc_list_add(&netdev->guest_attr.ipv6, list);

	return 0;
}

static int config_network_ipv6_gateway(const char *key, char *value,
			               struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;
	struct in6_addr *gw;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	gw = malloc(sizeof(*gw));
	if (!gw) {
		SYSERROR("failed to allocate ipv6 gateway address");
		return -1;
	}

	if (!value) {
		ERROR("no ipv6 gateway address specified");
		return -1;
	}

	if (!strcmp(value, "auto")) {
		netdev->ipv6_gateway = NULL;
		netdev->ipv6_gateway_auto = true;
	} else {
		if (!inet_pton(AF_INET6, value, gw)) {
			SYSERROR("invalid ipv6 gateway address: %s", value);
			return -1;
		}

		netdev->ipv6_gateway = gw;
		netdev->ipv6_gateway_auto = false;
	}

	return 0;
}

static int config_network_veth_ipv6(const char *key, char *value,
			       struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;
	struct lxc_list *list;
	netdev = network_netdev_by_type(key, value, &lxc_conf->network, LXC_NET_VETH);
	if (!netdev)
		return -1;
	if (config_parse_allocate_ipv6(value, &list))
		return -1;
	lxc_list_add(&netdev->priv.veth_attr.host_attr.ipv6, list);
	return 0;
}

static int config_network_script(const char *key, char *value,
				 struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
	return -1;

	char *copy = strdup(value);
	if (!copy) {
		SYSERROR("failed to dup string '%s'", value);
		return -1;
	}
	if (strcmp(key, "lxc.network.script.up") == 0) {
		netdev->upscript = copy;
		return 0;
	}
	SYSERROR("Unknown key: %s", key);
	free(copy);
	return -1;
}

static int config_personality(const char *key, char *value,
			      struct lxc_conf *lxc_conf)
{
	signed long personality = lxc_config_parse_arch(value);

	if (personality >= 0)
		lxc_conf->personality = personality;
	else
		WARN("unsupported personality '%s'", value);

	return 0;
}

static int config_pts(const char *key, char *value, struct lxc_conf *lxc_conf)
{
	int maxpts = atoi(value);

	lxc_conf->pts = maxpts;

	return 0;
}

static int config_tty(const char *key, char *value, struct lxc_conf *lxc_conf)
{
	int nbtty = atoi(value);

	lxc_conf->tty = nbtty;

	return 0;
}

static int config_ttydir(const char *key, char *value,
			  struct lxc_conf *lxc_conf)
{
	char *path;

	if (!value || strlen(value) == 0)
		return 0;
	path = strdup(value);
	if (!path) {
		SYSERROR("failed to strdup '%s': %m", value);
		return -1;
	}

	lxc_conf->ttydir = path;

	return 0;
}

static int config_cgroup(const char *key, char *value, struct lxc_conf *lxc_conf)
{
	char *token = "lxc.cgroup.";
	char *subkey;
	struct lxc_list *cglist = NULL;
	struct lxc_cgroup *cgelem = NULL;

	subkey = strstr(key, token);

	if (!subkey)
		return -1;

	if (!strlen(subkey))
		return -1;

	if (strlen(subkey) == strlen(token))
		return -1;

	subkey += strlen(token);

	cglist = malloc(sizeof(*cglist));
	if (!cglist)
		goto out;

	cgelem = malloc(sizeof(*cgelem));
	if (!cgelem)
		goto out;
	memset(cgelem, 0, sizeof(*cgelem));

	cgelem->subsystem = strdup(subkey);
	cgelem->value = strdup(value);

	if (!cgelem->subsystem || !cgelem->value)
		goto out;

	cglist->elem = cgelem;

	lxc_list_add_tail(&lxc_conf->cgroup, cglist);

	return 0;

out:
	if (cglist)
		free(cglist);

	if (cgelem) {
		if (cgelem->subsystem)
			free(cgelem->subsystem);

		if (cgelem->value)
			free(cgelem->value);

		free(cgelem);
	}

	return -1;
}

static int config_keepns(const char *key, char *value, struct lxc_conf *lxc_conf)
{
	/*
	 * Omit support for pid and net.  Keeping the pid namespace shared
	 * is contrary to the point of LXC.  Keeping the network namespace
	 * shared when the guest is configured with network devices could
	 * cause strange behavior.
	 */
	if (!strcmp(value, "mount"))
		lxc_conf->keep_ns |= CLONE_NEWNS;
	else if (!strcmp(value, "ipc"))
		lxc_conf->keep_ns |= CLONE_NEWIPC;
	else if (!strcmp(value, "uts"))
		lxc_conf->keep_ns |= CLONE_NEWUTS;
	else
	{
		ERROR("unrecognized keep: %s", value);
		return -1;
	}
	return 0;
}

static int config_fstab(const char *key, char *value, struct lxc_conf *lxc_conf)
{
	if (strlen(value) >= MAXPATHLEN) {
		ERROR("%s path is too long", value);
		return -1;
	}

	lxc_conf->fstab = strdup(value);
	if (!lxc_conf->fstab) {
		SYSERROR("failed to duplicate string %s", value);
		return -1;
	}

	return 0;
}

static int config_mount(const char *key, char *value, struct lxc_conf *lxc_conf)
{
	char *fstab_token = "lxc.mount";
	char *token = "lxc.mount.entry";
	char *subkey;
	char *mntelem;
	struct lxc_list *mntlist;

	subkey = strstr(key, token);

	if (!subkey) {
		subkey = strstr(key, fstab_token);

		if (!subkey)
			return -1;

		return config_fstab(key, value, lxc_conf);
	}

	if (!strlen(subkey))
		return -1;

	mntlist = malloc(sizeof(*mntlist));
	if (!mntlist)
		return -1;

	mntelem = strdup(value);
	if (!mntelem)
		return -1;
	mntlist->elem = mntelem;

	lxc_list_add_tail(&lxc_conf->mount_list, mntlist);

	return 0;
}

static int config_cap_drop(const char *key, char *value,
			   struct lxc_conf *lxc_conf)
{
	char *dropcaps, *sptr, *token;
	struct lxc_list *droplist;
	int ret = -1;

	if (!strlen(value))
		return -1;

	dropcaps = strdup(value);
	if (!dropcaps) {
		SYSERROR("failed to dup '%s'", value);
		return -1;
	}

	/* in case several capability drop is specified in a single line
	 * split these caps in a single element for the list */
	for (;;) {
                token = strtok_r(dropcaps, " \t", &sptr);
                if (!token) {
			ret = 0;
                        break;
		}
		dropcaps = NULL;

		droplist = malloc(sizeof(*droplist));
		if (!droplist) {
			SYSERROR("failed to allocate drop list");
			break;
		}

		droplist->elem = strdup(token);
		if (!droplist->elem) {
			SYSERROR("failed to dup '%s'", token);
			free(droplist);
			break;
		}

		lxc_list_add_tail(&lxc_conf->caps, droplist);
        }

	free(dropcaps);

	return ret;
}

static int config_console(const char *key, char *value,
			  struct lxc_conf *lxc_conf)
{
	char *path;

	path = strdup(value);
	if (!path) {
		SYSERROR("failed to strdup '%s': %m", value);
		return -1;
	}

	lxc_conf->console.path = path;

	return 0;
}

static int config_rootfs(const char *key, char *value, struct lxc_conf *lxc_conf)
{
	if (strlen(value) >= MAXPATHLEN) {
		ERROR("%s path is too long", value);
		return -1;
	}

	lxc_conf->rootfs.path = strdup(value);
	if (!lxc_conf->rootfs.path) {
		SYSERROR("failed to duplicate string %s", value);
		return -1;
	}

	return 0;
}

static int config_rootfs_mount(const char *key, char *value, struct lxc_conf *lxc_conf)
{
	if (strlen(value) >= MAXPATHLEN) {
		ERROR("%s path is too long", value);
		return -1;
	}

	lxc_conf->rootfs.mount = strdup(value);
	if (!lxc_conf->rootfs.mount) {
		SYSERROR("failed to duplicate string '%s'", value);
		return -1;
	}

	return 0;
}

static int config_pivotdir(const char *key, char *value, struct lxc_conf *lxc_conf)
{
	if (strlen(value) >= MAXPATHLEN) {
		ERROR("%s path is too long", value);
		return -1;
	}

	lxc_conf->rootfs.pivot = strdup(value);
	if (!lxc_conf->rootfs.pivot) {
		SYSERROR("failed to duplicate string %s", value);
		return -1;
	}

	return 0;
}

static int config_utsname(const char *key, char *value, struct lxc_conf *lxc_conf)
{
	struct utsname *utsname;

	utsname = malloc(sizeof(*utsname));
	if (!utsname) {
		SYSERROR("failed to allocate memory");
		return -1;
	}

	if (strlen(value) >= sizeof(utsname->nodename)) {
		ERROR("node name '%s' is too long",
			      utsname->nodename);
		return -1;
	}

	strcpy(utsname->nodename, value);
	lxc_conf->utsname = utsname;

	return 0;
}

static int config_netns_path(const char *key, char *value, struct lxc_conf *lxc_conf)
{
	if (strlen(value) >= MAXPATHLEN) {
		ERROR("%s path is too long", value);
		return -1;
	}
	lxc_conf->netns_path = strdup(value);
	if (!lxc_conf->netns_path) {
		SYSERROR("failed to duplicate string %s", value);
		return -1;
	}
	return 0;
}

static int config_netns_mode(const char *key, char *value, struct lxc_conf *lxc_conf)
{
	enum lxc_netns_open_mode_t nom;
	if (!strcmp(value, "open"))
		nom = LXC_NETNS_OPEN;
	else if (!strcmp(value, "create"))
		nom = LXC_NETNS_CREATE_OPEN;
	else
	{
		ERROR("Unhandled netns open mode '%s' (should be 'open' or 'create')", value);
		return -1;
	}
	lxc_conf->netns_open_mode = nom;
	return 0;
}

static int parse_line(char *buffer, void *data)
{
	const struct config *config;
	char *line, *linep;
	char *dot;
	char *key;
	char *value;
	int ret = 0;

	if (lxc_is_line_empty(buffer))
		return 0;

	/* we have to dup the buffer otherwise, at the re-exec for
	 * reboot we modified the original string on the stack by
	 * replacing '=' by '\0' below
	 */
	linep = line = strdup(buffer);
	if (!line) {
		SYSERROR("failed to allocate memory for '%s'", buffer);
		return -1;
	}

	line += lxc_char_left_gc(line, strlen(line));

	/* martian option - ignoring it, the commented lines beginning by '#'
	 * fall in this case
	 */
	if (strncmp(line, "lxc.", 4))
		goto out;

	ret = -1;

	dot = strstr(line, "=");
	if (!dot) {
		ERROR("invalid configuration line: %s", line);
		goto out;
	}

	*dot = '\0';
	value = dot + 1;

	key = line;
	key[lxc_char_right_gc(key, strlen(key))] = '\0';

	value += lxc_char_left_gc(value, strlen(value));
	value[lxc_char_right_gc(value, strlen(value))] = '\0';

	config = getconfig(key);
	if (!config) {
		ERROR("unknow key %s", key);
		goto out;
	}

	ret = config->cb(key, value, data);

out:
	free(linep);
	return ret;
}

int lxc_config_readline(char *buffer, struct lxc_conf *conf)
{
	return parse_line(buffer, conf);
}

int lxc_config_read(const char *file, const char *name, struct lxc_conf *conf)
{
	int rc;
	char *rcfile;
	if (file) {
		return lxc_file_for_each_line(file, parse_line, conf);
	}
	rc = asprintf(&rcfile, LXCPATH "/%s/config", name);
	if (rc == -1) {
		SYSERROR("failed to allocate memory");
		return -1;
	}
	if (!access(rcfile, F_OK))
		rc = lxc_file_for_each_line(rcfile, parse_line, conf);
	else
	/* container configuration does not exist */
		rc = 0;
	free(rcfile);
	return rc;
}

int lxc_config_define_add(struct lxc_list *defines, char* arg)
{
	struct lxc_list *dent;

	dent = malloc(sizeof(struct lxc_list));
	if (!dent)
		return -1;

	dent->elem = arg;
	lxc_list_add_tail(defines, dent);
	return 0;
}

int lxc_config_define_load(struct lxc_list *defines, struct lxc_conf *conf)
{
	struct lxc_list *it;
	int ret = 0;

	lxc_list_for_each(it, defines) {
		ret = lxc_config_readline(it->elem, conf);
		if (ret)
			break;
	}

	lxc_list_for_each(it, defines) {
		lxc_list_del(it);
		free(it);
	}

	return ret;
}

signed long lxc_config_parse_arch(const char *arch)
{
	struct per_name {
		char *name;
		unsigned long per;
	} pername[4] = {
		{ "x86", PER_LINUX32 },
		{ "i686", PER_LINUX32 },
		{ "x86_64", PER_LINUX },
		{ "amd64", PER_LINUX },
	};
	size_t len = sizeof(pername) / sizeof(pername[0]);

	int i;

	for (i = 0; i < len; i++) {
		if (!strcmp(pername[i].name, arch))
		    return pername[i].per;
	}

	return -1;
}

static const struct config config[] = {
	{ "lxc.arch",                 config_personality          },
	{ "lxc.pts",                  config_pts                  },
	{ "lxc.tty",                  config_tty                  },
	{ "lxc.devttydir",            config_ttydir               },
	{ "lxc.cgroup",               config_cgroup               },
	{ "lxc.keepns",				  config_keepns				  },
	{ "lxc.mount",                config_mount                },
	{ "lxc.rootfs.mount",         config_rootfs_mount         },
	{ "lxc.rootfs",               config_rootfs               },
	{ "lxc.pivotdir",             config_pivotdir             },
	{ "lxc.utsname",              config_utsname              },
	{ "lxc.netns.path",           config_netns_path           },
	{ "lxc.netns.mode",           config_netns_mode           },
	{ "lxc.network.type",         config_network_type         },
	{ "lxc.network.flags",        config_network_flags        },
	{ "lxc.network.link",         config_network_link         },
	{ "lxc.network.name",         config_network_name         },
	{ "lxc.network.macvlan.mode", config_network_macvlan_mode },
	{ "lxc.network.veth.pair",    config_network_veth_pair    },
	{ "lxc.network.veth.hwaddr",  config_network_veth_hwaddr  },
	{ "lxc.network.veth.ipv4",    config_network_veth_ipv4    },
	{ "lxc.network.veth.ipv6",    config_network_veth_ipv6    },
	{ "lxc.network.script.up",    config_network_script       },
	{ "lxc.network.hwaddr",       config_network_hwaddr       },
	{ "lxc.network.mtu",          config_network_mtu          },
	{ "lxc.network.vlan.id",      config_network_vlan_id      },
	{ "lxc.network.ipv4.gateway", config_network_ipv4_gateway },
	{ "lxc.network.ipv4",         config_network_ipv4         },
	{ "lxc.network.ipv6.gateway", config_network_ipv6_gateway },
	{ "lxc.network.ipv6",         config_network_ipv6         },
	{ "lxc.cap.drop",             config_cap_drop             },
	{ "lxc.console",              config_console              },
};

static const size_t config_size = sizeof(config)/sizeof(struct config);

static const struct config *getconfig(const char *key)
{
	const size_t config_size = sizeof(config) / sizeof(config[0]);
	const struct config *const end = config + config_size;
	const struct config *c = config;
	for (; c != end; ++ c)
		if (!strncmp(c->name, key, strlen(c->name)))
			return c;
	return NULL;
}
