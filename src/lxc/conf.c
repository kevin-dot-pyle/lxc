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
#undef _GNU_SOURCE
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <mntent.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pty.h>

#include <linux/loop.h>
#include <linux/magic.h>

#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <sys/personality.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <libgen.h>

#include "network.h"
#include "error.h"
#include "parse.h"
#include "config.h"
#include "utils.h"
#include "conf.h"
#include "log.h"
#include "lxc.h"	/* for lxc_cgroup_set() */
#include "caps.h"       /* for lxc_caps_last_cap() */

lxc_log_define(lxc_conf, lxc);

#define MAXHWLEN    18
#define MAXINDEXLEN 20
#define MAXMTULEN   16
#define MAXLINELEN  128

#ifndef MS_DIRSYNC
#define MS_DIRSYNC  128
#endif

#ifndef MS_REC
#define MS_REC 16384
#endif

#ifndef MNT_DETACH
#define MNT_DETACH 2
#endif

#ifndef MS_RELATIME
#define MS_RELATIME (1 << 21)
#endif

#ifndef MS_STRICTATIME
#define MS_STRICTATIME (1 << 24)
#endif

#ifndef CAP_SETFCAP
#define CAP_SETFCAP 31
#endif

#ifndef CAP_MAC_OVERRIDE
#define CAP_MAC_OVERRIDE 32
#endif

#ifndef CAP_MAC_ADMIN
#define CAP_MAC_ADMIN 33
#endif

#ifndef PR_CAPBSET_DROP
#define PR_CAPBSET_DROP 24
#endif

extern int pivot_root(const char * new_root, const char * put_old);

typedef int (*instanciate_cb)(struct lxc_handler *, struct lxc_netdev *);

struct mount_opt {
	const char *name;
	int clear;
	int flag;
};

struct caps_opt {
	const char *name;
	int value;
};

static int instanciate_veth(struct lxc_handler *, struct lxc_netdev *);
static int instanciate_macvlan(struct lxc_handler *, struct lxc_netdev *);
static int instanciate_vlan(struct lxc_handler *, struct lxc_netdev *);
static int instanciate_phys(struct lxc_handler *, struct lxc_netdev *);
static int instanciate_empty(struct lxc_handler *, struct lxc_netdev *);

static const instanciate_cb netdev_conf[] = {
	[LXC_NET_VETH]    = instanciate_veth,
	[LXC_NET_MACVLAN] = instanciate_macvlan,
	[LXC_NET_VLAN]    = instanciate_vlan,
	[LXC_NET_PHYS]    = instanciate_phys,
	[LXC_NET_EMPTY]   = instanciate_empty,
};

static const struct mount_opt mount_opt[] = {
	{ "defaults",      0, 0              },
	{ "ro",            0, MS_RDONLY      },
	{ "rw",            1, MS_RDONLY      },
	{ "suid",          1, MS_NOSUID      },
	{ "nosuid",        0, MS_NOSUID      },
	{ "dev",           1, MS_NODEV       },
	{ "nodev",         0, MS_NODEV       },
	{ "exec",          1, MS_NOEXEC      },
	{ "noexec",        0, MS_NOEXEC      },
	{ "sync",          0, MS_SYNCHRONOUS },
	{ "async",         1, MS_SYNCHRONOUS },
	{ "dirsync",       0, MS_DIRSYNC     },
	{ "remount",       0, MS_REMOUNT     },
	{ "mand",          0, MS_MANDLOCK    },
	{ "nomand",        1, MS_MANDLOCK    },
	{ "atime",         1, MS_NOATIME     },
	{ "noatime",       0, MS_NOATIME     },
	{ "diratime",      1, MS_NODIRATIME  },
	{ "nodiratime",    0, MS_NODIRATIME  },
	{ "bind",          0, MS_BIND        },
	{ "rbind",         0, MS_BIND|MS_REC },
	{ "relatime",      0, MS_RELATIME    },
	{ "norelatime",    1, MS_RELATIME    },
	{ "strictatime",   0, MS_STRICTATIME },
	{ "nostrictatime", 1, MS_STRICTATIME },
};

static const struct caps_opt caps_opt[] = {
	{ "chown",             CAP_CHOWN             },
	{ "dac_override",      CAP_DAC_OVERRIDE      },
	{ "dac_read_search",   CAP_DAC_READ_SEARCH   },
	{ "fowner",            CAP_FOWNER            },
	{ "fsetid",            CAP_FSETID            },
	{ "kill",              CAP_KILL              },
	{ "setgid",            CAP_SETGID            },
	{ "setuid",            CAP_SETUID            },
	{ "setpcap",           CAP_SETPCAP           },
	{ "linux_immutable",   CAP_LINUX_IMMUTABLE   },
	{ "net_bind_service",  CAP_NET_BIND_SERVICE  },
	{ "net_broadcast",     CAP_NET_BROADCAST     },
	{ "net_admin",         CAP_NET_ADMIN         },
	{ "net_raw",           CAP_NET_RAW           },
	{ "ipc_lock",          CAP_IPC_LOCK          },
	{ "ipc_owner",         CAP_IPC_OWNER         },
	{ "sys_module",        CAP_SYS_MODULE        },
	{ "sys_rawio",         CAP_SYS_RAWIO         },
	{ "sys_chroot",        CAP_SYS_CHROOT        },
	{ "sys_ptrace",        CAP_SYS_PTRACE        },
	{ "sys_pacct",         CAP_SYS_PACCT         },
	{ "sys_admin",         CAP_SYS_ADMIN         },
	{ "sys_boot",          CAP_SYS_BOOT          },
	{ "sys_nice",          CAP_SYS_NICE          },
	{ "sys_resource",      CAP_SYS_RESOURCE      },
	{ "sys_time",          CAP_SYS_TIME          },
	{ "sys_tty_config",    CAP_SYS_TTY_CONFIG    },
	{ "mknod",             CAP_MKNOD             },
	{ "lease",             CAP_LEASE             },
#ifdef CAP_AUDIT_WRITE
	{ "audit_write",       CAP_AUDIT_WRITE       },
#endif
#ifdef CAP_AUDIT_CONTROL
	{ "audit_control",     CAP_AUDIT_CONTROL     },
#endif
	{ "setfcap",           CAP_SETFCAP           },
	{ "mac_override",      CAP_MAC_OVERRIDE      },
	{ "mac_admin",         CAP_MAC_ADMIN         },
#ifdef CAP_SYSLOG
	{ "syslog",            CAP_SYSLOG            },
#endif
#ifdef CAP_WAKE_ALARM
	{ "wake_alarm",        CAP_WAKE_ALARM        },
#endif
};

struct mount_file_entries_state_t
{
	int seen_remount;
};

static void finalize_mount_file_entries_state(struct mount_file_entries_state_t *const mfe)
{
	(void)mfe;
}

static int run_script(const char *name, const char *section,
		      const char *script, ...)
{
	int ret;
	FILE *f;
	char *buffer, *p, *output;
	size_t size = 0;
	va_list ap;

	INFO("Executing script '%s' for container '%s', config section '%s'",
	     script, name, section);

	va_start(ap, script);
	while ((p = va_arg(ap, char *)))
		size += strlen(p) + 1;
	va_end(ap);

	size += strlen(script);
	size += strlen(name);
	size += strlen(section);
	size += 3;

	if (size > INT_MAX)
		return -1;

	buffer = alloca(size);
	if (!buffer) {
		ERROR("failed to allocate memory");
		return -1;
	}

	ret = sprintf(buffer, "%s %s %s", script, name, section);

	va_start(ap, script);
	while ((p = va_arg(ap, char *)))
		ret += sprintf(buffer + ret, " %s", p);
	va_end(ap);

	f = popen(buffer, "r");
	if (!f) {
		SYSERROR("popen failed");
		return -1;
	}

	output = malloc(LXC_LOG_BUFFER_SIZE);
	if (!output) {
		ERROR("failed to allocate memory for script output");
		return -1;
	}

	while(fgets(output, LXC_LOG_BUFFER_SIZE, f))
		DEBUG("script output: %s", output);

	free(output);

	if (pclose(f)) {
		ERROR("Script exited on error");
		return -1;
	}

	return 0;
}

static int find_fstype_cb(char* buffer, void *data)
{
	struct cbarg {
		const char *rootfs;
		const char *target;
		int mntopt;
	} *cbarg = data;

	char *fstype;

	/* we don't try 'nodev' entries */
	if (strstr(buffer, "nodev"))
		return 0;

	fstype = buffer;
	fstype += lxc_char_left_gc(fstype, strlen(fstype));
	fstype[lxc_char_right_gc(fstype, strlen(fstype))] = '\0';

	DEBUG("trying to mount '%s'->'%s' with fstype '%s'",
	      cbarg->rootfs, cbarg->target, fstype);

	if (mount(cbarg->rootfs, cbarg->target, fstype, cbarg->mntopt, NULL)) {
		DEBUG("mount failed with error: %s", strerror(errno));
		return 0;
	}

	INFO("mounted '%s' on '%s', with fstype '%s'",
	     cbarg->rootfs, cbarg->target, fstype);

	return 1;
}

static int mount_unknow_fs(const char *rootfs, const char *target, int mntopt)
{
	int i;

	struct cbarg {
		const char *rootfs;
		const char *target;
		int mntopt;
	} cbarg = {
		.rootfs = rootfs,
		.target = target,
		.mntopt = mntopt,
	};

	/*
	 * find the filesystem type with brute force:
	 * first we check with /etc/filesystems, in case the modules
	 * are auto-loaded and fall back to the supported kernel fs
	 */
	char *fsfile[] = {
		"/etc/filesystems",
		"/proc/filesystems",
	};

	for (i = 0; i < sizeof(fsfile)/sizeof(fsfile[0]); i++) {

		int ret;

		if (access(fsfile[i], F_OK))
			continue;

		ret = lxc_file_for_each_line(fsfile[i], find_fstype_cb, &cbarg);
		if (ret < 0) {
			ERROR("failed to parse '%s'", fsfile[i]);
			return -1;
		}

		if (ret)
			return 0;
	}

	ERROR("failed to determine fs type for '%s'", rootfs);
	return -1;
}

static int mount_rootfs_dir(const char *rootfs, const char *target)
{
	return mount(rootfs, target, "none", MS_BIND | MS_REC, NULL);
}

static int setup_lodev(const char *rootfs, int fd, struct loop_info64 *loinfo)
{
	int rfd;
	int ret = -1;

	rfd = open(rootfs, O_RDWR);
	if (rfd < 0) {
		SYSERROR("failed to open '%s'", rootfs);
		return -1;
	}

	memset(loinfo, 0, sizeof(*loinfo));

	loinfo->lo_flags = LO_FLAGS_AUTOCLEAR;

	if (ioctl(fd, LOOP_SET_FD, rfd)) {
		SYSERROR("failed to LOOP_SET_FD");
		goto out;
	}

	if (ioctl(fd, LOOP_SET_STATUS64, loinfo)) {
		SYSERROR("failed to LOOP_SET_STATUS64");
		goto out;
	}

	ret = 0;
out:
	close(rfd);

	return ret;
}

static int mount_rootfs_file(const char *rootfs, const char *target)
{
	struct dirent dirent, *direntp;
	struct loop_info64 loinfo;
	int ret = -1, fd = -1;
	DIR *dir;
	char path[MAXPATHLEN];

	dir = opendir("/dev");
	if (!dir) {
		SYSERROR("failed to open '/dev'");
		return -1;
	}

	while (!readdir_r(dir, &dirent, &direntp)) {

		if (!direntp)
			break;

		if (!strcmp(direntp->d_name, "."))
			continue;

		if (!strcmp(direntp->d_name, ".."))
			continue;

		if (strncmp(direntp->d_name, "loop", 4))
			continue;

		sprintf(path, "/dev/%s", direntp->d_name);
		fd = open(path, O_RDWR);
		if (fd < 0)
			continue;

		if (ioctl(fd, LOOP_GET_STATUS64, &loinfo) == 0) {
			close(fd);
			continue;
		}

		if (errno != ENXIO) {
			WARN("unexpected error for ioctl on '%s': %m",
			     direntp->d_name);
			continue;
		}

		DEBUG("found '%s' free lodev", path);

		ret = setup_lodev(rootfs, fd, &loinfo);
		if (!ret)
			ret = mount_unknow_fs(path, target, 0);
		close(fd);

		break;
	}

	if (closedir(dir))
		WARN("failed to close directory");

	return ret;
}

static int mount_rootfs_block(const char *rootfs, const char *target)
{
	return mount_unknow_fs(rootfs, target, 0);
}

static int mount_rootfs(const char *rootfs, const char *target)
{
	char absrootfs[MAXPATHLEN];
	struct stat s;
	int i;

	if (!realpath(rootfs, absrootfs)) {
		SYSERROR("failed to get real path for '%s'", rootfs);
		return -1;
	}

	if (stat(absrootfs, &s)) {
		SYSERROR("failed to stat '%s'", absrootfs);
		return -1;
	}

	switch(s.st_mode & S_IFMT)
	{
		case S_IFDIR:
			i = mount_rootfs_dir(absrootfs, target);
			break;
		case S_IFBLK:
			i = mount_rootfs_block(absrootfs, target);
			break;
		case S_IFREG:
			i = mount_rootfs_file(absrootfs, target);
			break;
		default:
			ERROR("unsupported rootfs type for '%s'", absrootfs);
			return -1;
	}
	if (i)
		return i;
	/* change into new root fs */
	if (chdir(target)) {
		SYSERROR("can't chdir to new rootfs '%s'", target);
		return -1;
	}
	return i;
}

static int setup_utsname(struct utsname *utsname)
{
	if (!utsname)
		return 0;

	if (sethostname(utsname->nodename, strlen(utsname->nodename))) {
		SYSERROR("failed to set the hostname to '%s'", utsname->nodename);
		return -1;
	}

	INFO("'%s' hostname has been setup", utsname->nodename);

	return 0;
}

static int setup_tty(const struct lxc_rootfs *rootfs,
		     const struct lxc_tty_info *tty_info, char *ttydir)
{
	char path[MAXPATHLEN], lxcpath[MAXPATHLEN];
	int i, ret;

	if (!rootfs->path)
		return 0;

	for (i = 0; i < tty_info->nbtty; i++) {

		struct lxc_pty_info *pty_info = &tty_info->pty_info[i];

		ret = snprintf(path, sizeof(path), "%s/dev/tty%d",
			 rootfs->mount, i + 1);
		if (ret >= sizeof(path)) {
			ERROR("pathname too long for ttys");
			return -1;
		}
		if (ttydir) {
			/* create dev/lxc/tty%d" */
			snprintf(lxcpath, sizeof(lxcpath), "%s/dev/%s/tty%d",
				 rootfs->mount, ttydir, i + 1);
			if (ret >= sizeof(lxcpath)) {
				ERROR("pathname too long for ttys");
				return -1;
			}
			ret = creat(lxcpath, 0660);
			if (ret==-1 && errno != EEXIST) {
				SYSERROR("error creating %s\n", lxcpath);
				return -1;
			}
			close(ret);
			ret = unlink(path);
			if (ret && errno != ENOENT) {
				SYSERROR("error unlinking %s\n", path);
				return -1;
			}

			if (mount(pty_info->name, lxcpath, "none", MS_BIND, 0)) {
				WARN("failed to mount '%s'->'%s'",
				     pty_info->name, path);
				continue;
			}

			snprintf(lxcpath, sizeof(lxcpath), "%s/tty%d", ttydir, i+1);
			ret = symlink(lxcpath, path);
			if (ret) {
				SYSERROR("failed to create symlink for tty %d\n", i+1);
				return -1;
			}
		} else {
			if (mount(pty_info->name, path, "none", MS_BIND, 0)) {
				WARN("failed to mount '%s'->'%s'",
						pty_info->name, path);
				continue;
			}
		}
	}

	INFO("%d tty(s) has been setup", tty_info->nbtty);

	return 0;
}

static int setup_rootfs_pivot_root_cb(char *buffer, void *data)
{
	struct lxc_list	*mountlist, *listentry, *iterator;
	char *pivotdir, *mountpoint, *mountentry;
	int found;
	void **cbparm;

	mountentry = buffer;
	cbparm = (void **)data;

	mountlist = cbparm[0];
	pivotdir  = cbparm[1];

	/* parse entry, first field is mountname, ignore */
	mountpoint = strtok(mountentry, " ");
	if (!mountpoint)
		return -1;

	/* second field is mountpoint */
	mountpoint = strtok(NULL, " ");
	if (!mountpoint)
		return -1;

	/* only consider mountpoints below old root fs */
	if (strncmp(mountpoint, pivotdir, strlen(pivotdir)))
		return 0;

	/* filter duplicate mountpoints */
	found = 0;
	lxc_list_for_each(iterator, mountlist) {
		if (!strcmp(iterator->elem, mountpoint)) {
			found = 1;
			break;
		}
	}
	if (found)
		return 0;

	/* add entry to list */
	listentry = malloc(sizeof(*listentry));
	if (!listentry) {
		SYSERROR("malloc for mountpoint listentry failed");
		return -1;
	}

	listentry->elem = strdup(mountpoint);
	if (!listentry->elem) {
		SYSERROR("strdup failed");
		return -1;
	}
	lxc_list_add(mountlist, listentry);

	return 0;
}

static int umount_oldrootfs(const char *oldrootfs)
{
	char path[MAXPATHLEN];
	void *cbparm[2];
	struct lxc_list mountlist, *iterator;
	int ok, still_mounted, last_still_mounted;

	/* read and parse /proc/mounts in old root fs */
	lxc_list_init(&mountlist);

	/* oldrootfs is on the top tree directory now */
	snprintf(path, sizeof(path), "/%s", oldrootfs);
	cbparm[0] = &mountlist;

	cbparm[1] = strdup(path);
	if (!cbparm[1]) {
		SYSERROR("strdup failed");
		return -1;
	}

	snprintf(path, sizeof(path), "%s/proc/mounts", oldrootfs);

	ok = lxc_file_for_each_line(path,
				    setup_rootfs_pivot_root_cb, &cbparm);
	if (ok < 0) {
		SYSERROR("failed to read or parse mount list '%s'", path);
		return -1;
	}

	/* umount filesystems until none left or list no longer shrinks */
	still_mounted = 0;
	do {
		last_still_mounted = still_mounted;
		still_mounted = 0;

		lxc_list_for_each(iterator, &mountlist) {

			/* umount normally */
			if (!umount(iterator->elem)) {
				DEBUG("umounted '%s'", (char *)iterator->elem);
				lxc_list_del(iterator);
				continue;
			}

			still_mounted++;
		}

	} while (still_mounted > 0 && still_mounted != last_still_mounted);


	lxc_list_for_each(iterator, &mountlist) {

		/* let's try a lazy umount */
		if (!umount2(iterator->elem, MNT_DETACH)) {
			INFO("lazy unmount of '%s'", (char *)iterator->elem);
			continue;
		}

		/* be more brutal (nfs) */
		if (!umount2(iterator->elem, MNT_FORCE)) {
			INFO("forced unmount of '%s'", (char *)iterator->elem);
			continue;
		}

		WARN("failed to unmount '%s'", (char *)iterator->elem);
	}

	return 0;
}

int setup_rootfs_pivot_root(const char *pivotdir)
{
	int remove_pivotdir = 0;

	if (access(pivotdir, F_OK)) {

		if (mkdir_p(pivotdir, 0755)) {
			SYSERROR("failed to create pivotdir '%s'", pivotdir);
			return -1;
		}

		remove_pivotdir = 1;
		DEBUG("created '%s' directory", pivotdir);
	}

	DEBUG("mountpoint for old rootfs is '%s'", pivotdir);

	/* pivot_root into our new root fs */
	if (pivot_root(".", pivotdir)) {
		SYSERROR("pivot_root syscall failed");
		return -1;
	}

	if (chroot(".")) {
		SYSERROR("can't chroot to . after pivot_root");
		return -1;
	}

	if (chdir("/")) {
		SYSERROR("can't chdir to / after pivot_root");
		return -1;
	}

	DEBUG("pivot_root syscall successful");

	/* we switch from absolute path to relative path */
	if (umount_oldrootfs(pivotdir))
		return -1;

	/* remove temporary mount point, we don't consider the removing
	 * as fatal */
	if (remove_pivotdir && rmdir(pivotdir))
		WARN("can't remove mountpoint '%s': %m", pivotdir);

	return 0;
}

static int setup_rootfs(const struct lxc_rootfs *rootfs)
{
	if (!rootfs->path)
		return 0;

	if (access(rootfs->mount, F_OK)) {
		SYSERROR("failed to access to '%s', check it is present",
			 rootfs->mount);
		return -1;
	}

	if (mount_rootfs(rootfs->path, rootfs->mount)) {
		ERROR("failed to mount rootfs");
		return -1;
	}

	DEBUG("mounted '%s' on '%s'", rootfs->path, rootfs->mount);

	return 0;
}

static int setup_cwd_rootfs(const struct lxc_rootfs *rootfs)
{
	/*
	 * Yes, compare one value and then use another.  This is the logic
	 * used when pivoting, so match it here.
	 */
	const char *const path = ((rootfs->path != NULL) ? rootfs->mount : "/");
	if (chdir(path)) {
		SYSERROR("can't chdir to new rootfs '%s'", path);
		return -1;
	}
	return 0;
}

static int setup_pts(int pts)
{
	char target[PATH_MAX];

	if (!pts)
		return 0;

	if (!access("dev/pts/ptmx", F_OK) && umount("dev/pts")) {
		SYSERROR("failed to umount 'dev/pts'");
		return -1;
	}

	if (mount("devpts", "dev/pts", "devpts", MS_MGC_VAL,
		  "newinstance,ptmxmode=0666")) {
		SYSERROR("failed to mount a new instance of '/dev/pts'");
		return -1;
	}

	if (access("dev/ptmx", F_OK)) {
		if (!symlink("/dev/pts/ptmx", "dev/ptmx"))
			goto out;
		SYSERROR("failed to symlink '/dev/pts/ptmx'->'/dev/ptmx'");
		return -1;
	}

	if (realpath("dev/ptmx", target) && !strcmp(target, "/dev/pts/ptmx"))
		goto out;

	/* fallback here, /dev/pts/ptmx exists just mount bind */
	if (mount("dev/pts/ptmx", "dev/ptmx", "none", MS_BIND, 0)) {
		SYSERROR("mount failed '/dev/pts/ptmx'->'/dev/ptmx'");
		return -1;
	}

	INFO("created new pts instance");

out:
	return 0;
}

static int setup_personality(int persona)
{
	if (persona == -1)
		return 0;

	if (personality(persona) < 0) {
		SYSERROR("failed to set personality to '0x%x'", persona);
		return -1;
	}

	INFO("set personality to '0x%x'", persona);

	return 0;
}

static int setup_dev_console(const struct lxc_rootfs *rootfs,
			 const struct lxc_console *console)
{
	char path[MAXPATHLEN];
	struct stat s;
	int ret;

	ret = snprintf(path, sizeof(path), "%s/dev/console", rootfs->mount);
	if (ret >= sizeof(path)) {
		ERROR("console path too long\n");
		return -1;
	}

	if (access(path, F_OK)) {
		WARN("rootfs specified but no console found at '%s'", path);
		return 0;
	}

	if (console->peer == -1) {
		INFO("no console output required");
		return 0;
	}

	if (stat(path, &s)) {
		SYSERROR("failed to stat '%s'", path);
		return -1;
	}

	if (chmod(console->name, s.st_mode)) {
		SYSERROR("failed to set mode '0%o' to '%s'",
			 s.st_mode, console->name);
		return -1;
	}

	if (mount(console->name, path, "none", MS_BIND, 0)) {
		ERROR("failed to mount '%s' on '%s'", console->name, path);
		return -1;
	}

	INFO("console has been setup");
	return 0;
}

static int setup_ttydir_console(const struct lxc_rootfs *rootfs,
			 const struct lxc_console *console,
			 char *ttydir)
{
	char path[MAXPATHLEN], lxcpath[MAXPATHLEN];
	int ret;

	/* create rootfs/dev/<ttydir> directory */
	ret = snprintf(path, sizeof(path), "%s/dev/%s", rootfs->mount,
		       ttydir);
	if (ret >= sizeof(path))
		return -1;
	ret = mkdir(path, 0755);
	if (ret && errno != EEXIST) {
		SYSERROR("failed with errno %d to create %s\n", errno, path);
		return -1;
	}
	INFO("created %s\n", path);

	ret = snprintf(lxcpath, sizeof(lxcpath), "%s/dev/%s/console",
		       rootfs->mount, ttydir);
	if (ret >= sizeof(lxcpath)) {
		ERROR("console path too long\n");
		return -1;
	}

	snprintf(path, sizeof(path), "%s/dev/console", rootfs->mount);
	ret = unlink(path);
	if (ret && errno != ENOENT) {
		SYSERROR("error unlinking %s\n", path);
		return -1;
	}

	ret = creat(lxcpath, 0660);
	if (ret==-1 && errno != EEXIST) {
		SYSERROR("error %d creating %s\n", errno, lxcpath);
		return -1;
	}
	close(ret);

	if (console->peer == -1) {
		INFO("no console output required");
		return 0;
	}

	if (mount(console->name, lxcpath, "none", MS_BIND, 0)) {
		ERROR("failed to mount '%s' on '%s'", console->name, lxcpath);
		return -1;
	}

	/* create symlink from rootfs/dev/console to 'lxc/console' */
	snprintf(lxcpath, sizeof(lxcpath), "%s/console", ttydir);
	ret = symlink(lxcpath, path);
	if (ret) {
		SYSERROR("failed to create symlink for console");
		return -1;
	}

	INFO("console has been setup on %s", lxcpath);

	return 0;
}

static int setup_console(const struct lxc_rootfs *rootfs,
			 const struct lxc_console *console,
			 char *ttydir)
{
	/* We don't have a rootfs, /dev/console will be shared */
	if (!rootfs->path)
		return 0;
	if (!ttydir)
		return setup_dev_console(rootfs, console);

	return setup_ttydir_console(rootfs, console, ttydir);
}

static int setup_cgroup(const char *name, struct lxc_list *cgroups)
{
	struct lxc_list *iterator;
	struct lxc_cgroup *cg;
	int ret = -1;

	if (lxc_list_empty(cgroups))
		return 0;

	lxc_list_for_each(iterator, cgroups) {

		cg = iterator->elem;

		if (lxc_cgroup_set(name, cg->subsystem, cg->value))
			goto out;

		DEBUG("cgroup '%s' set to '%s'", cg->subsystem, cg->value);
	}

	ret = 0;
	INFO("cgroup has been setup");
out:
	return ret;
}

struct mount_option_state_t
{
	unsigned long flags;
	char *data;
};

static void parse_mntopt(const char *const opt, struct mount_option_state_t *const mos)
{
	const struct mount_opt *mo;

	/* If opt is found in mount_opt, set or clear flags.
	 * Otherwise append it to data. */

	for (mo = mount_opt; mo != (mount_opt + (sizeof(mount_opt) / sizeof(mount_opt[0]))); ++mo) {
		if (!strncmp(opt, mo->name, strlen(mo->name))) {
			if (mo->clear)
				mos->flags &= ~mo->flag;
			else
				mos->flags |= mo->flag;
			return;
		}
	}

	if (*mos->data)
		strcat(mos->data, ",");
	strcat(mos->data, opt);
}

static int parse_mntopts(const char *mntopts, struct mount_option_state_t *mo)
{
	char *s, *data;
	char *p, *saveptr = NULL;

	mo->flags = 0;
	mo->data = NULL;
	if (!mntopts)
		return 0;

	s = strdup(mntopts);
	if (!s) {
		SYSERROR("failed to allocate memory");
		return -1;
	}

	data = malloc(strlen(s) + 1);
	if (!data) {
		SYSERROR("failed to allocate memory");
		free(s);
		return -1;
	}
	*data = 0;
	mo->data = data;

	for (p = strtok_r(s, ",", &saveptr); p != NULL;
	     p = strtok_r(NULL, ",", &saveptr))
		parse_mntopt(p, mo);

	if (!*data)
	{
		mo->data = NULL;
		free(data);
	}
	free(s);

	return 0;
}

struct recursive_mkdir_state_t
{
	const char *dir_basename;
	struct statfs fsst;
	struct stat fdst;
};

static int check_acceptable_fs_type(const int fd, const char *const fsname, const char *const p, struct recursive_mkdir_state_t *const rms)
{
	memset(&rms->fsst, 0, sizeof(rms->fsst));
	const int rcstatfs = fstatfs(fd, &rms->fsst);
	if (rcstatfs)
	{
		SYSERROR("failed to fstatfs '%s' for '%s'", p, fsname);
		return -1;
	}
	if (rms->fsst.f_type != TMPFS_MAGIC)
	{
		WARN("mountpoint parent '%s' not on tmpfs, will not auto-create mountpoint for '%s'.", p, fsname);
		return -1;
	}
	memset(&rms->fdst, 0, sizeof(rms->fdst));
	const int rcstat = fstat(fd, &rms->fdst);
	if (rcstat)
	{
		SYSERROR("failed to fstat '%s' for '%s'", p, fsname);
		return -1;
	}
	return 0;
}

static int open_mkdir_at(const int dirfd, const char *dirname, const char *const basename, const mode_t st_mode)
{
	const int rcmkdir = mkdirat(dirfd, basename, st_mode);
	if (rcmkdir)
	{
		SYSERROR("failed to mkdirat '%s'/'%s'", dirname, basename);
		return rcmkdir;
	}
	const int fd = openat(dirfd, basename, O_RDONLY, 0);
	if (fd < 0)
	{
		SYSERROR("failed to open-after-mkdir '%s'/'%s'", dirname, basename);
	}
	return fd;
}

static int recursive_mkdir_on_tmpfs_allocated(const char *const fsname, char *const p, struct recursive_mkdir_state_t *const rms)
{
	char *const s = strrchr(p, '/');
	if (!s || s == p)
	{
		DEBUG("Target '%s' has no slashes, cannot check tmpfs for '%s'", p, fsname);
		return -1;
	}
	*s = 0;
	/*
	 * p now points at $(dirname $p)
	 */
	int fd = openat(AT_FDCWD, p, O_RDONLY, 0);
	if (fd >= 0)
	{
		const int rca = check_acceptable_fs_type(fd, fsname, p, rms);
		if (rca)
		{
			close(fd);
			return -1;
		}
	}
	else if (errno != ENOENT)
	{
		SYSERROR("failed to open-statfs '%s' for '%s'", p, fsname);
		return -1;
	}
	else
	{
		const int pfd = recursive_mkdir_on_tmpfs_allocated(fsname, p, rms);
		if (pfd < 0)
			return pfd;
		fd = open_mkdir_at(pfd, p, rms->dir_basename, rms->fdst.st_mode);
		close(pfd);
		if (fd < 0)
			return fd;
	}
	*s = '/';
	rms->dir_basename = s + 1;
	return fd;
}

static int mkmntpt_at_fd(const int fdtarget, const char *const basename, const char *const fsname, const char *target, const int want_directory_mount)
{
	if (want_directory_mount)
	{
		const int rcmk = mkdirat(fdtarget, basename, 0);
		if (rcmk)
		{
			SYSERROR("failed to mkdir '%s' for source '%s'", target, fsname);
			return rcmk;
		}
		DEBUG("created directory to mount '%s' at '%s'", fsname, target);
	}
	else
	{
		const int rcmk = openat(fdtarget, basename, O_CREAT | O_RDWR, 0);
		if (rcmk < 0)
		{
			SYSERROR("failed to open-create '%s' for '%s'", fsname, target);
			return rcmk;
		}
		close(rcmk);
		DEBUG("created file to mount '%s' at '%s'", fsname, target);
	}
	return 0;
}

static int recursive_mkdir_on_tmpfs_writable(const char *const fsname, char *const p, const int want_directory_mount)
{
	struct recursive_mkdir_state_t rms;
	const int pfd = recursive_mkdir_on_tmpfs_allocated(fsname, p, &rms);
	if (pfd < 0)
		return pfd;
	const int rc = mkmntpt_at_fd(pfd, rms.dir_basename, fsname, p, want_directory_mount);
	close(pfd);
	return rc;
}

static int recursive_mkdir_on_tmpfs(const char *const fsname, const char *const target, const int want_directory_mount)
{
	char *const p = strdup(target);
	if (!p)
	{
		SYSERROR("failed to strdup '%s'", target);
		return -1;
	}
	const int rc = recursive_mkdir_on_tmpfs_writable(fsname, p, want_directory_mount);
	free(p);
	return rc;
}

static int mount_or_make(const char *const fsname, const char *target, const char *fstype, unsigned long mountflags, const char *data)
{
	if (!mount(fsname, target, fstype, mountflags, data))
		return 0;
	if (errno != ENOENT)
	{
		SYSERROR("failed to mount '%s' on '%s'", fsname, target);
		return -1;
	}
	int want_dir = 1;
	if (mountflags & MS_BIND)
	{
		struct stat st;
		memset(&st, 0, sizeof(st));
		if (stat(fsname, &st))
		{
			SYSERROR("failed to stat '%s' for '%s'", fsname, target);
			return -1;
		}
		want_dir = S_ISDIR(st.st_mode);
	}
	const int rc = recursive_mkdir_on_tmpfs(fsname, target, want_dir);
	if (rc < 0)
		return rc;
	if (!mount(fsname, target, fstype, mountflags, data))
		return 0;
	SYSERROR("failed to mount '%s' on '%s'", fsname, target);
	return -1;
}

static int mount_entry(const char *fsname, const char *target,
		       const char *fstype, const struct mount_option_state_t *const mo)
{
	const unsigned long mountflags = mo->flags;
	const char *const data = mo->data;
	if (!(mountflags & MS_REMOUNT) && mount_or_make(fsname, target, fstype, mountflags, data)) {
		return -1;
	}

	if ((mountflags & MS_REMOUNT) || (mountflags & MS_BIND)) {

		DEBUG("remounting %s on %s to respect bind or remount options",
		      fsname, target);

		if (mount(fsname, target, fstype,
			  mountflags | MS_REMOUNT, data)) {
			SYSERROR("failed to mount '%s' on '%s'",
				 fsname, target);
			return -1;
		}
	}

	DEBUG("mounted '%s' on '%s', type '%s'", fsname, target, fstype);

	return 0;
}

static inline int mount_entry_on_systemfs(struct mntent *mntent, const struct mount_option_state_t *const mo)
{
	int ret;

	ret = mount_entry(mntent->mnt_fsname, mntent->mnt_dir,
			  mntent->mnt_type, mo);
	return ret;
}

static int mount_entry_on_absolute_rootfs(struct mntent *mntent, const struct mount_option_state_t *const mo,
					  const struct lxc_rootfs *rootfs)
{
	char *aux;
	char path[MAXPATHLEN];
	int ret = 0;

	aux = strstr(mntent->mnt_dir, rootfs->path);
	if (!aux) {
		WARN("ignoring mount point '%s'", mntent->mnt_dir);
		goto out;
	}

	snprintf(path, MAXPATHLEN, "%s/%s", rootfs->mount,
		 aux + strlen(rootfs->path));

	ret = mount_entry(mntent->mnt_fsname, path, mntent->mnt_type,
			  mo);

out:
	return ret;
}

static int mount_entry_on_relative_rootfs(struct mntent *mntent, const struct mount_option_state_t *const mo,
					  const char *rootfs)
{
	char path[MAXPATHLEN];
	int ret;

        /* relative to root mount point */
	snprintf(path, sizeof(path), "%s/%s", rootfs, mntent->mnt_dir);

	ret = mount_entry(mntent->mnt_fsname, path, mntent->mnt_type,
			  mo);

	return ret;
}

static void free_mount_option_state(struct mount_option_state_t *const mo)
{
	free(mo->data);
}

static int mkdirat_ignore_eexist(const int fd, const char *const dirname, const char *const basename, const mode_t st_mode)
{
	const int rcmkdir = mkdirat(fd, basename, st_mode);
	if (!rcmkdir)
	{
		DEBUG("created directory mountpoint '%s'/'%s' %#o", dirname, basename, st_mode);
		return 0;
	}
	if (errno == EEXIST)
	{
		DEBUG("directory already exists '%s'/'%s'", dirname, basename);
		return 0;
	}
	SYSERROR("failed to mkdirat '%s'/'%s' %#o", dirname, basename, st_mode);
	return -1;
}

static int openat_ignore_eexist(const int fd, const char *const dirname, const char *const basename, const mode_t st_mode)
{
	const int rc = openat(fd, basename, O_RDWR | O_CREAT, st_mode);
	if (rc >= 0)
	{
		close(rc);
		DEBUG("created file mountpoint '%s'/'%s' %#o", dirname, basename, st_mode);
		return 0;
	}
	if (errno == EEXIST)
	{
		DEBUG("file already exists '%s'/'%s'", dirname, basename);
		return 0;
	}
	SYSERROR("failed to openat '%s'/'%s' %#o", dirname, basename, st_mode);
	return -1;
}

static int setup_rootfs_dev_console_mntpt(const int fd, const char *const dirname, const struct lxc_console *const console)
{
	if (console->peer == -1) {
		DEBUG("no console output required, skipping probe of '%s'/dev/console", dirname);
		return 0;
	}
	int rc;
	rc = openat_ignore_eexist(fd, dirname, "console", S_IRUSR | S_IWUSR);
	return rc;
}

static int setup_rootfs_dev_mountpoints_fd(const int fd, const char *const dirname, const struct lxc_console *const console)
{
	int rc;
	rc = mkdirat_ignore_eexist(fd, dirname, "pts", 0);
	if (rc)
		return rc;
	rc = mkdirat_ignore_eexist(fd, dirname, "shm", 0);
	if (rc)
		return rc;
	rc = mkdirat_ignore_eexist(fd, dirname, "mqueue", 0);
	if (rc)
		return rc;
	rc = setup_rootfs_dev_console_mntpt(fd, dirname, console);
	return rc;
}

static int setup_rootfs_dev_mountpoints(const int fd, const char *const dirname, const struct lxc_console *const console)
{
	int rc;
	/*
	 * Allow all users to traverse /dev, in case the configuration does
	 * not mount anything here.
	 */
	rc = mkdirat_ignore_eexist(fd, dirname, "dev", S_IXUSR | S_IXGRP | S_IXOTH);
	if (rc)
		return rc;
	const int dfd = openat(fd, "dev", O_RDONLY);
	if (dfd < 0) {
		SYSERROR("failed to open-after-mkdir '%s'/'%s'", dirname, "dev");
		return rc;
	}
	rc = setup_rootfs_dev_mountpoints_fd(dfd, dirname, console);
	close(dfd);
	return rc;
}

static int setup_rootfs_magic_directories_fd(const int fd, const char *const dirname, const struct lxc_console *const console)
{
	struct statfs buf;
	memset(&buf, 0, sizeof(buf));
	const int rcsf = fstatfs(fd, &buf);
	if (rcsf)
	{
		WARN("failed to statfs '%s': %s", dirname, strerror(errno));
		return 0;
	}
	if (buf.f_type != TMPFS_MAGIC)
	{
		DEBUG("rootfs not a tmpfs, skipping directory probes");
		return 0;
	}
	int rc;
	rc = setup_rootfs_dev_mountpoints(fd, dirname, console);
	if (rc)
		return rc;
	rc = mkdirat_ignore_eexist(fd, dirname, "proc", 0);
	if (rc)
		return rc;
	return 0;
}

static int setup_rootfs_magic_directories(const struct lxc_rootfs *const rootfs, const struct lxc_console *const console)
{
	if (!rootfs->path)
		return 0;
	const int fd = open(rootfs->path, O_RDONLY, 0);
	if (fd < 0)
	{
		WARN("failed to open '%s': %s", rootfs->path, strerror(errno));
		return 0;
	}
	const int rc = setup_rootfs_magic_directories_fd(fd, rootfs->path, console);
	close(fd);
	return rc;
}

static int mount_file_entries(const struct lxc_rootfs *rootfs, const struct lxc_console *const console, FILE *file, struct mount_file_entries_state_t *const mfe_state)
{
	struct mntent *mntent;
	int ret = -1;

	while ((mntent = getmntent(file))) {
		struct mount_option_state_t mo;
		if (parse_mntopts(mntent->mnt_opts, &mo) < 0) {
			ERROR("failed to parse mount option '%s'", mntent->mnt_opts);
			return -1;
		}
		/*
		 * A remount of the container rootfs could make it read-only, so
		 * create the magic directories early if a remount is detected.
		 */
		if ((mo.flags & MS_REMOUNT) && !mfe_state->seen_remount)
		{
			mfe_state->seen_remount = 1;
			if (setup_rootfs_magic_directories(rootfs, console)) {
				free_mount_option_state(&mo);
				return -1;
			}
		}

		int rcmnt;
		if (!rootfs->path) {
			rcmnt = mount_entry_on_systemfs(mntent, &mo);
		}
		else

		/* We have a separate root, mounts are relative to it */
		if (mntent->mnt_dir[0] != '/') {
			rcmnt = mount_entry_on_relative_rootfs(mntent, &mo, rootfs->mount);
		}
		else
			rcmnt = mount_entry_on_absolute_rootfs(mntent, &mo, rootfs);
		free_mount_option_state(&mo);
		if (rcmnt)
			return rcmnt;
	}

	ret = 0;

	INFO("mount points have been setup");
	return ret;
}

static int setup_mount(const struct lxc_rootfs *rootfs, const struct lxc_console *const console, const char *fstab, struct mount_file_entries_state_t *const mfe_state)
{
	FILE *file;
	int ret;

	if (!fstab)
		return 0;

	file = setmntent(fstab, "r");
	if (!file) {
		SYSERROR("failed to use '%s'", fstab);
		return -1;
	}

	ret = mount_file_entries(rootfs, console, file, mfe_state);

	endmntent(file);
	return ret;
}

static int setup_mount_entries(const struct lxc_rootfs *rootfs, const struct lxc_console *const console, struct lxc_list *mount, struct mount_file_entries_state_t *const mfe_state)
{
	FILE *file;
	struct lxc_list *iterator;
	char *mount_entry;
	int ret;

	file = tmpfile();
	if (!file) {
		ERROR("tmpfile error: %m");
		return -1;
	}

	lxc_list_for_each(iterator, mount) {
		mount_entry = iterator->elem;
		fprintf(file, "%s\n", mount_entry);
	}

	rewind(file);

	ret = mount_file_entries(rootfs, console, file, mfe_state);

	fclose(file);
	return ret;
}

static int setup_caps(struct lxc_list *caps)
{
	struct lxc_list *iterator;
	char *drop_entry;
	char *ptr;
	int i, capid;

	lxc_list_for_each(iterator, caps) {

		drop_entry = iterator->elem;

		capid = -1;

		for (i = 0; i < sizeof(caps_opt)/sizeof(caps_opt[0]); i++) {

			if (strcmp(drop_entry, caps_opt[i].name))
				continue;

			capid = caps_opt[i].value;
			break;
		}

		if (capid < 0) {
			/* try to see if it's numeric, so the user may specify
			* capabilities  that the running kernel knows about but
			* we don't */
			capid = strtol(drop_entry, &ptr, 10);
			if (!ptr || *ptr != '\0' ||
			capid == LONG_MIN || capid == LONG_MAX)
				/* not a valid number */
				capid = -1;
			else if (capid > lxc_caps_last_cap())
				/* we have a number but it's not a valid
				* capability */
				capid = -1;
		}

	        if (capid < 0) {
			ERROR("unknown capability %s", drop_entry);
			return -1;
		}

		DEBUG("drop capability '%s' (%d)", drop_entry, capid);

		if (prctl(PR_CAPBSET_DROP, capid, 0, 0, 0)) {
                       SYSERROR("failed to remove %s capability", drop_entry);
                       return -1;
                }

	}

	DEBUG("capabilities has been setup");

	return 0;
}

static int setup_hw_addr(char *hwaddr, const char *ifname)
{
	struct sockaddr sockaddr;
	struct ifreq ifr;
	int ret, fd;

	ret = lxc_convert_mac(hwaddr, &sockaddr);
	if (ret) {
		ERROR("mac address '%s' conversion failed : %s",
		      hwaddr, strerror(-ret));
		return -1;
	}

	memcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	memcpy((char *) &ifr.ifr_hwaddr, (char *) &sockaddr, sizeof(sockaddr));

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		ERROR("socket failure : %s", strerror(errno));
		return -1;
	}

	ret = ioctl(fd, SIOCSIFHWADDR, &ifr);
	close(fd);
	if (ret)
		ERROR("ioctl failure : %s", strerror(errno));

	DEBUG("mac address '%s' on '%s' has been setup", hwaddr, ifname);

	return ret;
}

static int setup_ipv4_addr(const struct lxc_list *ip, int ifindex)
{
	const struct lxc_list *iterator;
	const struct lxc_inetdev *inetdev;
	int err;

	lxc_list_for_each(iterator, ip) {

		inetdev = iterator->elem;

		err = lxc_ipv4_addr_add(ifindex, &inetdev->addr,
					&inetdev->bcast, inetdev->prefix);
		if (err) {
			ERROR("failed to setup_ipv4_addr ifindex %d : %s",
			      ifindex, strerror(-err));
			return -1;
		}
	}

	return 0;
}

static int setup_ipv6_addr(const struct lxc_list *ip, int ifindex)
{
	const struct lxc_list *iterator;
	const struct lxc_inet6dev *inet6dev;
	int err;

	lxc_list_for_each(iterator, ip) {

		inet6dev = iterator->elem;

		err = lxc_ipv6_addr_add(ifindex, &inet6dev->addr,
					&inet6dev->mcast, &inet6dev->acast,
					inet6dev->prefix);
		if (err) {
			ERROR("failed to setup_ipv6_addr ifindex %d : %s",
			      ifindex, strerror(-err));
			return -1;
		}
	}

	return 0;
}

static int setup_interface_attr(const struct lxc_interface_attr *attr, const char *current_ifname, const int ifindex)
{
	/* set a mac address */
	if (attr->hwaddr) {
		if (setup_hw_addr(attr->hwaddr, current_ifname)) {
			ERROR("failed to setup hw address for '%s'",
			      current_ifname);
			return -1;
		}
	}

	/* setup ipv4 addresses on the interface */
	if (setup_ipv4_addr(&attr->ipv4, ifindex)) {
		ERROR("failed to setup ip addresses for '%s'",
			      current_ifname);
		return -1;
	}

	/* setup ipv6 addresses on the interface */
	if (setup_ipv6_addr(&attr->ipv6, ifindex)) {
		ERROR("failed to setup ipv6 addresses for '%s'",
			      current_ifname);
		return -1;
	}
	return 0;
}

static int setup_netdev(struct lxc_netdev *netdev)
{
	char ifname[IFNAMSIZ];
	char *current_ifname = ifname;
	int err;

	/* empty network namespace */
	if (!netdev->ifindex) {
		if (netdev->flags & IFF_UP) {
			err = lxc_netdev_up("lo");
			if (err) {
				ERROR("failed to set the loopback up : %s",
				      strerror(-err));
				return -1;
			}
		}
		return 0;
	}

	/* retrieve the name of the interface */
	if (!if_indextoname(netdev->ifindex, current_ifname)) {
		ERROR("no interface corresponding to index '%d'",
		      netdev->ifindex);
		return -1;
	}

	/* default: let the system to choose one interface name */
	if (!netdev->guest_attr.name)
		netdev->guest_attr.name = netdev->type == LXC_NET_PHYS ?
			netdev->link : "eth%d";

	/* rename the interface name */
	err = lxc_netdev_rename_by_name(ifname, netdev->guest_attr.name);
	if (err) {
		ERROR("failed to rename %s->%s : %s", ifname, netdev->guest_attr.name,
		      strerror(-err));
		return -1;
	}

	/* Re-read the name of the interface because its name has changed
	 * and would be automatically allocated by the system
	 */
	if (!if_indextoname(netdev->ifindex, current_ifname)) {
		ERROR("no interface corresponding to index '%d'",
		      netdev->ifindex);
		return -1;
	}

	if (setup_interface_attr(&netdev->guest_attr, current_ifname, netdev->ifindex))
		return -1;

	/* set the network device up */
	if (netdev->flags & IFF_UP) {
		int err;

		err = lxc_netdev_up(current_ifname);
		if (err) {
			ERROR("failed to set '%s' up : %s", current_ifname,
			      strerror(-err));
			return -1;
		}

		/* the network is up, make the loopback up too */
		err = lxc_netdev_up("lo");
		if (err) {
			ERROR("failed to set the loopback up : %s",
			      strerror(-err));
			return -1;
		}
	}

	/* We can only set up the default routes after bringing
	 * up the interface, sine bringing up the interface adds
	 * the link-local routes and we can't add a default
	 * route if the gateway is not reachable. */

	/* setup ipv4 gateway on the interface */
	if (netdev->ipv4_gateway) {
		if (!(netdev->flags & IFF_UP)) {
			ERROR("Cannot add ipv4 gateway for %s when not bringing up the interface", ifname);
			return -1;
		}

		if (lxc_list_empty(&netdev->guest_attr.ipv4)) {
			ERROR("Cannot add ipv4 gateway for %s when not assigning an address", ifname);
			return -1;
		}

		err = lxc_ipv4_gateway_add(netdev->ifindex, netdev->ipv4_gateway);
		if (err) {
			ERROR("failed to setup ipv4 gateway for '%s': %s",
				      ifname, strerror(-err));
			if (netdev->ipv4_gateway_auto) {
				char buf[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, netdev->ipv4_gateway, buf, sizeof(buf));
				ERROR("tried to set autodetected ipv4 gateway '%s'", buf);
			}
			return -1;
		}
	}

	/* setup ipv6 gateway on the interface */
	if (netdev->ipv6_gateway) {
		if (!(netdev->flags & IFF_UP)) {
			ERROR("Cannot add ipv6 gateway for %s when not bringing up the interface", ifname);
			return -1;
		}

		if (lxc_list_empty(&netdev->guest_attr.ipv6) && !IN6_IS_ADDR_LINKLOCAL(netdev->ipv6_gateway)) {
			ERROR("Cannot add ipv6 gateway for %s when not assigning an address", ifname);
			return -1;
		}

		err = lxc_ipv6_gateway_add(netdev->ifindex, netdev->ipv6_gateway);
		if (err) {
			ERROR("failed to setup ipv6 gateway for '%s': %s",
				      ifname, strerror(-err));
			if (netdev->ipv6_gateway_auto) {
				char buf[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET, netdev->ipv6_gateway, buf, sizeof(buf));
				ERROR("tried to set autodetected ipv6 gateway '%s'", buf);
			}
			return -1;
		}
	}

	DEBUG("'%s' has been setup", current_ifname);

	return 0;
}

static int setup_network(struct lxc_list *network)
{
	struct lxc_list *iterator;
	struct lxc_netdev *netdev;

	lxc_list_for_each(iterator, network) {

		netdev = iterator->elem;

		if (setup_netdev(netdev)) {
			ERROR("failed to setup netdev");
			return -1;
		}
	}

	if (!lxc_list_empty(network))
		INFO("network has been setup");

	return 0;
}

static int setup_private_host_hw_addr(char *veth1)
{
	struct ifreq ifr;
	int err;
	int sockfd;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		return -errno;

	snprintf((char *)ifr.ifr_name, IFNAMSIZ, "%s", veth1);
	err = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if (err < 0) {
		close(sockfd);
		return -errno;
	}

	ifr.ifr_hwaddr.sa_data[0] = 0xfe;
	err = ioctl(sockfd, SIOCSIFHWADDR, &ifr);
	close(sockfd);
	if (err < 0)
		return -errno;

	DEBUG("mac address of host interface '%s' changed to private "
	      "%02x:%02x:%02x:%02x:%02x:%02x", veth1,
	      ifr.ifr_hwaddr.sa_data[0] & 0xff,
	      ifr.ifr_hwaddr.sa_data[1] & 0xff,
	      ifr.ifr_hwaddr.sa_data[2] & 0xff,
	      ifr.ifr_hwaddr.sa_data[3] & 0xff,
	      ifr.ifr_hwaddr.sa_data[4] & 0xff,
	      ifr.ifr_hwaddr.sa_data[5] & 0xff);

	return 0;
}

struct lxc_conf *lxc_conf_init(void)
{
	struct lxc_conf *new;

	new = 	malloc(sizeof(*new));
	if (!new) {
		ERROR("lxc_conf_init : %m");
		return NULL;
	}
	memset(new, 0, sizeof(*new));

	new->personality = -1;
	new->console.path = NULL;
	new->console.peer = -1;
	new->console.master = -1;
	new->console.slave = -1;
	new->console.name[0] = '\0';
	new->rootfs.mount = LXCROOTFSMOUNT;
	lxc_list_init(&new->fstab_list);
	lxc_list_init(&new->cgroup);
	lxc_list_init(&new->network);
	lxc_list_init(&new->mount_list);
	lxc_list_init(&new->caps);

	return new;
}

static int instanciate_veth(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	char veth1buf[IFNAMSIZ], *veth1;
	char veth2buf[IFNAMSIZ], *veth2;
	int err;
	int veth1ifindex;

	if (netdev->priv.veth_attr.host_attr.name)
		veth1 = netdev->priv.veth_attr.host_attr.name;
	else {
		snprintf(veth1buf, sizeof(veth1buf), "vethXXXXXX");
		veth1 = mktemp(veth1buf);
	}

	snprintf(veth2buf, sizeof(veth2buf), "vethXXXXXX");
	veth2 = mktemp(veth2buf);

	if (!strlen(veth1) || !strlen(veth2)) {
		ERROR("failed to allocate a temporary name");
		return -1;
	}

	err = lxc_veth_create(veth1, veth2);
	if (err) {
		ERROR("failed to create %s-%s : %s", veth1, veth2,
		      strerror(-err));
		return -1;
	}

	/* changing the high byte of the mac address to 0xfe, the bridge interface
	 * will always keep the host's mac address and not take the mac address
	 * of a container */
	err = setup_private_host_hw_addr(veth1);
	if (err) {
		ERROR("failed to change mac address of host interface '%s' : %s",
			veth1, strerror(-err));
		goto out_delete;
	}

	if (netdev->mtu) {
		err = lxc_netdev_set_mtu(veth1, atoi(netdev->mtu));
		if (!err)
			err = lxc_netdev_set_mtu(veth2, atoi(netdev->mtu));
		if (err) {
			ERROR("failed to set mtu '%s' for %s-%s : %s",
			      netdev->mtu, veth1, veth2, strerror(-err));
			goto out_delete;
		}
	}

	veth1ifindex = if_nametoindex(veth1);
	if (!veth1ifindex)
	{
		ERROR("failed to retrieve the index for %s", veth1);
		goto out_delete;
	}
	if (setup_interface_attr(&netdev->priv.veth_attr.host_attr, veth1, veth1ifindex))
		goto out_delete;

	if (netdev->link) {
		err = lxc_bridge_attach(netdev->link, veth1);
		if (err) {
			ERROR("failed to attach '%s' to the bridge '%s' : %s",
				      veth1, netdev->link, strerror(-err));
			goto out_delete;
		}
	}

	netdev->ifindex = if_nametoindex(veth2);
	if (!netdev->ifindex) {
		ERROR("failed to retrieve the index for %s", veth2);
		goto out_delete;
	}

	err = lxc_netdev_up(veth1);
	if (err) {
		ERROR("failed to set %s up : %s", veth1, strerror(-err));
		goto out_delete;
	}

	if (netdev->upscript) {
		err = run_script(handler->name, "net", netdev->upscript, "up",
				 "veth", veth1, (char*) NULL);
		if (err)
			goto out_delete;
	}

	DEBUG("instanciated veth '%s/%s', index is '%d'",
	      veth1, veth2, netdev->ifindex);

	return 0;

out_delete:
	lxc_netdev_delete_by_name(veth1);
	return -1;
}

static int instanciate_macvlan(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	char peerbuf[IFNAMSIZ], *peer;
	int err;

	if (!netdev->link) {
		ERROR("no link specified for macvlan netdev");
		return -1;
	}

	snprintf(peerbuf, sizeof(peerbuf), "mcXXXXXX");

	peer = mktemp(peerbuf);
	if (!strlen(peer)) {
		ERROR("failed to make a temporary name");
		return -1;
	}

	err = lxc_macvlan_create(netdev->link, peer,
				 netdev->priv.macvlan_attr.mode);
	if (err) {
		ERROR("failed to create macvlan interface '%s' on '%s' : %s",
		      peer, netdev->link, strerror(-err));
		return -1;
	}

	netdev->ifindex = if_nametoindex(peer);
	if (!netdev->ifindex) {
		ERROR("failed to retrieve the index for %s", peer);
		lxc_netdev_delete_by_name(peer);
		return -1;
	}

	if (netdev->upscript) {
		err = run_script(handler->name, "net", netdev->upscript, "up",
				 "macvlan", netdev->link, (char*) NULL);
		if (err)
			return -1;
	}

	DEBUG("instanciated macvlan '%s', index is '%d' and mode '%d'",
	      peer, netdev->ifindex, netdev->priv.macvlan_attr.mode);

	return 0;
}

/* XXX: merge with instanciate_macvlan */
static int instanciate_vlan(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	char peer[IFNAMSIZ];
	int err;

	if (!netdev->link) {
		ERROR("no link specified for vlan netdev");
		return -1;
	}

	snprintf(peer, sizeof(peer), "vlan%d", netdev->priv.vlan_attr.vid);

	err = lxc_vlan_create(netdev->link, peer, netdev->priv.vlan_attr.vid);
	if (err) {
		ERROR("failed to create vlan interface '%s' on '%s' : %s",
		      peer, netdev->link, strerror(-err));
		return -1;
	}

	netdev->ifindex = if_nametoindex(peer);
	if (!netdev->ifindex) {
		ERROR("failed to retrieve the ifindex for %s", peer);
		lxc_netdev_delete_by_name(peer);
		return -1;
	}

	DEBUG("instanciated vlan '%s', ifindex is '%d'", " vlan1000",
	      netdev->ifindex);

	return 0;
}

static int instanciate_phys(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	if (!netdev->link) {
		ERROR("no link specified for the physical interface");
		return -1;
	}

	netdev->ifindex = if_nametoindex(netdev->link);
	if (!netdev->ifindex) {
		ERROR("failed to retrieve the index for %s", netdev->link);
		return -1;
	}

	if (netdev->upscript) {
		int err;
		err = run_script(handler->name, "net", netdev->upscript,
				 "up", "phys", netdev->link, (char*) NULL);
		if (err)
			return -1;
	}

	return 0;
}

static int instanciate_empty(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	netdev->ifindex = 0;
	if (netdev->upscript) {
		int err;
		err = run_script(handler->name, "net", netdev->upscript,
				 "up", "empty", (char*) NULL);
		if (err)
			return -1;
	}
	return 0;
}

int lxc_create_network(struct lxc_handler *handler)
{
	struct lxc_list *network = &handler->conf->network;
	struct lxc_list *iterator;

	lxc_list_for_each(iterator, network) {
		struct lxc_netdev *netdev = iterator->elem;
		const unsigned nettype = netdev->type;

		if (nettype >= sizeof(netdev_conf) / sizeof(netdev_conf[0])) {
			ERROR("invalid network configuration type '%d'",
			      netdev->type);
			return -1;
		}

		if (netdev_conf[nettype](handler, netdev)) {
			ERROR("failed to create netdev");
			return -1;
		}

	}

	return 0;
}

void lxc_delete_network(struct lxc_list *network)
{
	struct lxc_list *iterator;
	struct lxc_netdev *netdev;

	lxc_list_for_each(iterator, network) {
		netdev = iterator->elem;
		if (netdev->ifindex == 0)
			continue;

		if (netdev->type == LXC_NET_PHYS) {
			if (lxc_netdev_rename_by_index(netdev->ifindex, netdev->link))
				WARN("failed to rename to the initial name the " \
				     "netdev '%s'", netdev->link);
			continue;
		}

		/* Recent kernel remove the virtual interfaces when the network
		 * namespace is destroyed but in case we did not moved the
		 * interface to the network namespace, we have to destroy it
		 */
		if (lxc_netdev_delete_by_index(netdev->ifindex))
			WARN("failed to remove interface '%s'", netdev->guest_attr.name);
	}
}

int lxc_assign_network(struct lxc_list *network, pid_t pid)
{
	struct lxc_list *iterator;
	struct lxc_netdev *netdev;
	int err;

	lxc_list_for_each(iterator, network) {

		netdev = iterator->elem;

		/* empty network namespace, nothing to move */
		if (!netdev->ifindex)
			continue;

		err = lxc_netdev_move_by_index(netdev->ifindex, pid);
		if (err) {
			ERROR("failed to move '%s' to the container : %s",
			      netdev->link, strerror(-err));
			return -1;
		}

		DEBUG("move '%s'[%s] to '%d'", netdev->guest_attr.name, netdev->guest_attr.hwaddr, pid);
	}

	return 0;
}

int lxc_find_gateway_addresses(struct lxc_handler *handler)
{
	struct lxc_list *network = &handler->conf->network;
	struct lxc_list *iterator;
	struct lxc_netdev *netdev;
	int link_index;

	lxc_list_for_each(iterator, network) {
		netdev = iterator->elem;

		if (!netdev->ipv4_gateway_auto && !netdev->ipv6_gateway_auto)
			continue;

		if (netdev->type != LXC_NET_VETH && netdev->type != LXC_NET_MACVLAN) {
			ERROR("gateway = auto only supported for "
			      "veth and macvlan");
			return -1;
		}

		if (!netdev->link) {
			ERROR("gateway = auto needs a link interface");
			return -1;
		}

		link_index = if_nametoindex(netdev->link);
		if (!link_index)
			return -EINVAL;

		if (netdev->ipv4_gateway_auto) {
			if (lxc_ipv4_addr_get(link_index, &netdev->ipv4_gateway)) {
				ERROR("failed to automatically find ipv4 gateway "
				      "address from link interface '%s'", netdev->link);
				return -1;
			}
		}

		if (netdev->ipv6_gateway_auto) {
			if (lxc_ipv6_addr_get(link_index, &netdev->ipv6_gateway)) {
				ERROR("failed to automatically find ipv6 gateway "
				      "address from link interface '%s'", netdev->link);
				return -1;
			}
		}
	}

	return 0;
}

int lxc_create_tty(const char *name, struct lxc_conf *conf)
{
	struct lxc_tty_info *tty_info = &conf->tty_info;
	int i;

	/* no tty in the configuration */
	if (!conf->tty)
		return 0;

	tty_info->pty_info =
		malloc(sizeof(*tty_info->pty_info)*conf->tty);
	if (!tty_info->pty_info) {
		SYSERROR("failed to allocate pty_info");
		return -1;
	}

	for (i = 0; i < conf->tty; i++) {

		struct lxc_pty_info *pty_info = &tty_info->pty_info[i];

		if (openpty(&pty_info->master, &pty_info->slave,
			    pty_info->name, NULL, NULL)) {
			SYSERROR("failed to create pty #%d", i);
			tty_info->nbtty = i;
			lxc_delete_tty(tty_info);
			return -1;
		}

		DEBUG("allocated pty '%s' (%d/%d)",
		      pty_info->name, pty_info->master, pty_info->slave);

                /* Prevent leaking the file descriptors to the container */
		fcntl(pty_info->master, F_SETFD, FD_CLOEXEC);
		fcntl(pty_info->slave, F_SETFD, FD_CLOEXEC);

		pty_info->busy = 0;
	}

	tty_info->nbtty = conf->tty;

	INFO("tty's configured");

	return 0;
}

void lxc_delete_tty(struct lxc_tty_info *tty_info)
{
	int i;

	for (i = 0; i < tty_info->nbtty; i++) {
		struct lxc_pty_info *pty_info = &tty_info->pty_info[i];

		close(pty_info->master);
		close(pty_info->slave);
	}

	free(tty_info->pty_info);
	tty_info->nbtty = 0;
}

int lxc_setup(const char *name, struct lxc_conf *lxc_conf)
{
	const struct lxc_list *li;
	if (setup_utsname(lxc_conf->utsname)) {
		ERROR("failed to setup the utsname for '%s'", name);
		return -1;
	}

	if (setup_network(&lxc_conf->network)) {
		ERROR("failed to setup the network for '%s'", name);
		return -1;
	}

	if (setup_rootfs(&lxc_conf->rootfs)) {
		ERROR("failed to setup rootfs for '%s'", name);
		return -1;
	}

	struct mount_file_entries_state_t mfe_state;
	memset(&mfe_state, 0, sizeof(mfe_state));
	lxc_list_for_each(li, (&lxc_conf->fstab_list)) {
		const char *fstab = li->elem;
		if (setup_mount(&lxc_conf->rootfs, &lxc_conf->console, fstab, &mfe_state)) {
			ERROR("failed to setup the mounts for '%s'", name);
			return -1;
		}
	}

	if (setup_mount_entries(&lxc_conf->rootfs, &lxc_conf->console, &lxc_conf->mount_list, &mfe_state)) {
		ERROR("failed to setup the mount entries for '%s'", name);
		return -1;
	}
	int need_setup_rootfs_magic = 0;
	if (!mfe_state.seen_remount)
		need_setup_rootfs_magic = 1;
	finalize_mount_file_entries_state(&mfe_state);
	if (need_setup_rootfs_magic)
	{
		if (setup_rootfs_magic_directories(&lxc_conf->rootfs, &lxc_conf->console))
		{
			return -1;
		}
	}

	if (setup_cgroup(name, &lxc_conf->cgroup)) {
		ERROR("failed to setup the cgroups for '%s'", name);
		return -1;
	}

	if (setup_console(&lxc_conf->rootfs, &lxc_conf->console, lxc_conf->ttydir)) {
		ERROR("failed to setup the console for '%s'", name);
		return -1;
	}

	if (setup_tty(&lxc_conf->rootfs, &lxc_conf->tty_info, lxc_conf->ttydir)) {
		ERROR("failed to setup the ttys for '%s'", name);
		return -1;
	}

	if (setup_cwd_rootfs(&lxc_conf->rootfs)) {
		return -1;
	}

	if (setup_pts(lxc_conf->pts)) {
		ERROR("failed to setup the new pts instance");
		return -1;
	}

	if (setup_personality(lxc_conf->personality)) {
		ERROR("failed to setup personality");
		return -1;
	}

	if (setup_caps(&lxc_conf->caps)) {
		ERROR("failed to drop capabilities");
		return -1;
	}

	NOTICE("'%s' is setup.", name);

	return 0;
}
