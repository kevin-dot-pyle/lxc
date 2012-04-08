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
#include <errno.h>
#include <libgen.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include "caps.h"
#include "execute.h"
#include "lxc.h"
#include "log.h"
#include "conf.h"
#include "confile.h"
#include "arguments.h"
#include "config.h"
#include "start.h"

lxc_log_define(lxc_execute_ui, lxc_execute);

static struct lxc_list defines;

static int my_checker(const struct lxc_arguments* args)
{
	if (!args->argc) {
		lxc_error(args, "missing command to execute !");
		return -1;
	}

	return 0;
}

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 'e': args->exec = arg; break;
	case 'f': args->rcfile = arg; break;
	case 's': return lxc_config_define_add(&defines, arg);
	case 'g': args->gid = arg; break;
	case 'G': args->gidlist = arg; break;
	case 'u': args->uid = arg; break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"exec", required_argument, 0, 'e'},
	{"rcfile", required_argument, 0, 'f'},
	{"define", required_argument, 0, 's'},
	{"gid", required_argument, 0, 'g'},
	{"gidlist", required_argument, 0, 'G'},
	{"uid", required_argument, 0, 'u'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-execute",
	.help     = "\
--name=NAME [--exec=PROG] -- COMMAND\n\
\n\
lxc-execute creates a container with the identifier NAME\n\
and execs COMMAND into this container.\n\
\n\
Options :\n\
" LXC_HELP_COMMON_OPTIONS "\
  -e, --exec=PROG      Program to run in the container\n\
  -g, --gid=GID        Run child as with gid GID\n\
  -G, --gidlist=GIDLST Run child with supplemental groups GIDLST\n\
  -u, --uid=UID        Run child as with uid UID\n\
",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = my_checker,
};

int main(int argc, char *argv[])
{
	struct lxc_conf *conf;

	lxc_list_init(&defines);

	if (lxc_caps_init())
		return -1;

	if (lxc_arguments_parse(&my_args, argc, argv))
		return -1;

	if (lxc_log_init(my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet))
		return -1;

	conf = lxc_conf_init();
	if (!conf) {
		ERROR("failed to initialize configuration");
		return -1;
	}

	if (lxc_config_read(my_args.rcfile, my_args.name, conf)) {
		ERROR("failed to read configuration file");
		return -1;
	}

	if (lxc_config_define_load(&defines, conf))
		return -1;

	struct lxc_execute_args ea = {
		.exec = my_args.exec,
		.uid = my_args.uid,
		.gid = my_args.gid,
		.gidlist = my_args.gidlist,
		.argv = my_args.argv,
		.pivot = NULL,
		.quiet = my_args.quiet,
	};

	if (conf->rootfs.path)
	{
		ea.pivot = conf->rootfs.pivot ? conf->rootfs.pivot : "mnt";
	}
	return lxc_execute(&ea, my_args.name, conf);
}
