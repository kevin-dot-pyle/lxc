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

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#include "execute.h"
#include "log.h"
#include "start.h"

lxc_log_define(lxc_execute, lxc_start);

static int plan_arg_str(const int nbargs, const char *arg)
{
	if (!arg)
		return nbargs;
	return nbargs + 2;
}

static int add_arg_str(char **const argv, int nbargs, const char *opt, const char *arg)
{
	if (!arg)
		return nbargs;
	argv[nbargs++] = strdup(opt);
	argv[nbargs++] = strdup(arg);
	return nbargs;
}

static int execute_start(struct lxc_handler *handler, void* data)
{
	int j, i = 0;
	struct lxc_execute_args *my_args = data;
	char **argv;
	int argc = 0;
	int extra_argc = 0;

	while (my_args->argv[argc++]);

	extra_argc = plan_arg_str(extra_argc, my_args->exec);

	/*
	 * 3 = "lxc-init" + "--" + NULL
	 */
	argv = malloc((argc + extra_argc + 3 + (my_args->quiet ? 1 : 0)) * sizeof(*argv));
	if (!argv)
		return 1;

	argv[i++] = LXCINITDIR "/lxc-init";
	if (my_args->quiet)
		argv[i++] = "--quiet";
	i = add_arg_str(argv, i, "--exec", my_args->exec);
	argv[i++] = "--";
	for (j = 0; j < argc; j++)
		argv[i++] = my_args->argv[j];
	argv[i++] = NULL;

	NOTICE("exec'ing '%s'", my_args->argv[0]);

	execvp(argv[0], argv);
	SYSERROR("failed to exec %s", argv[0]);
	return 1;
}

static int execute_post_start(struct lxc_handler *handler, void* data)
{
	struct lxc_execute_args *my_args = data;
	NOTICE("'%s' started with pid '%d'", my_args->argv[0], handler->pid);
	return 0;
}

static struct lxc_operations execute_start_ops = {
	.start = execute_start,
	.post_start = execute_post_start
};

int lxc_execute(struct lxc_execute_args *args, const char *name,
		struct lxc_conf *conf)
{
	if (lxc_check_inherited(conf, -1))
		return -1;

	return __lxc_start(name, conf, &execute_start_ops, args);
}
