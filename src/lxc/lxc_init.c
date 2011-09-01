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

#include <stdio.h>
#include <ctype.h>
#include <grp.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#define _GNU_SOURCE
#include <getopt.h>

#include "log.h"
#include "caps.h"
#include "error.h"
#include "utils.h"

lxc_log_define(lxc_init, lxc);

static int quiet;

static struct option options[] = {
	{ "exec", required_argument, 0, 'e' },
	{ "gid", required_argument, 0, 'g' },
	{ "gidlist", required_argument, 0, 'G' },
	{ "quiet", no_argument, &quiet, 1 },
	{ "uid", required_argument, 0, 'u' },
	{ 0, 0, 0, 0 },
};

static	int was_interrupted = 0;

static void parse_gidlist(const char *pi, size_t *total_groups, gid_t **result)
{
	const char *p;
	unsigned count = 0;
	*total_groups = 0;
	*result = NULL;
	for (p = pi; *p; ++p) {
		const unsigned char c = *p;
		if (isdigit(c))
			continue;
		if (c == ',')
		{
			++ count;
			continue;
		}
		ERROR("gid list must be numeric separated by commas");
		return;
	}
	if (++ count > 32)
	{
		ERROR("gid list exceeded arbitrary length limit");
		return;
	}
	gid_t *pg = malloc(count * sizeof(gid_t));
	if (!pg)
	{
		ERROR("failed to allocate gidlist: %m");
		return;
	}
	*result = pg;
	*total_groups = count;
	for (p = pi; *p; ++p) {
		char *e;
		*pg++ = strtoul(p, &e, 10);
		if (!*e)
			break;
		if (*e != ',')
			break;
		p = e;
	}
}

int main(int argc, char *argv[])
{

	void interrupt_handler(int sig)
	{
		if (!was_interrupted)
			was_interrupted = sig;
	}

	pid_t pid;
	int nbargs = 0;
	int err = -1;
	const char *program_to_exec = NULL;
	const char *gid = NULL;
	const char *uid = NULL;
	char **aargv;
	sigset_t mask, omask;
	int i, shutdown = 0;
	uid_t nuid = 0;
	gid_t ngid = 0;
	size_t gidcount = 0;
	gid_t *gidlist = NULL;
	char *p;
	int syncpipe[2];

	while (1) {
		int ret = getopt_long_only(argc, argv, "", options, NULL);
		if (ret == -1) {
			break;
		}
		if (ret == 'e') {
			program_to_exec = optarg;
			continue;
		}
		if (ret == 'g') {
			gid = optarg;
			continue;
		}
		if (ret == 'G') {
			if (gidlist)
				free(gidlist);
			parse_gidlist(optarg, &gidcount, &gidlist);
			if (!gidlist)
				exit(err);
			continue;
		}
		if (ret == 'u') {
			uid = optarg;
			continue;
		}
		if  (ret == '?')
			exit(err);

		nbargs++;
	}

	if (lxc_caps_init())
		exit(err);

	if (lxc_log_init(NULL, 0, basename(argv[0]), quiet))
		exit(err);

	if (!argv[optind]) {
		ERROR("missing command to launch");
		exit(err);
	}
	if (uid) {
		nuid = strtoul(uid, &p, 0);
		if (*p) {
			ERROR("uid must be numeric");
			exit(err);
		}
	}
	if (gid) {
		ngid = strtoul(gid, &p, 0);
		if (*p) {
			ERROR("gid must be numeric");
			exit(err);
		}
	}

	aargv = &argv[optind];
	if (!program_to_exec)
		program_to_exec = aargv[0];
	argc -= nbargs;

        /*
	 * mask all the signals so we are safe to install a
	 * signal handler and to fork
	 */
	sigfillset(&mask);
	sigdelset(&mask, SIGILL);
	sigdelset(&mask, SIGSEGV);
	sigdelset(&mask, SIGBUS);
	sigprocmask(SIG_SETMASK, &mask, &omask);

	for (i = 1; i < NSIG; i++) {
		struct sigaction act;

		/* Exclude some signals: ILL, SEGV and BUS are likely to
		 * reveal a bug and we want a core. STOP and KILL cannot be
		 * handled anyway: they're here for documentation.
		 */
		if (i == SIGILL ||
		    i == SIGSEGV ||
		    i == SIGBUS ||
		    i == SIGSTOP ||
		    i == SIGKILL)
			continue;

		sigfillset(&act.sa_mask);
		sigdelset(&act.sa_mask, SIGILL);
		sigdelset(&act.sa_mask, SIGSEGV);
		sigdelset(&act.sa_mask, SIGBUS);
		sigdelset(&act.sa_mask, SIGSTOP);
		sigdelset(&act.sa_mask, SIGKILL);
		act.sa_flags = 0;
		act.sa_handler = interrupt_handler;
		sigaction(i, &act, NULL);
	}

	if (lxc_setup_fs())
		exit(err);

	if (pipe(syncpipe))
	{
		ERROR("pipe failed: %m");
		exit(err);
	}
	pid = fork();

	if (pid < 0)
		exit(err);

	if (!pid) {
		ssize_t dummy;
		char c;
		close(syncpipe[1]);

		/* restore default signal handlers */
		for (i = 1; i < NSIG; i++)
			signal(i, SIG_DFL);

		sigprocmask(SIG_SETMASK, &omask, NULL);
		dummy = read(syncpipe[0], &c, sizeof(c));
		if (dummy < 0) {
			ERROR("read failed: %m");
			exit(err);
		}
		close(syncpipe[0]);

		NOTICE("about to exec '%s'", program_to_exec);
		if (gid) {
			if (setgid(ngid)) {
				ERROR("failed to setgid for '%s': %m", program_to_exec);
				exit(err);
			}
			if (!gidlist) {
				gidcount = 1;
				gidlist = &ngid;
			}
		}
		if (gidlist) {
			if (setgroups(gidcount, gidlist)) {
				ERROR("failed to setgroups for '%s': %m", program_to_exec);
				exit(err);
			}
		}
		if (uid) {
			if (setuid(nuid)) {
				ERROR("failed to setuid for '%s': %m", program_to_exec);
				exit(err);
			}
		}

		if (lxc_caps_reset())
			exit(err);

		execvp(program_to_exec, aargv);
		ERROR("failed to exec: '%s' : %m", program_to_exec);
		exit(err);
	}
	if (gidlist)
		free(gidlist);
	close(syncpipe[0]);

	if (lxc_caps_reset()) {
		kill(pid, SIGKILL);
		exit(err);
	}
	close(syncpipe[1]);

	/* let's process the signals now */
	sigdelset(&omask, SIGALRM);
	sigprocmask(SIG_SETMASK, &omask, NULL);

	/* no need of other inherited fds but stderr */
	close(fileno(stdin));
	close(fileno(stdout));

	err = 0;
	for (;;) {
		int status;
		int orphan = 0;
		pid_t waited_pid;

		switch (was_interrupted) {

		case 0:
			break;

		case SIGTERM:
			if (!shutdown) {
				shutdown = 1;
				kill(-1, SIGTERM);
				alarm(1);
			}
			break;

		case SIGALRM:
			kill(-1, SIGKILL);
			break;

		default:
			kill(pid, was_interrupted);
			break;
		}

		was_interrupted = 0;
		waited_pid = wait(&status);
		if (waited_pid < 0) {
			if (errno == ECHILD)
				goto out;
			if (errno == EINTR)
				continue;

			ERROR("failed to wait child : %s",
			      strerror(errno));
			goto out;
		}

		/* reset timer each time a process exited */
		if (shutdown)
			alarm(1);

		/*
		 * keep the exit code of started application
		 * (not wrapped pid) and continue to wait for
		 * the end of the orphan group.
		 */
		if ((waited_pid != pid) || (orphan ==1))
			continue;
		orphan = 1;
		err = lxc_error_set_and_log(waited_pid, status);
	}
out:
	return err;
}
