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

#ifndef _confile_h
#define _confile_h

struct lxc_conf;
struct lxc_list;

extern int lxc_config_read(const char *file, const char *name, struct lxc_conf *conf);
extern int lxc_config_readline(char *buffer, struct lxc_conf *conf);

extern int lxc_config_define_add(struct lxc_list *defines, char* arg);
extern int lxc_config_define_load(struct lxc_list *defines,
				  struct lxc_conf *conf);

/* needed for lxc-attach */
extern signed long lxc_config_parse_arch(const char *arch);

#endif
