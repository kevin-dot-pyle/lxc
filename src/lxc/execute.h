#ifndef __execute_h
#define __execute_h

#ifdef __cplusplus
extern "C" {
#endif

struct lxc_execute_args {
	const char *exec;
	const char *uid;
	const char *gid;
	const char *gidlist;
	char *const *argv;
	const char *pivot;
	int quiet;
};

#ifdef __cplusplus
}
#endif

#endif
