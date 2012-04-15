#ifndef __execute_h
#define __execute_h

#ifdef __cplusplus
extern "C" {
#endif

struct lxc_execute_args {
	char *const *argv;
	int quiet;
};

#ifdef __cplusplus
}
#endif

#endif
