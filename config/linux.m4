AC_DEFUN([AC_LINUX],
[
	AC_LINUX_DIR()
	AC_LINUX_SRCARCH()
])

AC_DEFUN([AC_LINUX_DIR],
[
	AC_ARG_WITH([linuxdir],
		[AC_HELP_STRING([--with-linuxdir=DIR],
			[specify path to Linux source directory])],
		[LINUX_DIR="${withval}"],
		[LINUX_DIR=default])

	AC_SUBST(LINUX_DIR)
])

AC_DEFUN([AC_LINUX_SRCARCH],[
	AC_MSG_CHECKING(for linux SRCARCH)

	case "${host}" in
	i[[3456]]86-*) LINUX_SRCARCH=x86;;
	x86_64-*) LINUX_SRCARCH=x86;;
	powerpc*-*) LINUX_SRCARCH=powerpc;;
	s390*-*) LINUX_SRCARCH=s390;;
	arm*-*) LINUX_SRCARCH=arm;;
	mips*-*) LINUX_SRCARCH=mips;;
	sparc*-*) LINUX_SRCARCH=sparc;;
	*) AC_MSG_ERROR([architecture ${host} not supported]);;
	esac

	AC_MSG_RESULT(${LINUX_SRCARCH})
	AC_SUBST(LINUX_SRCARCH)
])
