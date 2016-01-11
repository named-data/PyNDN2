# To build using autotools, see the Development section of the file INSTALL.

AC_PREREQ([2.59])
AC_INIT([ndn-cpp], [0.9], [ndn-lib@lists.cs.ucla.edu], [ndn-cpp], [https://github.com/named-data/ndn-cpp])
AM_INIT_AUTOMAKE([1.10 -Wall no-define foreign])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([configure.ac])
# Create config.h without prefixes.  Put it in the include directory so CFLAGS will have -I./include .
AC_CONFIG_HEADERS(include/config.h)
# Add prefixes and output to a unique file name which will go into the ndn-cpp include install directory.
AX_PREFIX_CONFIG_H(include/ndn-cpp/ndn-cpp-config.h)
AM_MAINTAINER_MODE
AM_PROG_AR
AC_PROG_LIBTOOL
LT_PREREQ([2.2])
LT_INIT()
AC_PROG_CXX
AM_PROG_CC_C_O
AC_PROG_OBJCXX
AC_LANG([C++])

# Special case.
case "$host" in
  *-darwin* | *-macos10*)
     if test -d /opt/local ; then
       CFLAGS="$CFLAGS -I/opt/local/include"
       CXXFLAGS="$CXXFLAGS -I/opt/local/include"
       CPPFLAGS="$CPPFLAGS -I/opt/local/include"
       LDFLAGS="$LDFLAGS -L/opt/local/lib"
     elif test -d /sw ; then
       CFLAGS="$CFLAGS -I/sw/include"
       CXXFLAGS="$CXXFLAGS -I/sw/include"
       CPPFLAGS="$CPPFLAGS -I/sw/include"
       LDFLAGS="$LDFLAGS -L/sw/lib"
     fi
  ;;
esac

AM_PATH_PYTHON(2.7.0)
PY_PREFIX=`$PYTHON -c 'import sys ; print sys.prefix'`
PYTHON_LIBS="-lpython$PYTHON_VERSION"
PYTHON_CFLAGS="-I$PY_PREFIX/include/python$PYTHON_VERSION"
PYTHON_CPPFLAGS="-I$PY_PREFIX/include/python$PYTHON_VERSION"
AC_SUBST([PYTHON_LIBS])
AC_SUBST([PYTHON_CFLAGS])
AC_SUBST([PYTHON_CPPFLAGS])

AX_PYTHON_DEVEL([>= 2.7])

AC_TYPE_SIZE_T
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_CHECK_FUNCS([memcmp] [memcpy] [memset])
AC_CHECK_FUNCS([strchr], :, AC_MSG_ERROR([*** strchr not found. Check 'config.log' for more details.]))
AC_CHECK_FUNCS([sscanf], :, AC_MSG_ERROR([*** sscanf not found. Check 'config.log' for more details.]))
AC_CHECK_HEADERS([time.h], :, AC_MSG_ERROR([*** time.h not found. Check 'config.log' for more details.]))
AC_CHECK_HEADERS([sys/time.h], :, AC_MSG_ERROR([*** sys/time.h not found. Check 'config.log' for more details.]))
AC_CHECK_FUNCS([gettimeofday], :, AC_MSG_ERROR([*** gettimeofday not found. processEvents requires it. Check 'config.log' for more details.]))
AC_CHECK_FUNCS([round])
AC_C_INLINE

AC_MSG_CHECKING([for gmtime support])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
    [[#include <time.h>]]
    [[#include <sys/time.h>]]
    [[struct timeval tv;]]
    [[int result1 = gettimeofday(&tv, 0);]]
    [[time_t time1 = time(0);]]
    [[struct tm* tm1 = gmtime(&time1);]]
    [[time_t time2 = timegm(tm1);]])
], [
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED([HAVE_GMTIME_SUPPORT], 1, [1 if have sys/time gmtime support including timegm.])
], [
    AC_MSG_RESULT([no])
    AC_DEFINE_UNQUOTED([HAVE_GMTIME_SUPPORT], 0, [1 if have sys/time gmtime support including timegm.])
])

# Require libcrypto.
AC_CHECK_LIB([crypto], [EVP_EncryptInit], [],
             [AC_MSG_FAILURE([can't find openssl crypto lib])])

AC_MSG_CHECKING([for __attribute__((deprecated))])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
    [[void func(int); __attribute__((deprecated))]])
], [
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED([HAVE_ATTRIBUTE_DEPRECATED], 1, [1 if have `__attribute__((deprecated))'.])
], [
    AC_MSG_RESULT([no])
    AC_DEFINE_UNQUOTED([HAVE_ATTRIBUTE_DEPRECATED], 0, [1 if have `__attribute__((deprecated))'.])
])

# htonll is supported on Windows 8 but not earlier Windows.
AC_MSG_CHECKING([for htonll])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
    [[#include <WinSock2.h>]]
    [[htonll(1);]])
], [
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED([HAVE_HTONLL], 1, [1 if have WinSock2 `htonll'.])
], [
    AC_MSG_RESULT([no])
    AC_DEFINE_UNQUOTED([HAVE_HTONLL], 0, [1 if have WinSock2 `htonll'.])
])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
