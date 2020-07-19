dnl Checks for required headers and functions
dnl
dnl Version: 20200104

dnl Function to detect if libhmac dependencies are available
AC_DEFUN([AX_LIBHMAC_CHECK_LOCAL],
  [dnl Check for libcrypto (openssl) support
  AX_LIBCRYPTO_CHECK_ENABLE

  AS_IF(
    [test "x$ac_cv_libcrypto" != xno],
    [AX_LIBCRYPTO_CHECK_MD5
    AX_LIBCRYPTO_CHECK_SHA1
    AX_LIBCRYPTO_CHECK_SHA224
    AX_LIBCRYPTO_CHECK_SHA256
    AX_LIBCRYPTO_CHECK_SHA512])

  dnl Fallback to local versions if necessary
  AS_IF(
    [test "x$ac_cv_libcrypto" = xno || test "x$ac_cv_libcrypto_md5" = xno],
    [ac_cv_libhmac_md5=local],
    [ac_cv_libhmac_md5=$ac_cv_libcrypto_md5])

  AS_IF(
    [test "x$ac_cv_libcrypto" = xno || test "x$ac_cv_libcrypto_sha1" = xno],
    [ac_cv_libhmac_sha1=local],
    [ac_cv_libhmac_sha1=$ac_cv_libcrypto_sha1])

  AS_IF(
    [test "x$ac_cv_libcrypto" = xno || test "x$ac_cv_libcrypto_sha224" = xno],
    [ac_cv_libhmac_sha224=local],
    [ac_cv_libhmac_sha224=$ac_cv_libcrypto_sha224])

  AS_IF(
    [test "x$ac_cv_libcrypto" = xno || test "x$ac_cv_libcrypto_sha256" = xno],
    [ac_cv_libhmac_sha256=local],
    [ac_cv_libhmac_sha256=$ac_cv_libcrypto_sha256])

  AS_IF(
    [test "x$ac_cv_libcrypto" = xno || test "x$ac_cv_libcrypto_sha512" = xno],
    [ac_cv_libhmac_sha512=local],
    [ac_cv_libhmac_sha512=$ac_cv_libcrypto_sha512])
  ])

dnl Function to detect if hmactools dependencies are available
AC_DEFUN([AX_HMACTOOLS_CHECK_LOCAL],
  [AC_CHECK_HEADERS([signal.h sys/signal.h unistd.h])

  AC_CHECK_FUNCS([close getopt setvbuf])

  AS_IF(
   [test "x$ac_cv_func_close" != xyes],
   [AC_MSG_FAILURE(
     [Missing function: close],
     [1])
  ])
])

dnl Function to check if DLL support is needed
AC_DEFUN([AX_LIBHMAC_CHECK_DLL_SUPPORT],
  [AS_IF(
    [test "x$enable_shared" = xyes && test "x$ac_cv_enable_static_executables" = xno],
    [AS_CASE(
      [$host],
      [*cygwin* | *mingw* | *msys*],
      [AC_DEFINE(
        [HAVE_DLLMAIN],
        [1],
        [Define to 1 to enable the DllMain function.])
      AC_SUBST(
        [HAVE_DLLMAIN],
        [1])

      AC_SUBST(
        [LIBHMAC_DLL_EXPORT],
        ["-DLIBHMAC_DLL_EXPORT"])

      AC_SUBST(
        [LIBHMAC_DLL_IMPORT],
        ["-DLIBHMAC_DLL_IMPORT"])
      ])
    ])
  ])

