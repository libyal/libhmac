dnl Functions for libhmac
dnl
dnl Version: 20161224

dnl Function to detect if libhmac dependencies are available
AC_DEFUN([AX_LIBHMAC_CHECK_LOCAL],
  [ac_cv_libhmac_md5=no
  ac_cv_libhmac_sha1=no
  ac_cv_libhmac_sha224=no
  ac_cv_libhmac_sha256=no
  ac_cv_libhmac_sha512=no

  dnl Check for Windows crypto API support
  AX_WINCRYPT_CHECK_LIB

  AS_IF(
    [test "x$ac_cv_wincrypt" != xno],
    [AX_WINCRYPT_CHECK_MD5
    AX_WINCRYPT_CHECK_SHA1
    AX_WINCRYPT_CHECK_SHA224
    AX_WINCRYPT_CHECK_SHA256
    AX_WINCRYPT_CHECK_SHA512

    ac_cv_libhmac_md5=$ac_cv_wincrypt_md5
    ac_cv_libhmac_sha1=$ac_cv_wincrypt_sha1
    ac_cv_libhmac_sha224=$ac_cv_wincrypt_sha224
    ac_cv_libhmac_sha256=$ac_cv_wincrypt_sha256
    ac_cv_libhmac_sha512=$ac_cv_wincrypt_sha512
  ])

  dnl Check for libcrypto (openssl) support
  AS_IF(
    [test "x$ac_cv_libhmac_md5" = xno && test "x$ac_cv_libhmac_sha1" = xno && test "x$ac_cv_libhmac_sha224" = xno && test "x$ac_cv_libhmac_sha256" = xno && test "x$ac_cv_libhmac_sha512" = xno],
    [AX_LIBCRYPTO_CHECK_ENABLE

    AS_IF(
      [test "x$ac_cv_libcrypto" != xno],
      [AX_LIBCRYPTO_CHECK_MD5
      AX_LIBCRYPTO_CHECK_SHA1
      AX_LIBCRYPTO_CHECK_SHA224
      AX_LIBCRYPTO_CHECK_SHA256
      AX_LIBCRYPTO_CHECK_SHA512

      ac_cv_libhmac_md5=$ac_cv_libcrypto_md5
      ac_cv_libhmac_sha1=$ac_cv_libcrypto_sha1
      ac_cv_libhmac_sha224=$ac_cv_libcrypto_sha224
      ac_cv_libhmac_sha256=$ac_cv_libcrypto_sha256
      ac_cv_libhmac_sha512=$ac_cv_libcrypto_sha512
    ])
  ])

  dnl Fallback to local versions if necessary
  AS_IF(
    [test "x$ac_cv_libhmac_md5" = xno],
    [ac_cv_libhmac_md5=local])

  AS_IF(
    [test "x$ac_cv_libhmac_sha1" = xno],
    [ac_cv_libhmac_sha1=local])

  AS_IF(
    [test "x$ac_cv_libhmac_sha224" = xno],
    [ac_cv_libhmac_sha224=local])

  AS_IF(
    [test "x$ac_cv_libhmac_sha256" = xno],
    [ac_cv_libhmac_sha256=local])

  AS_IF(
    [test "x$ac_cv_libhmac_sha512" = xno],
    [ac_cv_libhmac_sha512=local])

  dnl Check if DLL support is needed
  AS_IF(
    [test "x$enable_shared" = xyes],
    [AS_CASE(
      [$host],
      [*cygwin* | *mingw*],
      [AC_DEFINE(
        [HAVE_DLLMAIN],
        [1],
        [Define to 1 to enable the DllMain function.])
      AC_SUBST(
        [HAVE_DLLMAIN],
        [1])
    ])
  ])
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

  dnl Check if tools should be build as static executables
  AX_COMMON_CHECK_ENABLE_STATIC_EXECUTABLES

  dnl Check if DLL support is needed
  AS_IF(
    [test "x$enable_shared" = xyes && test "x$ac_cv_enable_static_executables" = xno],
    [AS_CASE(
      [$host],
      [*cygwin* | *mingw*],
      [AC_SUBST(
        [LIBHMAC_DLL_IMPORT],
        ["-DLIBHMAC_DLL_IMPORT"])
    ])
  ])
])

