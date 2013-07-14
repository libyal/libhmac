dnl Functions for libhmac
dnl
dnl Version: 20120714

dnl Function to detect if libhmac dependencies are available
AC_DEFUN([AX_LIBHMAC_CHECK_LOCAL],
 [ac_cv_libhmac_md5=no
 ac_cv_libhmac_sha1=no
 ac_cv_libhmac_sha256=no
 ac_cv_libhmac_sha512=no

 dnl Check for Windows crypto API support
 AS_IF(
  [test "x$ac_cv_enable_winapi" = xyes],
  [AX_WINCRYPT_CHECK_LIB

  AS_IF(
   [test "x$ac_cv_wincrypt" != xno],
   [AX_WINCRYPT_CHECK_MD5
   AX_WINCRYPT_CHECK_SHA1
   AX_WINCRYPT_CHECK_SHA256
   AX_WINCRYPT_CHECK_SHA512

   ac_cv_libhmac_md5=$ac_cv_wincrypt_md5
   ac_cv_libhmac_sha1=$ac_cv_wincrypt_sha1
   ac_cv_libhmac_sha256=$ac_cv_wincrypt_sha256
   ac_cv_libhmac_sha512=$ac_cv_wincrypt_sha512
  ])
 ])

 dnl Check for libcrypto (openssl) support
 AS_IF(
  [test "x$ac_cv_libhmac_md5" = xno && test "x$ac_cv_libhmac_sha1" = xno && test "x$ac_cv_libhmac_sha256" = xno && test "x$ac_cv_libhmac_sha512" = xno],
  [AX_LIBCRYPTO_CHECK_ENABLE

  AS_IF(
   [test "x$ac_cv_libcrypto" != xno],
   [AX_LIBCRYPTO_CHECK_MD5
   AX_LIBCRYPTO_CHECK_SHA1
   AX_LIBCRYPTO_CHECK_SHA256
   AX_LIBCRYPTO_CHECK_SHA512

   ac_cv_libhmac_md5=$ac_cv_libcrypto_md5
   ac_cv_libhmac_sha1=$ac_cv_libcrypto_sha1
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
  [test "x$ac_cv_libhmac_sha256" = xno],
  [ac_cv_libhmac_sha256=local])

 AS_IF(
  [test "x$ac_cv_libhmac_sha512" = xno],
  [ac_cv_libhmac_sha512=local])
 ])

