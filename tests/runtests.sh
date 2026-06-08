#!/bin/sh
# Script to run tests
#
# Version: 20260602

if test -f ${PWD}/libhmac/.libs/libhmac.1.dylib && test -f ./pyhmac/.libs/pyhmac.so
then
	install_name_tool -change /usr/local/lib/libhmac.1.dylib ${PWD}/libhmac/.libs/libhmac.1.dylib ./pyhmac/.libs/pyhmac.so
fi

make check $@
RESULT=$?

if test ${RESULT} -ne 0 && test -f tests/test-suite.log
then
	cat tests/test-suite.log
fi
exit ${RESULT}

