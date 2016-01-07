#!/bin/bash
#
# hmacsum -d sha224 testing script
#
# Copyright (C) 2011-2016, Joachim Metz <joachim.metz@gmail.com>
#
# Refer to AUTHORS for acknowledgements.
#
# This software is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.
#

EXIT_SUCCESS=0;
EXIT_FAILURE=1;
EXIT_IGNORE=77;

INPUT="input";
TMP="tmp";

GREP="grep";
LS="ls";
SED="sed";
SHA224SUM="sha224sum";
TR="tr";
WC="wc";

test_sha224sum()
{ 
	INPUT_FILE=$1;

	rm -rf tmp;
	mkdir tmp;

	SUM=`${TEST_RUNNER} ${HMACSUM} -d sha224 ${INPUT_FILE} | ${GREP} "SHA224" | ${SED} 's/^[^:]*[:][\t][\t]*//'`;

	RESULT=$?;

	rm -rf tmp;

	if test ${RESULT} -eq ${EXIT_SUCCESS};
	then
		SUM_CHECK=`${SHA224SUM} ${INPUT_FILE} | ${SED} 's/[ ][ ]*[^ ][^ ]*$//'`;

		if test ${SUM} != ${SUM_CHECK};
		then
			RESULT=${EXIT_FAILURE};
		fi
	fi

	echo "";

	echo -n "Testing hmacsum -d sha224 of input: ${INPUT_FILE} ";

	if test ${RESULT} -ne ${EXIT_SUCCESS};
	then
		echo " (FAIL)";
	else
		echo " (PASS)";
	fi
	return ${RESULT};
}

HMACSUM="../hmactools/hmacsum";

if ! test -x ${HMACSUM};
then
	HMACSUM="../hmactools/hmacsum.exe";
fi

if ! test -x ${HMACSUM};
then
	echo "Missing executable: ${HMACSUM}";

	exit ${EXIT_FAILURE};
fi

TEST_RUNNER="tests/test_runner.sh";

if ! test -x ${TEST_RUNNER};
then
	TEST_RUNNER="./test_runner.sh";
fi

if ! test -x ${TEST_RUNNER};
then
	echo "Missing test runner: ${TEST_RUNNER}";

	exit ${EXIT_FAILURE};
fi

if ! test -d ${INPUT};
then
	echo "No ${INPUT} directory found, to test hmacsum create ${INPUT} directory and place test files in directory.";

	exit ${EXIT_IGNORE};
fi

EXIT_RESULT=${EXIT_IGNORE};

if test -d ${INPUT};
then
	RESULT=`${LS} ${INPUT}/* | ${TR} ' ' '\n' | ${WC} -l`;

	if test ${RESULT} -eq 0;
	then
		echo "No files found in ${INPUT} directory, to test hmacsum place test files in directory.";
	else
		for FILENAME in `${LS} ${INPUT}/* | ${TR} ' ' '\n'`;
		do
			if ! test_sha224sum "${FILENAME}";
			then
				exit ${EXIT_FAILURE};
			fi
		done

		EXIT_RESULT=${EXIT_SUCCESS};
	fi
fi

exit ${EXIT_RESULT};

