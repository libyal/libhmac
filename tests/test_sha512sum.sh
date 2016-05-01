#!/bin/bash
# Sum tool testing script
#
# Version: 20160411

EXIT_SUCCESS=0;
EXIT_FAILURE=1;
EXIT_IGNORE=77;

TEST_PREFIX=`dirname ${PWD}`;
TEST_PREFIX=`basename ${TEST_PREFIX} | sed 's/^lib\([^-]*\).*$/\1/'`;
TEST_SUFFIX="sum";

TEST_PROFILE="${TEST_PREFIX}${TEST_SUFFIX}";
TEST_DESCRIPTION="${TEST_PREFIX}${TEST_SUFFIX}";
OPTION_SETS="";

TEST_TOOL_DIRECTORY="../${TEST_PREFIX}tools";
TEST_TOOL="${TEST_PREFIX}${TEST_SUFFIX}";
INPUT_DIRECTORY="input";
INPUT_GLOB="*";

test_callback()
{
	local TMPDIR=$1;
	local TEST_SET_DIRECTORY=$2;
	local TEST_OUTPUT=$3;
	local TEST_EXECUTABLE=$4;
	local TEST_INPUT=$5;
	shift 5;
	local ARGUMENTS=$@;

	run_test_with_input_and_arguments "${TEST_EXECUTABLE}" -d sha512 ${INPUT_FILE} | ${GREP} "SHA512" | ${SED} 's/^[^:]*[:][\t][\t]*//' > ${TMPDIR}/sha512;
	local RESULT=$?;

	DIGEST_HASH=`cat ${TMPDIR}/sha512`;

	if test ${RESULT} -eq ${EXIT_SUCCESS};
	then
		if test "${PLATFORM}" = "Darwin";
		then
			VERIFICATION_DIGEST_HASH=`sha512 ${INPUT_FILE} | ${SED} 's/[ ][ ]*[^ ][^ ]*$//'`;
		else
			VERIFICATION_DIGEST_HASH=`sha512sum ${INPUT_FILE} | ${SED} 's/[ ][ ]*[^ ][^ ]*$//'`;
		fi
		if test ${DIGEST_HASH} != ${VERIFICATION_DIGEST_HASH};
		then
			RESULT=${EXIT_FAILURE};
		fi
	fi

	echo "";

	echo -n "Testing ${TEST_PROFILE} -d sha512 of input: ${INPUT_FILE} ";

	if test ${RESULT} -ne ${EXIT_SUCCESS};
	then
		echo " (FAIL)";
	else
		echo " (PASS)";
	fi
	return ${RESULT};
}

if ! test -z ${SKIP_TOOLS_TESTS};
then
	exit ${EXIT_IGNORE};
fi

TEST_EXECUTABLE="${TEST_TOOL_DIRECTORY}/${TEST_TOOL}";

if ! test -x "${TEST_EXECUTABLE}";
then
	TEST_EXECUTABLE="${TEST_TOOL_DIRECTORY}/${TEST_TOOL}.exe";
fi

if ! test -x "${TEST_EXECUTABLE}";
then
	echo "Missing test executable: ${TEST_EXECUTABLE}";

	exit ${EXIT_FAILURE};
fi

TEST_RUNNER="tests/test_runner.sh";

if ! test -f "${TEST_RUNNER}";
then
	TEST_RUNNER="./test_runner.sh";
fi

if ! test -f "${TEST_RUNNER}";
then
	echo "Missing test runner: ${TEST_RUNNER}";

	exit ${EXIT_FAILURE};
fi

PLATFORM=`uname -s`;

source ${TEST_RUNNER};

if test "${PLATFORM}" = "Darwin";
then
	assert_availability_binary sha512;
else
	assert_availability_binary sha512sum;
fi

run_test_on_input_directory "${TEST_PROFILE}" "${TEST_DESCRIPTION}" "with_callback" "${OPTION_SETS}" "${TEST_EXECUTABLE}" "${INPUT_DIRECTORY}" "${INPUT_GLOB}";
RESULT=$?;

exit ${RESULT};

