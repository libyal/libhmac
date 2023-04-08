#!/bin/bash
# Sum tool testing script
#
# Version: 20230408

EXIT_SUCCESS=0;
EXIT_FAILURE=1;
EXIT_IGNORE=77;

OPTION_SETS="";

INPUT_GLOB="*";

test_callback()
{
	local TMPDIR=$1;
	local TEST_SET_DIRECTORY=$2;
	local TEST_OUTPUT=$3;
	local TEST_EXECUTABLE=$4;
	local TEST_INPUT=$5;
	shift 5;
	local ARGUMENTS=("$@");

	run_test_with_input_and_arguments "${TEST_EXECUTABLE}" "${INPUT_FILE}" -dsha1 > ${TMPDIR}/hmacsum;
	local RESULT=$?;

	DIGEST_HASH=`cat ${TMPDIR}/hmacsum | grep "SHA1" | sed 's/^[^:]*[:][\t][\t]*//'`;

	cp ${TMPDIR}/hmacsum /tmp/

	if test ${RESULT} -eq ${EXIT_SUCCESS};
	then
		if test "${PLATFORM}" = "Darwin";
		then
			VERIFICATION_DIGEST_HASH=`openssl sha1 ${INPUT_FILE} | sed 's/^[^=]*=//'`;
		else
			VERIFICATION_DIGEST_HASH=`sha1sum ${INPUT_FILE} | sed 's/[ ][ ]*[^ ][^ ]*$//'`;
		fi
		if test "${DIGEST_HASH}" != "${VERIFICATION_DIGEST_HASH}";
		then
			RESULT=${EXIT_FAILURE};
		fi
	fi

	echo "";

	echo -n "Testing hmacsum -d sha1 of input: ${INPUT_FILE} ";

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

TEST_EXECUTABLE="../hmactools/hmacsum";

if ! test -x "${TEST_EXECUTABLE}";
then
	TEST_EXECUTABLE="../hmactools/hmacsum.exe";
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
	assert_availability_binary openssl;
else
	assert_availability_binary sha1sum;
fi

if ! test -d "input";
then
	echo "Test input directory: input not found.";

	return ${EXIT_IGNORE};
fi
RESULT=`ls input/* | tr ' ' '\n' | wc -l`;

if test ${RESULT} -eq ${EXIT_SUCCESS};
then
	echo "No files or directories found in the test input directory: input";

	return ${EXIT_IGNORE};
fi

TEST_PROFILE_DIRECTORY=$(get_test_profile_directory "input" "hmacsum");

IGNORE_LIST=$(read_ignore_list "${TEST_PROFILE_DIRECTORY}");

RESULT=${EXIT_SUCCESS};

for TEST_SET_INPUT_DIRECTORY in input/*;
do
	if ! test -d "${TEST_SET_INPUT_DIRECTORY}";
	then
		continue;
	fi
	if check_for_directory_in_ignore_list "${TEST_SET_INPUT_DIRECTORY}" "${IGNORE_LIST}";
	then
		continue;
	fi

	TEST_SET_DIRECTORY=$(get_test_set_directory "${TEST_PROFILE_DIRECTORY}" "${TEST_SET_INPUT_DIRECTORY}");

	OLDIFS=${IFS};

	# IFS="\n"; is not supported by all platforms.
	IFS="
";

	if test -f "${TEST_SET_DIRECTORY}/files";
	then
		for INPUT_FILE in `cat ${TEST_SET_DIRECTORY}/files | sed "s?^?${TEST_SET_INPUT_DIRECTORY}/?"`;
		do
			run_test_on_input_file_with_options "${TEST_SET_DIRECTORY}" "hmacsum" "with_callback" "${OPTION_SETS}" "${TEST_EXECUTABLE}" "${INPUT_FILE}";
			RESULT=$?;

			if test ${RESULT} -ne ${EXIT_SUCCESS};
			then
				break;
			fi
		done
	else
		for INPUT_FILE in `ls -1 ${TEST_SET_INPUT_DIRECTORY}/${INPUT_GLOB}`;
		do
			run_test_on_input_file_with_options "${TEST_SET_DIRECTORY}" "hmacsum" "with_callback" "${OPTION_SETS}" "${TEST_EXECUTABLE}" "${INPUT_FILE}";
			RESULT=$?;

			if test ${RESULT} -ne ${EXIT_SUCCESS};
			then
				break;
			fi
		done
	fi
	IFS=${OLDIFS};

	if test ${RESULT} -ne ${EXIT_SUCCESS};
	then
		break;
	fi
done

exit ${RESULT};

