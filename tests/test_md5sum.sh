#!/usr/bin/env bash
# Sum tool testing script
#
# Version: 20240417

EXIT_SUCCESS=0;
EXIT_FAILURE=1;
EXIT_IGNORE=77;

PROFILES=("hmacsum");
OPTIONS_PER_PROFILE=("")
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

	run_test_with_input_and_arguments "${TEST_EXECUTABLE}" "${INPUT_FILE}" -dmd5 > ${TMPDIR}/hmacsum;
	local RESULT=$?;

	# Note that the $'' string notation is needed for Mac OS to correctly interpret the tabs.
	DIGEST_HASH=`cat ${TMPDIR}/hmacsum | grep "MD5" | sed $'s/^[^:]*[:][\t][\t]*//'`;

	if test ${RESULT} -eq ${EXIT_SUCCESS};
	then
		if test "${PLATFORM}" = "Darwin";
		then
			VERIFICATION_DIGEST_HASH=`md5 ${INPUT_FILE} | sed 's/^[^=]*= //'`;
		else
			VERIFICATION_DIGEST_HASH=`md5sum ${INPUT_FILE} | sed 's/[ ][ ]*[^ ][^ ]*$//'`;
		fi
		if test "${DIGEST_HASH}" != "${VERIFICATION_DIGEST_HASH}";
		then
			RESULT=${EXIT_FAILURE};
		fi
	fi

	echo "";

	echo -n "Testing hmacsum -d md5 of input: ${INPUT_FILE} ";

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

TEST_DIRECTORY=`dirname $0`;

TEST_RUNNER="${TEST_DIRECTORY}/test_runner.sh";

if ! test -f "${TEST_RUNNER}";
then
	echo "Missing test runner: ${TEST_RUNNER}";

	exit ${EXIT_FAILURE};
fi

PLATFORM=`uname -s`;

source ${TEST_RUNNER};

if test "${PLATFORM}" = "Darwin";
then
	assert_availability_binary md5;
else
	assert_availability_binary md5sum;
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

RESULT=${EXIT_SUCCESS};

for PROFILE_INDEX in ${!PROFILES[*]};
do
	TEST_PROFILE=${PROFILES[${PROFILE_INDEX}]};

	TEST_PROFILE_DIRECTORY=$(get_test_profile_directory "input" "${TEST_PROFILE}");

	IGNORE_LIST=$(read_ignore_list "${TEST_PROFILE_DIRECTORY}");

	IFS=" " read -a PROFILE_OPTIONS <<< ${OPTIONS_PER_PROFILE[${PROFILE_INDEX}]};

	RESULT=${EXIT_SUCCESS};

	for TEST_SET_INPUT_DIRECTORY in input/*;
	do
		if ! test -d "${TEST_SET_INPUT_DIRECTORY}";
		then
			continue;
		fi
		TEST_SET=`basename ${TEST_SET_INPUT_DIRECTORY}`;

		if check_for_test_set_in_ignore_list "${TEST_SET}" "${IGNORE_LIST}";
		then
			continue;
		fi
		TEST_SET_DIRECTORY=$(get_test_set_directory "${TEST_PROFILE_DIRECTORY}" "${TEST_SET_INPUT_DIRECTORY}");

		RESULT=${EXIT_SUCCESS};

		if test -f "${TEST_SET_DIRECTORY}/files";
		then
			IFS="" read -a INPUT_FILES <<< $(cat ${TEST_SET_DIRECTORY}/files | sed "s?^?${TEST_SET_INPUT_DIRECTORY}/?");
		else
			IFS="" read -a INPUT_FILES <<< $(ls -1d ${TEST_SET_INPUT_DIRECTORY}/${INPUT_GLOB});
		fi
		for INPUT_FILE in "${INPUT_FILES[@]}";
		do
			TESTED_WITH_OPTIONS=0;

			for OPTION_SET in ${OPTION_SETS[@]};
			do
				TEST_DATA_OPTION_FILE=$(get_test_data_option_file "${TEST_SET_DIRECTORY}" "${INPUT_FILE}" "${OPTION_SET}");

				if test -f ${TEST_DATA_OPTION_FILE};
				then
					TESTED_WITH_OPTIONS=1;

					IFS=" " read -a OPTIONS <<< $(read_test_data_option_file "${TEST_SET_DIRECTORY}" "${INPUT_FILE}" "${OPTION_SET}");

					run_test_on_input_file "${TEST_SET_DIRECTORY}" "hmacsum" "with_callback" "${OPTION_SET}" "${TEST_EXECUTABLE}" "${INPUT_FILE}" "${PROFILE_OPTIONS[@]}" "${OPTIONS[@]}";
					RESULT=$?;

					if test ${RESULT} -ne ${EXIT_SUCCESS};
					then
						break;
					fi
				fi
			done

			if test ${TESTED_WITH_OPTIONS} -eq 0;
			then
				run_test_on_input_file "${TEST_SET_DIRECTORY}" "hmacsum" "with_callback" "" "${TEST_EXECUTABLE}" "${INPUT_FILE}" "${PROFILE_OPTIONS[@]}";
				RESULT=$?;
			fi

			if test ${RESULT} -ne ${EXIT_SUCCESS};
			then
				break;
			fi
		done

		# Ignore failures due to corrupted data.
		if test "${TEST_SET}" = "corrupted";
		then
			RESULT=${EXIT_SUCCESS};
		fi
		if test ${RESULT} -ne ${EXIT_SUCCESS};
		then
			break;
		fi
	done
done

exit ${RESULT};

