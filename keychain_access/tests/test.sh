#!/bin/bash

export HACKME=hackme-swift
export OUTFILE=keychain_access_test.json

export SERVICE_NAME=org.owlink.findme
export SERVICE_SECRET=🦉

echo "Add dummy password under label ${SERVICE_NAME} ..."
security add-generic-password -a ${USER} -A -s ${SERVICE_NAME} -w ${SERVICE_SECRET}

echo "Start ${HACKME} program ..."
make
./${HACKME} &

echo "Extract secret(s) to ${OUTFILE} ..."
../keychain_access.py ${HACKME} -o ${OUTFILE}

echo -n "Compare with extracted secret ..."
./test_keychain_item.py -l ${SERVICE_NAME} -s ${SERVICE_SECRET} -f ${OUTFILE}
RESULT=$?
if [[ $RESULT -eq 0 ]]; then
	echo -e "\033[0;32m sucess!\033[0m"
else
	echo -e "\033[0;31m failure!\033[0m"
fi

echo "Clean up ..."
rm keychain_access_test.json
security delete-generic-password -a ${USER} -l ${SERVICE_NAME} > /dev/null

exit ${RESULT}
