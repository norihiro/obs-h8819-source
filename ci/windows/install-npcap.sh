#! /bin/bash

set -ex

curl -O https://npcap.com/dist/npcap-sdk-1.15.zip
sha256sum -c <<<'52c7b9fb4abee3ad9fe739bb545c3efe77b731c8e127122bdf328eafdae3ed4f npcap-sdk-1.15.zip'
7z x npcap-sdk-1.15.zip

function path_unix2win
{
	echo "$@" | sed -e 's;^/\([cd]\)/;\1:\\;' -e 's;/;\\;g'
}

: ${GITHUB_ENV:=/dev/stdout}
echo "NPCAP_INCLUDE_DIR=$(path_unix2win $PWD/Include)" >> $GITHUB_ENV
echo "NPCAP_LIBRARY_DIR=$(path_unix2win $PWD/Lib/x64)" >> $GITHUB_ENV
echo "NPCAP_LIBRARIES=wpcap.lib" >> $GITHUB_ENV
