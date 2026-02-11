#! /bin/bash

set -ex

curl -O https://npcap.com/dist/npcap-sdk-1.16.zip
sha256sum -c <<<'f0a8be7778ee3ae1b99bbbecb27a3ff0f6c111a4093f1c78c5c5a099607184db npcap-sdk-1.16.zip'
7z x npcap-sdk-1.16.zip

function path_unix2win
{
	echo "$@" | sed -e 's;^/\([cd]\)/;\1:\\;' -e 's;/;\\;g'
}

: ${GITHUB_ENV:=/dev/stdout}
echo "NPCAP_INCLUDE_DIR=$(path_unix2win $PWD/Include)" >> $GITHUB_ENV
echo "NPCAP_LIBRARY_DIR=$(path_unix2win $PWD/Lib/x64)" >> $GITHUB_ENV
echo "NPCAP_LIBRARIES=wpcap.lib" >> $GITHUB_ENV
