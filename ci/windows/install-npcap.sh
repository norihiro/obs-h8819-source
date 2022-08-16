#! /bin/bash

set -ex

curl -O https://npcap.com/dist/npcap-sdk-1.13.zip
sha256sum -c <<<'dad1f2bf1b02b787be08ca4862f99e39a876c1f274bac4ac0cedc9bbc58f94fd npcap-sdk-1.13.zip'
7z x npcap-sdk-1.13.zip

function path_unix2win
{
	echo "$@" | sed -e 's;^/\([cd]\)/;\1:\\;' -e 's;/;\\;g'
}

: ${GITHUB_ENV:=/dev/stdout}
echo "NPCAP_INCLUDE_DIR=$(path_unix2win $PWD/Include)" >> $GITHUB_ENV
echo "NPCAP_LIBRARY_DIR=$(path_unix2win $PWD/Lib/x64)" >> $GITHUB_ENV
echo "NPCAP_LIBRARIES=wpcap.lib" >> $GITHUB_ENV
