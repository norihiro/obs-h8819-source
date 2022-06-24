#! /bin/bash

if test -n "$1"; then
	repo="$1"
else
	repo=$(basename $(pwd))
fi

mkdir -p crowdin-work
mkdir -p crowdin-work/${repo}
pushd crowdin-work/${repo}
ln -fs ../../data/locale/en-US.ini main.ini
ln -fs ../../README.md ./
popd
sed -e "s;%repository.name%;${repo};g" < .github/files/crowdin-template.yml > crowdin.yml
