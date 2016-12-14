#!/bin/sh
# LICENSE: BSD 2-Clause License, see LICENSE.md
#
# Creates a build of an add-on release.
#

# variables
CHANNEL='productive'
VERSION='0.1'

# parameter parsing
for ARG in "$@"
do
	[ "$ARG" = "-d" ] || [ "$ARG" = "--dev" ] || [ "$ARG" = "--development" ] && CHANNEL='development'
done

# make dir if necessary
mkdir -p ./build

# compress 
7z a "./build/privatebin_$CHANNEL\_$VERSION.xpi" *.js *.json
