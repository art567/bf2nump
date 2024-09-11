#!/bin/sh

MACH="ia-32"
BASEDIR=$(dirname $0)

# Make dirs
if ! [ -d $BASEDIR/bin ]
then
    mkdir $BASEDIR/bin
fi

if ! [ -d $BASEDIR/bin/$MACH ]
then
    mkdir $BASEDIR/bin/$MACH
fi

# Build
gcc $BASEDIR/loader.c -m32 -o $BASEDIR/bin/$MACH/loader

chmod +x $BASEDIR/bin/$MACH/loader


echo "DONE"