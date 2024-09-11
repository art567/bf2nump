#!/bin/sh

MACH=""
# 64-bit FreeBSD is "amd64" => emulates 32-bit Linux.
case `uname -m` in
    i[3456]86 | amd64) MACH="ia-32"
    ;;
    x86_64) MACH="amd-64"
    ;;
esac

# force 32 bit
# MACH="ia-32"

# force 64 bit
# MACH="amd-64"

if ! [ -d pb ]
then
    ln -s pb_$MACH pb
fi

BINARY_DIR="$(pwd)/bin"
if [ -d "$BINARY_DIR/$MACH" ]
then
    BINARY_DIR="$BINARY_DIR/$MACH"
fi

# Make the OS give us .core-dumps if the server crashes
ulimit -c unlimited

export LD_LIBRARY_PATH=$BINARY_DIR

echo "--- Started: $(date) ---" >> error.log
exec "$BINARY_DIR/loader" "$BINARY_DIR/bf2" "$@" 2>>error.log