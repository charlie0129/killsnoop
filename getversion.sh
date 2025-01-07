#!/bin/bash

verdefault="$(git describe --tags --always --dirty 2>/dev/null || echo "UNKNOWN")"
ver="${VERSION:-$verdefault}"

source /etc/os-release

unamer="$(uname -r)"
majver="${unamer%%.*}"
minver="${unamer#*.}"
minver="${minver%%.*}"

echo $ver-$ID-$VERSION_ID-kernel-$majver.$minver
