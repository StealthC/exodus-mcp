#!/usr/bin/env bash
# Compiles and runs the native unit tests that do not need the emulator.
#
# The per-access log format is produced by the pinned Exodus fork and consumed by
# the Go server, so its encoding rules are validated natively here with the host
# compiler: direction, width, boundary addresses, 64-bit sequence rendering,
# previous-value availability, and register snapshots. The tests link only the
# pure header, so they run anywhere and never start Exodus.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

cxx=${CXX:-g++}
if ! command -v "$cxx" >/dev/null 2>&1; then
	echo "native tests skipped: $cxx is not available"
	exit 0
fi

mkdir -p tmp
binary=tmp/native-memory-access-log-test
"$cxx" -std=c++14 -Wall -Wextra -Werror \
	-I vendor/exodus/ExodusSDK/Processor \
	-o "$binary" \
	native-plugin/tests/memory_access_log_test.cpp
"$binary"
