#!/usr/bin/env bash
# Local quality gates mirroring CI: format check, vet, race-enabled tests,
# and Windows cross-compilation gates. Run from WSL or any Linux shell.
#
# Usage:
#   ./scripts/test.sh                 run all Linux-side gates
#   ./scripts/test.sh --windows-live  additionally build the bridge test
#                                     binary for Windows and execute it
#                                     through WSL interop (real named pipes)
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

unformatted=$(gofmt -l cmd internal)
if [ -n "$unformatted" ]; then
	echo "gofmt required on:"
	echo "$unformatted"
	exit 1
fi

race_flag=""
if [ "${EXODUS_MCP_TEST_RACE:-1}" = "1" ]; then
	race_flag="-race"
fi

go vet ./...
go test $race_flag ./...

echo "-- GOOS=windows gates --"
GOOS=windows GOARCH=amd64 go build ./...
GOOS=windows GOARCH=amd64 go vet ./...

if [ "${1:-}" = "--windows-live" ]; then
	echo "-- Windows live bridge tests (WSL interop) --"
	mkdir -p bin
	test_binary="bin/exodus-mcp.bridge.test.exe"
	GOOS=windows GOARCH=amd64 go test -c -o "$test_binary" ./internal/bridge/
	set +e
	"$test_binary" ${RUNV:-} -test.v "${@:2}"
	status=$?
	set -e
	rm -f "$test_binary"
	if [ "$status" -ne 0 ]; then
		echo "Windows live tests failed."
		exit "$status"
	fi
fi

echo "All gates passed."
