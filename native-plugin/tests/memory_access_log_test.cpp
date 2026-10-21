// Native unit tests for the engine's memory access log format.
//
// The producer side of per-access capture lives in the pinned Exodus fork
// (ExodusSDK/Processor/MemoryAccessLog.h and Processor.cpp). This test compiles
// that header standalone with the host compiler and validates the encoding
// rules the MCP server parses: direction, width, boundary addresses, monotonic
// sequence rendering, previous-value availability, and register snapshots.
//
// It intentionally does not link the emulator: it proves the contract, not the
// CPU cores. The access-path integration itself is validated by building the
// fork and by live smoke runs (see docs/TRACE-SESSIONS.md).
//
// Build and run: bash scripts/native-test.sh

#include "MemoryAccessLog.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

int failures = 0;

void Check(bool condition, const char* message)
{
	if (!condition)
	{
		std::printf("FAIL: %s\n", message);
		++failures;
	}
}

void CheckEquals(const std::string& actual, const std::string& expected, const char* message)
{
	if (actual != expected)
	{
		std::printf("FAIL: %s\n  expected: %s\n  actual:   %s\n", message, expected.c_str(), actual.c_str());
		++failures;
	}
}

std::vector<std::string> SplitTabs(const std::string& line)
{
	std::vector<std::string> fields;
	std::string current;
	for (size_t index = 0; index < line.size(); ++index)
	{
		if (line[index] == '\t')
		{
			fields.push_back(current);
			current.clear();
			continue;
		}
		current.push_back(line[index]);
	}
	fields.push_back(current);
	return fields;
}

MemoryAccessLogRecord MakeRecord()
{
	MemoryAccessLogRecord record = {};
	record.sequence = 7;
	record.cycle = 1234;
	record.location = 0xFF0000;
	record.data = 0x42;
	record.pc = 0xFF0100;
	record.widthBits = 8;
	return record;
}

void TestReadRecord()
{
	MemoryAccessLogRecord record = MakeRecord();
	std::string line;
	FormatMemoryAccessLogLine(record, line);
	const std::vector<std::string> fields = SplitTabs(line);
	Check(fields.size() == 9, "a record has nine tab-separated fields");
	CheckEquals(fields[0], "7", "sequence is unsigned decimal");
	CheckEquals(fields[1], "1234", "cycle is unsigned decimal");
	CheckEquals(fields[2], "R", "a non-write record is a read");
	CheckEquals(fields[3], "ff0000", "location is lowercase hex without a prefix");
	CheckEquals(fields[4], "42", "value is lowercase hex without a prefix");
	CheckEquals(fields[5], "-", "an uncaptured previous value is a dash");
	CheckEquals(fields[6], "8", "width is decimal bits");
	CheckEquals(fields[7], "ff0100", "pc is lowercase hex");
	CheckEquals(fields[8], "-", "a record without registers renders a dash");
}

void TestWriteRecordWithPreviousAndRegisters()
{
	MemoryAccessLogRecord record = MakeRecord();
	record.flags = MemoryAccessFlagWrite | MemoryAccessFlagPreviousValid | MemoryAccessFlagRegisters;
	record.previous = 0xBE;
	record.registerCount = 18;
	for (unsigned int index = 0; index < record.registerCount; ++index)
	{
		record.registers[index] = 0x100 + index;
	}
	std::string line;
	FormatMemoryAccessLogLine(record, line);
	const std::vector<std::string> fields = SplitTabs(line);
	CheckEquals(fields[2], "W", "a write record renders W");
	CheckEquals(fields[5], "be", "a captured previous value renders hex");
	CheckEquals(fields[8].substr(0, 7), "100,101", "registers are comma separated hex");

	// A zero previous value is real data, not "unavailable".
	record.previous = 0;
	FormatMemoryAccessLogLine(record, line);
	CheckEquals(SplitTabs(line)[5], "0", "a zero previous value is rendered, not omitted");
}

void TestWidthEncoding()
{
	const unsigned int widths[] = {8, 16, 32};
	const char* expected[] = {"8", "16", "32"};
	for (int index = 0; index < 3; ++index)
	{
		MemoryAccessLogRecord record = MakeRecord();
		record.widthBits = widths[index];
		std::string line;
		FormatMemoryAccessLogLine(record, line);
		CheckEquals(SplitTabs(line)[6], expected[index], "width bits render as decimal bits");
	}
}

void TestBoundaryAddresses()
{
	// The Mega Drive M68K bus is 24-bit: the top address must round-trip and a
	// full 32-bit location must not be truncated by the formatter.
	const unsigned int addresses[] = {0x0, 0x1, 0xFFFFFF, 0x1000000, 0xFFFFFFFF};
	const char* expected[] = {"0", "1", "ffffff", "1000000", "ffffffff"};
	for (int index = 0; index < 5; ++index)
	{
		MemoryAccessLogRecord record = MakeRecord();
		record.location = addresses[index];
		record.pc = addresses[index];
		std::string line;
		FormatMemoryAccessLogLine(record, line);
		const std::vector<std::string> fields = SplitTabs(line);
		CheckEquals(fields[3], expected[index], "boundary location renders exactly");
		CheckEquals(fields[7], expected[index], "boundary pc renders exactly");
	}
}

void TestAccessRangeOverlap()
{
	// GotFlag is at odd address 0xFFFB49. A word write beginning at 0xFFFB48
	// touches that byte and must be retained by a one-byte monitored range.
	Check(MemoryAccessRangeOverlapsAccess(0xFFFB49, 0xFFFB49, 0xFFFB48, 16),
		"a word access starting before the watched byte overlaps it");
	Check(MemoryAccessRangeOverlapsAccess(0xFFFB48, 0xFFFB48, 0xFFFB48, 16),
		"a word access overlaps its first byte");
	Check(!MemoryAccessRangeOverlapsAccess(0xFFFB4A, 0xFFFB4A, 0xFFFB48, 16),
		"a word access does not overlap the following byte");
	Check(!MemoryAccessRangeOverlapsAccess(0xFFFB49, 0xFFFB49, 0xFFFB48, 8),
		"a byte access at the preceding address does not overlap the watched byte");
}

void TestLargeValues()
{
	MemoryAccessLogRecord record = MakeRecord();
	record.sequence = 18446744073709551615ULL;
	record.cycle = 18446744073709551615ULL;
	record.data = 0xDEADBEEF;
	std::string line;
	FormatMemoryAccessLogLine(record, line);
	const std::vector<std::string> fields = SplitTabs(line);
	CheckEquals(fields[0], "18446744073709551615", "a full 64-bit sequence renders exactly");
	CheckEquals(fields[1], "18446744073709551615", "a full 64-bit cycle renders exactly");
	CheckEquals(fields[4], "deadbeef", "a 32-bit value renders exactly");
}

void TestRegisterCap()
{
	MemoryAccessLogRecord record = MakeRecord();
	record.flags = MemoryAccessFlagRegisters;
	record.registerCount = MemoryAccessMaxRegisters + 4;
	for (unsigned int index = 0; index < MemoryAccessMaxRegisters; ++index)
	{
		record.registers[index] = index + 1;
	}
	std::string line;
	FormatMemoryAccessLogLine(record, line);
	const std::vector<std::string> fields = SplitTabs(line);
	unsigned int separators = 0;
	for (size_t index = 0; index < fields[8].size(); ++index)
	{
		if (fields[8][index] == ',')
		{
			++separators;
		}
	}
	Check(separators + 1 == MemoryAccessMaxRegisters, "a register snapshot is capped at the documented maximum");
}

} // namespace

int main()
{
	TestReadRecord();
	TestWriteRecordWithPreviousAndRegisters();
	TestWidthEncoding();
	TestBoundaryAddresses();
	TestAccessRangeOverlap();
	TestLargeValues();
	TestRegisterCap();
	if (failures != 0)
	{
		std::printf("%d native access-log test(s) failed\n", failures);
		return 1;
	}
	std::printf("native access-log tests passed\n");
	return 0;
}
