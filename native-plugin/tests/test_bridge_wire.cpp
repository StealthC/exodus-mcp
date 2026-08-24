// Standalone unit tests for the pure bridge-wire helpers. Built and run by
// scripts/internal/test-native.bat without any Exodus SDK dependency.

#include "../BridgeWire.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int failures = 0;

#define CHECK(condition) \
	do \
	{ \
		if (!(condition)) \
		{ \
			++failures; \
			std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
		} \
	} while (0)

#define CHECK_EQUAL(expected, actual) \
	do \
	{ \
		const std::string expectedValue = (expected); \
		const std::string actualValue = (actual); \
		if (expectedValue != actualValue) \
		{ \
			++failures; \
			std::printf("FAIL %s:%d: expected %s, got %s\n", __FILE__, __LINE__, expectedValue.c_str(), actualValue.c_str()); \
		} \
	} while (0)

static void TestParseRequestValid()
{
	mcpwire::WireRequest request;
	bool authorized = false;
	const bool parsed = mcpwire::ParseRequestBody(
		"capability=cap-1\nid=req-9\nmethod=mem_read\naddress=4096\nlength=16\nspace=m68k-ram\n\n",
		"cap-1",
		request,
		authorized);
	CHECK(parsed);
	CHECK(authorized);
	CHECK(request.id == "req-9");
	CHECK(request.method == "mem_read");
	CHECK(request.params.size() == 3);
	CHECK(request.params["address"] == "4096");
	CHECK(request.params["length"] == "16");
	CHECK(request.params["space"] == "m68k-ram");
}

static void TestParseRequestToleratesCRLFAndFinalBlank()
{
	mcpwire::WireRequest request;
	bool authorized = false;
	const bool parsed = mcpwire::ParseRequestBody("capability=c\r\nmethod=status\r\n\r\nextra-after-blank", "c", request, authorized);
	CHECK(parsed);
	CHECK(authorized);
	CHECK(request.method == "status");
}

static void TestParseRequestRejectsWrongCapability()
{
	mcpwire::WireRequest request;
	bool authorized = true;
	const bool parsed = mcpwire::ParseRequestBody("capability=wrong\nmethod=status\n\n", "right", request, authorized);
	CHECK(!parsed);
	CHECK(!authorized);
}

static void TestParseRequestMalformedLineFailsAuthorized()
{
	mcpwire::WireRequest request;
	bool authorized = false;
	const bool parsed = mcpwire::ParseRequestBody("capability=c\nthis-line-has-no-equals\n\n", "c", request, authorized);
	CHECK(!parsed);
	CHECK(authorized);
}

static void TestParseRequestMissingMethodFails()
{
	mcpwire::WireRequest request;
	bool authorized = false;
	CHECK(!mcpwire::ParseRequestBody("capability=c\nid=req-1\n\n", "c", request, authorized));
	CHECK(authorized);
}

static void TestAppendJsonStringEscaping()
{
	std::string out;
	mcpwire::AppendJsonString(out, std::string("a\"b\\c\nd\te") + '\x01' + "\xc3\xa9");
	CHECK_EQUAL(std::string("\"a\\\"b\\\\c\\nd\\te\\u0001\xc3\xa9\""), out);
}

static void TestBase64EncodeRfc4648Vectors()
{
	CHECK_EQUAL(std::string(""), mcpwire::Base64Encode((const unsigned char*)"", 0));
	CHECK_EQUAL(std::string("Zg=="), mcpwire::Base64Encode((const unsigned char*)"f", 1));
	CHECK_EQUAL(std::string("Zm8="), mcpwire::Base64Encode((const unsigned char*)"fo", 2));
	CHECK_EQUAL(std::string("Zm9v"), mcpwire::Base64Encode((const unsigned char*)"foo", 3));
	CHECK_EQUAL(std::string("Zm9vYg=="), mcpwire::Base64Encode((const unsigned char*)"foob", 4));
	CHECK_EQUAL(std::string("Zm9vYmE="), mcpwire::Base64Encode((const unsigned char*)"fooba", 5));
	CHECK_EQUAL(std::string("Zm9vYmFy"), mcpwire::Base64Encode((const unsigned char*)"foobar", 6));
}

static void TestBase64DecodeRfc4648Vectors()
{
	std::vector<unsigned char> output;
	CHECK(mcpwire::Base64Decode("", output) && output.empty());
	CHECK(mcpwire::Base64Decode("Zg==", output) && output.size() == 1 && output[0] == 'f');
	CHECK(mcpwire::Base64Decode("Zm8=", output) && output.size() == 2 && output[0] == 'f' && output[1] == 'o');
	CHECK(mcpwire::Base64Decode("Zm9v", output) && output.size() == 3 && output[0] == 'f' && output[1] == 'o' && output[2] == 'o');
	CHECK(mcpwire::Base64Decode("Zm9vYmFy", output) && output.size() == 6 && output[5] == 'r');
}

static void TestBase64DecodeRejectsBadInput()
{
	std::vector<unsigned char> output;
	CHECK(!mcpwire::Base64Decode("a", output));
	CHECK(!mcpwire::Base64Decode("abc", output));
	CHECK(!mcpwire::Base64Decode("====", output));
	CHECK(!mcpwire::Base64Decode("Zm9v!", output));
	CHECK(!mcpwire::Base64Decode("Zg=", output));
	CHECK(!mcpwire::Base64Decode("Zm9v=====", output));
}

static void TestSanitizeIdentifier()
{
	CHECK_EQUAL(std::string("kid-chameleon"), mcpwire::SanitizeIdentifier(L"Kid Chameleon!"));
	CHECK_EQUAL(std::string("m68k"), mcpwire::SanitizeIdentifier(L"M68K"));
	CHECK_EQUAL(std::string("dev"), mcpwire::SanitizeIdentifier(L"---"));
	CHECK_EQUAL(std::string("dev"), mcpwire::SanitizeIdentifier(L""));
	CHECK_EQUAL(std::string("a1-b2"), mcpwire::SanitizeIdentifier(L"a1 B2"));
}

static void TestParseUnsignedAcceptsDecimalAndHex()
{
	unsigned long long value = 0;
	CHECK(mcpwire::ParseUnsigned("4096", value) && value == 4096ull);
	CHECK(mcpwire::ParseUnsigned("0xFF", value) && value == 255ull);
	CHECK(mcpwire::ParseUnsigned("0X10", value) && value == 16ull);
	CHECK(mcpwire::ParseUnsigned("0", value) && value == 0ull);
}

static void TestParseUnsignedRejectsBadInput()
{
	unsigned long long value = 12345;
	CHECK(!mcpwire::ParseUnsigned("", value));
	CHECK(!mcpwire::ParseUnsigned("-1", value));
	CHECK(!mcpwire::ParseUnsigned("+1", value));
	CHECK(!mcpwire::ParseUnsigned("12a", value));
	CHECK(!mcpwire::ParseUnsigned("0x", value));
	CHECK(value == 0); // rejected calls zero the output
}

static void TestMakeFrameHeader()
{
	CHECK_EQUAL(std::string("00000000"), mcpwire::MakeFrameHeader(0));
	CHECK_EQUAL(std::string("000000FF"), mcpwire::MakeFrameHeader(255));
	CHECK_EQUAL(std::string("FFFFFFFF"), mcpwire::MakeFrameHeader(0xFFFFFFFFull));
	CHECK_EQUAL(std::string("000A7840"), mcpwire::MakeFrameHeader(686144));
}

int main()
{
	TestParseRequestValid();
	TestParseRequestToleratesCRLFAndFinalBlank();
	TestParseRequestRejectsWrongCapability();
	TestParseRequestMalformedLineFailsAuthorized();
	TestParseRequestMissingMethodFails();
	TestAppendJsonStringEscaping();
	TestBase64EncodeRfc4648Vectors();
	TestBase64DecodeRfc4648Vectors();
	TestBase64DecodeRejectsBadInput();
	TestSanitizeIdentifier();
	TestParseUnsignedAcceptsDecimalAndHex();
	TestParseUnsignedRejectsBadInput();
	TestMakeFrameHeader();

	if (failures != 0)
	{
		std::printf("%d check(s) failed.\n", failures);
		return (failures > 100) ? 100 : failures;
	}
	std::printf("All bridge-wire tests passed.\n");
	return 0;
}
