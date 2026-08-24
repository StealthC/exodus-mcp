#ifndef EXODUS_MCP_BRIDGE_WIRE_H
#define EXODUS_MCP_BRIDGE_WIRE_H

// Pure bridge-wire helpers shared by ExodusMcpPlugin and its standalone unit
// tests. This translation unit deliberately avoids windows.h and any Exodus
// SDK headers so it compiles and runs outside the emulator build.

#include <map>
#include <string>
#include <vector>

namespace mcpwire
{
	// Parsed form of one flat key/value bridge request.
	struct WireRequest
	{
		std::string id;
		std::string method;
		std::map<std::string, std::string> params;
	};

	// Parses one blank-line-terminated key/value request body and checks the
	// capability. Outputs follow HandleConnection's contract:
	// - unparsable body (no '=' in a line): returns false, authorized=true;
	// - wrong or missing capability: returns false, authorized=false;
	// - valid request: returns true (missing/empty method still fails).
	bool ParseRequestBody(const std::string& body, const std::string& expectedCapability, WireRequest& request, bool& authorized);

	// Appends value as one JSON string literal, escaping quotes, backslashes,
	// control characters, and passing UTF-8 bytes through unchanged.
	void AppendJsonString(std::string& target, const std::string& value);

	// RFC 4648 base64 with padding.
	std::string Base64Encode(const unsigned char* data, size_t size);

	// Decodes RFC 4648 base64 with padding; returns false on invalid input.
	bool Base64Decode(const std::string& input, std::vector<unsigned char>& output);

	// Lowercases ASCII alphanumerics, collapses every other run to one dash,
	// trims dashes, and falls back to "dev" when nothing survives.
	std::string SanitizeIdentifier(const std::wstring& value);

	// Accepts decimal or 0x-prefixed hexadecimal unsigned integers and rejects
	// signs, trailing garbage, empty input, and out-of-range values.
	bool ParseUnsigned(const std::string& text, unsigned long long& value);

	// Renders the eight-character uppercase hex frame length prefix used by
	// the wire protocol ("08X").
	std::string MakeFrameHeader(size_t size);
}

#endif
