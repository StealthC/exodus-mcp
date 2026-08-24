#include "BridgeWire.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace mcpwire
{
	bool ParseRequestBody(const std::string& body, const std::string& expectedCapability, WireRequest& request, bool& authorized)
	{
		authorized = false;
		size_t position = 0;
		std::map<std::string, std::string> fields;
		while (position < body.size())
		{
			size_t end = body.find('\n', position);
			if (end == std::string::npos)
			{
				end = body.size();
			}
			std::string line = body.substr(position, end - position);
			position = end + 1;
			if (!line.empty() && line[line.size() - 1] == '\r')
			{
				line.resize(line.size() - 1);
			}
			if (line.empty())
			{
				break;
			}
			const size_t separator = line.find('=');
			if (separator == std::string::npos)
			{
				authorized = true;
				return false;
			}
			fields[line.substr(0, separator)] = line.substr(separator + 1);
		}

		std::map<std::string, std::string>::iterator foundCapability = fields.find("capability");
		authorized = (foundCapability != fields.end() && foundCapability->second == expectedCapability && !expectedCapability.empty());
		if (!authorized)
		{
			return false;
		}

		std::map<std::string, std::string>::iterator foundMethod = fields.find("method");
		if (foundMethod == fields.end() || foundMethod->second.empty())
		{
			return false;
		}
		request.method = foundMethod->second;
		request.id.clear();
		request.params.clear();
		std::map<std::string, std::string>::iterator foundID = fields.find("id");
		if (foundID != fields.end())
		{
			request.id = foundID->second;
		}
		for (std::map<std::string, std::string>::const_iterator i = fields.begin(); i != fields.end(); ++i)
		{
			if (i->first != "capability" && i->first != "method" && i->first != "id")
			{
				request.params[i->first] = i->second;
			}
		}
		return true;
	}

	void AppendJsonString(std::string& target, const std::string& value)
	{
		target += "\"";
		for (std::string::const_iterator i = value.begin(); i != value.end(); ++i)
		{
			const unsigned char character = (unsigned char)*i;
			switch (character)
			{
			case '"':
				target += "\\\"";
				break;
			case '\\':
				target += "\\\\";
				break;
			case '\b':
				target += "\\b";
				break;
			case '\f':
				target += "\\f";
				break;
			case '\n':
				target += "\\n";
				break;
			case '\r':
				target += "\\r";
				break;
			case '\t':
				target += "\\t";
				break;
			default:
				if (character < 0x20)
				{
					char escape[8] = {0};
					sprintf_s(escape, sizeof(escape), "\\u%04X", character);
					target += escape;
				}
				else
				{
					target += (char)character;
				}
				break;
			}
		}
		target += "\"";
	}

	std::string Base64Encode(const unsigned char* data, size_t size)
	{
		static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		std::string encoded;
		encoded.reserve(((size + 2) / 3) * 4);
		for (size_t offset = 0; offset < size; offset += 3)
		{
			const unsigned int remaining = (unsigned int)(size - offset);
			const unsigned int b0 = data[offset];
			const unsigned int b1 = (remaining > 1) ? data[offset + 1] : 0;
			const unsigned int b2 = (remaining > 2) ? data[offset + 2] : 0;
			const unsigned int triple = (b0 << 16) | (b1 << 8) | b2;
			encoded += alphabet[(triple >> 18) & 0x3F];
			encoded += alphabet[(triple >> 12) & 0x3F];
			encoded += (remaining > 1) ? alphabet[(triple >> 6) & 0x3F] : '=';
			encoded += (remaining > 2) ? alphabet[triple & 0x3F] : '=';
		}
		return encoded;
	}

	bool Base64Decode(const std::string& input, std::vector<unsigned char>& output)
	{
		// RFC 4648 decoder: four base64 characters produce three bytes.
		static const signed char decodeTable[256] = {
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
			-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
			-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
		};
		output.clear();
		if (input.empty())
		{
			return true;
		}
		if ((input.size() % 4) != 0)
		{
			return false;
		}
		size_t padding = 0;
		if (input.size() >= 2 && input[input.size() - 1] == '=')
		{
			++padding;
		}
		if (input.size() >= 2 && input[input.size() - 2] == '=')
		{
			++padding;
		}
		if (padding > 2)
		{
			return false;
		}
		const size_t dataLength = input.size() - padding;
		if ((dataLength % 4) == 1)
		{
			return false;
		}
		output.reserve((dataLength / 4) * 3 + padding);
		for (size_t offset = 0; offset < dataLength; offset += 4)
		{
			const int a = decodeTable[(unsigned char)input[offset]];
			const int b = decodeTable[(unsigned char)input[offset + 1]];
			const int c = (offset + 2 < dataLength) ? decodeTable[(unsigned char)input[offset + 2]] : 0;
			const int d = (offset + 3 < dataLength) ? decodeTable[(unsigned char)input[offset + 3]] : 0;
			if (a < 0 || b < 0 || c < 0 || d < 0)
			{
				return false;
			}
			const unsigned int triple = ((unsigned int)a << 18) | ((unsigned int)b << 12) | ((unsigned int)c << 6) | (unsigned int)d;
			output.push_back((unsigned char)(triple >> 16));
			if (offset + 2 < dataLength)
			{
				output.push_back((unsigned char)(triple >> 8));
			}
			if (offset + 3 < dataLength)
			{
				output.push_back((unsigned char)triple);
			}
		}
		return true;
	}

	std::string SanitizeIdentifier(const std::wstring& value)
	{
		std::string sanitized;
		bool lastWasDash = true;
		for (std::wstring::const_iterator i = value.begin(); i != value.end(); ++i)
		{
			const wchar_t character = *i;
			if ((character >= L'a' && character <= L'z') || (character >= L'0' && character <= L'9'))
			{
				sanitized += (char)character;
				lastWasDash = false;
			}
			else if (character >= L'A' && character <= L'Z')
			{
				sanitized += (char)(character - L'A' + 'a');
				lastWasDash = false;
			}
			else if (!lastWasDash)
			{
				sanitized += '-';
				lastWasDash = true;
			}
		}
		while (!sanitized.empty() && sanitized[sanitized.size() - 1] == '-')
		{
			sanitized.resize(sanitized.size() - 1);
		}
		if (sanitized.empty())
		{
			sanitized = "dev";
		}
		return sanitized;
	}

	bool ParseUnsigned(const std::string& text, unsigned long long& value)
	{
		value = 0;
		if (text.empty())
		{
			return false;
		}
		const char* start = text.c_str();
		char* end = 0;
		errno = 0;
		const bool hexadecimal = (text.size() > 2 && start[0] == '0' && (start[1] == 'x' || start[1] == 'X'));
		const unsigned long long parsed = strtoull(start, &end, hexadecimal ? 16 : 10);
		if (end != (start + text.size()) || errno == ERANGE || start[0] == '-' || start[0] == '+')
		{
			return false;
		}
		value = parsed;
		return true;
	}

	std::string MakeFrameHeader(size_t size)
	{
		static const char digits[] = "0123456789ABCDEF";
		char header[9] = {0};
		unsigned long long remaining = (unsigned long long)size;
		if (remaining > 0xFFFFFFFFull)
		{
			remaining = 0xFFFFFFFFull;
		}
		for (int index = 7; index >= 0; --index)
		{
			header[index] = digits[remaining & 0xF];
			remaining >>= 4;
		}
		return std::string(header, 8);
	}
}
