#include "BridgeWire.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

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
