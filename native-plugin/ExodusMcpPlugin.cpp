#include "ExodusMcpPlugin.h"

#include "Processor/Processor.pkg"
#include "M68000/IM68000.h"
#include "Z80/IZ80.h"
#include "Memory/IMemory.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <list>

namespace
{
const wchar_t* const kPipePrefix = L"\\\\.\\pipe\\";
const char* const kPluginVersion = "0.2.0";
const size_t kMaxRequestSize = 64 * 1024;
const size_t kMaxWriteChunk = 32 * 1024;
const unsigned long long kMaxReadLength = 8 * 1024 * 1024;
const unsigned int kDefaultDisassemblyCount = 32;
const unsigned int kMaxDisassemblyCount = 256;
const unsigned int kDefaultTraceEntries = 1000;
const unsigned int kMaxTraceEntries = 10000;
const unsigned long long kDefaultTraceTimeoutMs = 5000;
const unsigned long long kMaxTraceTimeoutMs = 30000;
const char* const kSupportedOperations[] = {"status", "emulator_status", "mem_spaces", "mem_read", "regs_get", "disasm", "trace_capture"};
const size_t kSupportedOperationCount = sizeof(kSupportedOperations) / sizeof(kSupportedOperations[0]);

bool ReadEnvironment(const wchar_t* name, std::wstring& value)
{
	const DWORD required = GetEnvironmentVariableW(name, 0, 0);
	if (required <= 1)
	{
		return false;
	}
	std::wstring buffer(required, L'\0');
	const DWORD written = GetEnvironmentVariableW(name, &buffer[0], required);
	if (written == 0 || written >= required)
	{
		return false;
	}
	buffer.resize(written);
	value = buffer;
	return true;
}

void AppendNumber(std::string& target, unsigned long long value)
{
	char buffer[32] = {0};
	sprintf_s(buffer, sizeof(buffer), "%llu", value);
	target += buffer;
}

void AppendHex(std::string& target, unsigned int value)
{
	char buffer[16] = {0};
	sprintf_s(buffer, sizeof(buffer), "%X", value);
	target += buffer;
}

std::string NumberToString(unsigned long long value)
{
	std::string text;
	AppendNumber(text, value);
	return text;
}

std::string ParamValue(const std::map<std::string, std::string>& params, const char* key)
{
	std::map<std::string, std::string>::const_iterator found = params.find(key);
	return (found == params.end()) ? std::string() : found->second;
}
}

ExodusMcpPlugin::ExodusMcpPlugin(const std::wstring& implementationName, const std::wstring& instanceName, unsigned int moduleID)
: Extension(implementationName, instanceName, moduleID),
  _stopEvent(0),
  _pipeThread(0),
  _loadedModuleCount(0),
  _bridgeEnabled(false)
{ }

ExodusMcpPlugin::~ExodusMcpPlugin()
{
	StopBridge();
}

bool ExodusMcpPlugin::BuildExtension()
{
	CaptureModuleSnapshot();
	if (!LoadBridgeConfiguration())
	{
		// Loading the extension without bridge configuration is intentional:
		// it must never make a normal Exodus launch fail.
		return true;
	}
	return StartBridge();
}

bool ExodusMcpPlugin::LoadBridgeConfiguration()
{
	return ReadEnvironment(L"EXODUS_MCP_PIPE_NAME", _pipeName) &&
		ReadEnvironment(L"EXODUS_MCP_CAPABILITY", _capability) &&
		_pipeName.compare(0, wcslen(kPipePrefix), kPipePrefix) == 0;
}

bool ExodusMcpPlugin::StartBridge()
{
	_stopEvent = CreateEventW(0, TRUE, FALSE, 0);
	if (_stopEvent == 0)
	{
		return false;
	}
	_pipeThread = CreateThread(0, 0, PipeThreadEntry, this, 0, 0);
	if (_pipeThread == 0)
	{
		CloseHandle(_stopEvent);
		_stopEvent = 0;
		return false;
	}
	_bridgeEnabled = true;
	return true;
}

void ExodusMcpPlugin::StopBridge()
{
	if (_stopEvent != 0)
	{
		SetEvent(_stopEvent);
	}
	if (_pipeThread != 0)
	{
		WaitForSingleObject(_pipeThread, 2000);
		CloseHandle(_pipeThread);
		_pipeThread = 0;
	}
	if (_stopEvent != 0)
	{
		CloseHandle(_stopEvent);
		_stopEvent = 0;
	}
	_bridgeEnabled = false;
}

void ExodusMcpPlugin::CaptureModuleSnapshot()
{
	_loadedModuleCount = 0;
	const std::list<unsigned int> moduleIDs = GetSystemInterface().GetLoadedModuleIDs();
	_loadedModuleCount = static_cast<unsigned int>(moduleIDs.size());
}

//----------------------------------------------------------------------------------------------------------------------
// Wire protocol
//----------------------------------------------------------------------------------------------------------------------
DWORD WINAPI ExodusMcpPlugin::PipeThreadEntry(void* parameter)
{
	static_cast<ExodusMcpPlugin*>(parameter)->PipeThread();
	return 0;
}

void ExodusMcpPlugin::PipeThread()
{
	// ERROR_PIPE_LISTENING is not declared in every SDK revision we target.
	const DWORD kErrorPipeListening = 536;

	while (WaitForSingleObject(_stopEvent, 0) != WAIT_OBJECT_0)
	{
		HANDLE pipe = CreateNamedPipeW(
			_pipeName.c_str(),
			PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT,
			1,
			262144,
			4096,
			0,
			0);
		if (pipe == INVALID_HANDLE_VALUE)
		{
			WaitForSingleObject(_stopEvent, 100);
			continue;
		}

		std::string requestBody;
		if (WaitForRequest(pipe, kErrorPipeListening, requestBody))
		{
			HandleConnection(pipe, requestBody);
		}
		FlushFileBuffers(pipe);
		DrainUntilClientClose(pipe, kErrorPipeListening);
		DisconnectNamedPipe(pipe);
		CloseHandle(pipe);
	}
}

bool ExodusMcpPlugin::WaitForRequest(HANDLE pipe, DWORD pipeListeningError, std::string& request)
{
	// Polling reads replace ConnectNamedPipe: with PIPE_NOWAIT the connect
	// call proved unreliable across hosts, while ReadFile reports every state
	// we need - no client yet, connected without data, more data pending,
	// a complete message, or a disconnected peer.
	request.clear();
	char buffer[2048];
	while (WaitForSingleObject(_stopEvent, 0) != WAIT_OBJECT_0)
	{
		DWORD received = 0;
		if (!ReadFile(pipe, buffer, sizeof(buffer), &received, 0))
		{
			const DWORD error = GetLastError();
			if (error == pipeListeningError)
			{
				Sleep(10);
				continue;
			}
			if (error == ERROR_NO_DATA)
			{
				Sleep(5);
				continue;
			}
			if (error == ERROR_MORE_DATA && received > 0)
			{
				request.append(buffer, received);
				continue;
			}
			return false;
		}
		request.append(buffer, received);
		if (request.size() > kMaxRequestSize)
		{
			return false;
		}
		if (received < sizeof(buffer))
		{
			return !request.empty();
		}
	}
	return false;
}

void ExodusMcpPlugin::DrainUntilClientClose(HANDLE pipe, DWORD pipeListeningError)
{
	// Overlapped clients can still be about to read the buffered response when
	// the server drops the connection; discarding it early loses the reply.
	// Hold the pipe open until the client closes its end, mirroring a normal
	// half-close handshake.
	char drain[64] = {0};
	DWORD received = 0;
	while (WaitForSingleObject(_stopEvent, 0) != WAIT_OBJECT_0)
	{
		if (!ReadFile(pipe, drain, sizeof(drain), &received, 0))
		{
			const DWORD error = GetLastError();
			if ((error == ERROR_NO_DATA || error == pipeListeningError) && WaitForSingleObject(_stopEvent, 5) != WAIT_OBJECT_0)
			{
				continue;
			}
			break;
		}
		if (received == 0)
		{
			break;
		}
	}
}

void ExodusMcpPlugin::HandleConnection(HANDLE pipe, const std::string& requestBody)
{
	BridgeRequest request;
	bool authorized = false;
	const bool parsed = !requestBody.empty() && ParseRequest(requestBody, request, authorized);
	if (!parsed)
	{
		std::string response = "{\"protocol_version\":2,\"id\":\"\",\"status\":\"error\",\"error\":{\"code\":";
		response += authorized ? "\"bad_request\",\"message\":\"unable to parse bridge request\"}"
			: "\"unauthorized\",\"message\":\"bridge capability rejected\"}";
		response += "}\n";
		WriteAll(pipe, response);
		return;
	}

	std::string errorCode;
	std::string errorMessage;
	bool ok = true;
	std::string payload = ExecuteCommand(request, ok, errorCode, errorMessage);

	std::string response = "{\"protocol_version\":2,\"id\":";
	AppendJsonStringAscii(response, request.id);
	response += ",\"status\":\"";
	response += ok ? "ok" : "error";
	response += "\"";
	if (ok)
	{
		response += ",\"data\":";
		response += payload.empty() ? "{}" : payload;
	}
	else
	{
		response += ",\"error\":{\"code\":";
		AppendJsonStringAscii(response, errorCode);
		response += ",\"message\":";
		AppendJsonStringAscii(response, errorMessage);
		response += "}";
	}
	response += "}\n";
	WriteAll(pipe, response);
}

bool ExodusMcpPlugin::ParseRequest(const std::string& body, BridgeRequest& request, bool& authorized) const
{
	// Convert the wide capability once. The server generates URL-safe ASCII
	// capabilities; any wider value fails closed instead of losing fidelity.
	std::string expectedCapability;
	for (std::wstring::const_iterator i = _capability.begin(); i != _capability.end(); ++i)
	{
		if (*i > 0x7f)
		{
			authorized = false;
			return false;
		}
		expectedCapability += static_cast<char>(*i);
	}

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
	authorized = (foundCapability != fields.end() && foundCapability->second == expectedCapability);
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

bool ExodusMcpPlugin::WriteAll(HANDLE pipe, const std::string& data)
{
	char header[16] = {0};
	sprintf_s(header, sizeof(header), "%08X", (unsigned int)data.size());
	std::string framed;
	framed.reserve(data.size() + 8);
	framed.append(header, 8);
	framed.append(data);

	size_t offset = 0;
	while (offset < framed.size())
	{
		if (WaitForSingleObject(_stopEvent, 0) == WAIT_OBJECT_0)
		{
			return false;
		}
		const size_t remaining = framed.size() - offset;
		const DWORD toWrite = static_cast<DWORD>((remaining < kMaxWriteChunk) ? remaining : kMaxWriteChunk);
		DWORD written = 0;
		if (!WriteFile(pipe, framed.data() + offset, toWrite, &written, 0))
		{
			if (GetLastError() == ERROR_MORE_DATA && written > 0)
			{
				offset += written;
				continue;
			}
			return false;
		}
		if (written == 0)
		{
			return false;
		}
		offset += written;
	}
	return true;
}

//----------------------------------------------------------------------------------------------------------------------
// Command dispatch
//----------------------------------------------------------------------------------------------------------------------
std::string ExodusMcpPlugin::ExecuteCommand(const BridgeRequest& request, bool& ok, std::string& errorCode, std::string& errorMessage)
{
	ok = true;
	errorCode.clear();
	errorMessage.clear();

	const char* method = request.method.c_str();
	if (strcmp(method, "status") == 0)
	{
		return BuildStatusData();
	}
	if (strcmp(method, "emulator_status") == 0)
	{
		return BuildEmulatorStatusData();
	}
	if (strcmp(method, "mem_spaces") == 0)
	{
		return BuildSpaceCatalogData();
	}

	bool success = false;
	std::string payload;
	if (strcmp(method, "mem_read") == 0)
	{
		success = BuildMemoryReadData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "regs_get") == 0)
	{
		success = BuildRegistersData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "disasm") == 0)
	{
		success = BuildDisassemblyData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "trace_capture") == 0)
	{
		success = BuildTraceCaptureData(request, payload, errorCode, errorMessage);
	}
	else
	{
		ok = false;
		errorCode = "unknown_method";
		errorMessage = "Unsupported bridge method: " + request.method;
		return "";
	}

	if (!success)
	{
		ok = false;
		return "";
	}
	return payload;
}

//----------------------------------------------------------------------------------------------------------------------
// Command payloads
//----------------------------------------------------------------------------------------------------------------------
std::string ExodusMcpPlugin::BuildStatusData() const
{
	std::string data = "{\"plugin_version\":";
	AppendJsonStringAscii(data, kPluginVersion);
	data += ",\"lifecycle\":\"ready\",\"bridge_enabled\":";
	data += _bridgeEnabled ? "true" : "false";
	const std::list<unsigned int> statusModuleIDs = GetSystemInterface().GetLoadedModuleIDs();
	data += ",\"loaded_module_count\":";
	AppendNumber(data, statusModuleIDs.size());
	data += ",\"supported_operations\":[";
	for (size_t i = 0; i < kSupportedOperationCount; ++i)
	{
		if (i > 0)
		{
			data += ",";
		}
		AppendJsonStringAscii(data, kSupportedOperations[i]);
	}
	data += "]}";
	return data;
}

std::string ExodusMcpPlugin::BuildEmulatorStatusData()
{
	ISystemExtensionInterface& systemInterface = GetSystemInterface();

	std::string data = "{\"system_running\":";
	data += systemInterface.SystemRunning() ? "true" : "false";
	data += ",\"modules\":[";
	const std::list<unsigned int> moduleIDs = systemInterface.GetLoadedModuleIDs();
	bool firstEntry = true;
	for (std::list<unsigned int>::const_iterator i = moduleIDs.begin(); i != moduleIDs.end(); ++i)
	{
		if (!firstEntry)
		{
			data += ",";
		}
		firstEntry = false;
		std::wstring moduleName;
		std::wstring moduleInstance;
		systemInterface.GetModuleDisplayName(*i, moduleName);
		systemInterface.GetModuleInstanceName(*i, moduleInstance);
		data += "{\"id\":";
		AppendNumber(data, *i);
		data += ",\"display_name\":";
		AppendJsonString(data, moduleName);
		data += ",\"instance_name\":";
		AppendJsonString(data, moduleInstance);
		data += "}";
	}

	data += "],\"devices\":[";
	const std::list<IDevice*> devices = systemInterface.GetLoadedDevices();
	firstEntry = true;
	for (std::list<IDevice*>::const_iterator i = devices.begin(); i != devices.end(); ++i)
	{
		if (!firstEntry)
		{
			data += ",";
		}
		firstEntry = false;
		std::wstring instanceName;
		std::wstring displayName;
		systemInterface.GetDeviceInstanceName(*i, instanceName);
		systemInterface.GetFullyQualifiedDeviceDisplayName(*i, displayName);
		const bool processorDevice = dynamic_cast<IProcessor*>(*i) != 0;
		const bool memoryDevice = dynamic_cast<IMemory*>(*i) != 0;
		data += "{\"instance_name\":";
		AppendJsonString(data, instanceName);
		data += ",\"display_name\":";
		AppendJsonString(data, displayName);
		data += ",\"processor\":";
		data += processorDevice ? "true" : "false";
		data += ",\"memory\":";
		data += memoryDevice ? "true" : "false";
		data += "}";
	}
	data += "]}";
	return data;
}

std::vector<ExodusMcpPlugin::MemorySpace> ExodusMcpPlugin::BuildSpaceCatalog()
{
	std::vector<MemorySpace> catalog;
	const std::list<IDevice*> devices = GetSystemInterface().GetLoadedDevices();
	std::map<std::string, unsigned int> usedIDs;

	for (std::list<IDevice*>::const_iterator i = devices.begin(); i != devices.end(); ++i)
	{
		IDevice* device = *i;
		MemorySpace space;
		space.processor = 0;
		space.memory = 0;
		space.entrySize = 1;
		space.byteOrder = "unknown";

		std::wstring instanceName;
		std::wstring displayName;
		GetSystemInterface().GetDeviceInstanceName(device, instanceName);
		GetSystemInterface().GetFullyQualifiedDeviceDisplayName(device, displayName);

		if (IProcessor* processor = dynamic_cast<IProcessor*>(device))
		{
			std::string shortName;
			if (dynamic_cast<IM68000*>(device) != 0)
			{
				shortName = "m68k";
				space.byteOrder = "big-endian";
			}
			else if (dynamic_cast<IZ80*>(device) != 0)
			{
				shortName = "z80";
				space.byteOrder = "little-endian";
			}
			else
			{
				shortName = SanitizeIdentifier(instanceName);
			}
			space.kind = "bus";
			space.processor = processor;
			space.id = shortName + "-bus";
			const unsigned int addressBusWidth = processor->GetAddressBusWidth();
			space.sizeBytes = (addressBusWidth < 32) ? (1ULL << addressBusWidth) : 0ULL;
		}
		else if (IMemory* memory = dynamic_cast<IMemory*>(device))
		{
			space.kind = "memory";
			space.memory = memory;
			space.entrySize = memory->GetMemoryEntrySizeInBytes();
			const unsigned long long entryCount = memory->GetMemoryEntryCount();
			space.sizeBytes = space.entrySize * entryCount;
			if (space.entrySize == 1)
			{
				// Single-byte entries carry no multi-byte decode convention.
				space.byteOrder = "not-applicable";
			}
			else if (space.entrySize <= 4)
			{
				// Multi-byte entries on the Mega Drive baseline are 68000-side
				// words/longwords stored most-significant byte first.
				space.byteOrder = "big-endian";
			}
			space.id = "mem-" + SanitizeIdentifier(instanceName);
		}
		else
		{
			continue;
		}

		unsigned int& usage = usedIDs[space.id];
		if (usage > 0)
		{
			space.id += "-" + NumberToString(usage + 1);
		}
		++usage;
		space.deviceInstanceName = instanceName;
		space.deviceDisplayName = displayName;
		catalog.push_back(space);
	}
	return catalog;
}

std::string ExodusMcpPlugin::BuildSpaceCatalogData()
{
	const std::vector<MemorySpace> catalog = BuildSpaceCatalog();
	std::string data = "{\"spaces\":[";
	for (size_t i = 0; i < catalog.size(); ++i)
	{
		if (i > 0)
		{
			data += ",";
		}
		const MemorySpace& space = catalog[i];
		data += "{\"id\":";
		AppendJsonStringAscii(data, space.id);
		data += ",\"kind\":";
		AppendJsonStringAscii(data, space.kind);
		data += ",\"device_instance\":";
		AppendJsonString(data, space.deviceInstanceName);
		data += ",\"device_display\":";
		AppendJsonString(data, space.deviceDisplayName);
		data += ",\"size_bytes\":";
		AppendNumber(data, space.sizeBytes);
		data += ",\"entry_size_bytes\":";
		AppendNumber(data, space.entrySize);
		data += ",\"byte_order\":";
		AppendJsonStringAscii(data, space.byteOrder);
		data += "}";
	}
	data += "]}";
	return data;
}

const ExodusMcpPlugin::MemorySpace* ExodusMcpPlugin::FindSpace(const std::vector<MemorySpace>& catalog, const std::string& spaceId) const
{
	for (size_t i = 0; i < catalog.size(); ++i)
	{
		if (catalog[i].id == spaceId)
		{
			return &catalog[i];
		}
	}
	return 0;
}

unsigned int ExodusMcpPlugin::TypedGetPC(const std::string& cpu, IProcessor& target) const
{
	// GetCurrentPC only reports a value once a debugger break has latched the
	// processor; the typed interfaces expose the live PC while running.
	IDevice* device = target.GetDevice();
	if (_stricmp(cpu.c_str(), "m68k") == 0)
	{
		if (IM68000* m68k = dynamic_cast<IM68000*>(device))
		{
			return m68k->GetPC();
		}
	}
	else
	{
		if (IZ80* z80 = dynamic_cast<IZ80*>(device))
		{
			return z80->GetPC();
		}
	}
	return target.GetCurrentPC();
}

bool ExodusMcpPlugin::BuildMemoryReadData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	const std::string spaceId = ParamValue(request.params, "space");
	unsigned long long requestedAddress = 0;
	unsigned long long length = 0;
	const bool validAddress = ParseUnsigned(ParamValue(request.params, "address"), requestedAddress);
	const bool validLength = ParseUnsigned(ParamValue(request.params, "length"), length);
	if (spaceId.empty() || !validAddress || !validLength)
	{
		errorCode = "invalid_params";
		errorMessage = "mem_read requires space, address, and length parameters";
		return false;
	}
	if (length < 1 || length > kMaxReadLength)
	{
		errorCode = "length_out_of_range";
		errorMessage = "length must be between 1 and " + NumberToString(kMaxReadLength) + " bytes";
		return false;
	}

	const std::vector<MemorySpace> catalog = BuildSpaceCatalog();
	const MemorySpace* space = FindSpace(catalog, spaceId);
	if (space == 0)
	{
		errorCode = "unknown_space";
		errorMessage = "Unknown space id: " + spaceId + ". Valid ids:";
		for (size_t i = 0; i < catalog.size(); ++i)
		{
			errorMessage += " " + catalog[i].id;
		}
		return false;
	}
	if (requestedAddress >= space->sizeBytes || length > space->sizeBytes - requestedAddress)
	{
		errorCode = "out_of_range";
		errorMessage = "Requested range exceeds space size of " + NumberToString(space->sizeBytes) + " bytes";
		return false;
	}

	unsigned int busMask = space->processor->GetAddressBusMask();
	if (busMask == 0)
	{
		const unsigned int busWidth = space->processor->GetAddressBusWidth();
		busMask = (busWidth > 0 && busWidth < 32) ? ((1u << busWidth) - 1u) : 0xFFFFFFFFu;
	}
	unsigned long long address = requestedAddress;
	if (space->kind == "bus")
	{
		address &= busMask;
	}
	std::vector<unsigned char> bytes((size_t)length);
	if (space->kind == "bus")
	{
		for (unsigned long long offset = 0; offset < length; ++offset)
		{
			bytes[(size_t)offset] = (unsigned char)(space->processor->GetMemorySpaceByte((unsigned int)((address + offset) & busMask)) & 0xFF);
		}
	}
	else
	{
		const unsigned int entrySize = (space->entrySize > 0) ? space->entrySize : 1;
		unsigned long long lastEntryIndex = ~0ULL;
		unsigned int entryValue = 0;
		for (unsigned long long offset = 0; offset < length; ++offset)
		{
			const unsigned long long location = address + offset;
			const unsigned long long entryIndex = location / entrySize;
			if (entryIndex != lastEntryIndex)
			{
				entryValue = space->memory->ReadMemoryEntry((unsigned int)entryIndex);
				lastEntryIndex = entryIndex;
			}
			const unsigned int shiftInEntry = (unsigned int)(location % entrySize);
			const unsigned int byteShift = 8u * (entrySize - 1 - shiftInEntry);
			bytes[(size_t)offset] = (unsigned char)((entryValue >> byteShift) & 0xFF);
		}
	}

	data = "{\"space_id\":";
	AppendJsonStringAscii(data, space->id);
	data += ",\"kind\":";
	AppendJsonStringAscii(data, space->kind);
	data += ",\"address\":";
	AppendNumber(data, requestedAddress);
	data += ",\"effective_address\":";
	AppendNumber(data, address);
	data += ",\"length\":";
	AppendNumber(data, length);
	data += ",\"byte_order\":";
	AppendJsonStringAscii(data, space->byteOrder);
	data += ",\"encoding\":\"base64\",\"consistency\":\"live\",\"data\":\"";
	data += Base64Encode(bytes.empty() ? 0 : &bytes[0], bytes.size());
	data += "\"}";
	return true;
}

IProcessor* ExodusMcpPlugin::FindProcessor(const std::string& cpuName, bool& validName) const
{
	validName = true;
	bool wantM68K = (_stricmp(cpuName.c_str(), "m68k") == 0);
	bool wantZ80 = (_stricmp(cpuName.c_str(), "z80") == 0);
	if (!wantM68K && !wantZ80)
	{
		validName = false;
		return 0;
	}
	const std::list<IDevice*> devices = GetSystemInterface().GetLoadedDevices();
	for (std::list<IDevice*>::const_iterator i = devices.begin(); i != devices.end(); ++i)
	{
		IDevice* device = *i;
		if (wantM68K && dynamic_cast<IM68000*>(device) != 0)
		{
			return dynamic_cast<IProcessor*>(device);
		}
		if (wantZ80 && dynamic_cast<IZ80*>(device) != 0)
		{
			return dynamic_cast<IProcessor*>(device);
		}
	}
	return 0;
}

bool ExodusMcpPlugin::BuildRegistersData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	const std::string cpu = ParamValue(request.params, "cpu");
	bool validName = false;
	IProcessor* processor = FindProcessor(cpu, validName);
	if (!validName)
	{
		errorCode = "invalid_params";
		errorMessage = "cpu must be m68k or z80";
		return false;
	}
	if (processor == 0)
	{
		errorCode = "cpu_not_found";
		errorMessage = "No " + cpu + " processor is present in the loaded target";
		return false;
	}

	data = "{\"cpu\":";
	AppendJsonStringAscii(data, cpu);
	data += ",\"byte_order\":\"not-applicable\",\"register_note\":\"Values are plain host integers; byte order is not applicable.\",\"registers\":{";

	if (_stricmp(cpu.c_str(), "m68k") == 0)
	{
		IM68000* m68k = dynamic_cast<IM68000*>(processor->GetDevice());
		if (m68k == 0)
		{
			errorCode = "cpu_not_found";
			errorMessage = "The M68000 device could not be resolved";
			return false;
		}
		for (int reg = 0; reg < IM68000::DataRegCount; ++reg)
		{
			if (reg > 0)
			{
				data += ",";
			}
			data += "\"d";
			AppendNumber(data, reg);
			data += "\":";
			AppendNumber(data, m68k->GetD(reg));
		}
		for (int reg = 0; reg < IM68000::AddressRegCount; ++reg)
		{
			data += ",\"a";
			AppendNumber(data, reg);
			data += "\":";
			AppendNumber(data, m68k->GetA(reg));
		}
		data += ",\"pc\":";
		AppendNumber(data, m68k->GetPC());
		data += ",\"sr\":";
		AppendNumber(data, m68k->GetSR());
		data += ",\"ccr\":";
		AppendNumber(data, m68k->GetCCR());
		data += ",\"ssp\":";
		AppendNumber(data, m68k->GetSSP());
		data += ",\"usp\":";
		AppendNumber(data, m68k->GetUSP());
		data += "},\"flags\":{\"t\":";
		data += m68k->GetSR_T() ? "true" : "false";
		data += ",\"s\":";
		data += m68k->GetSR_S() ? "true" : "false";
		data += ",\"ipm\":";
		AppendNumber(data, m68k->GetSR_IPM());
		data += ",\"x\":";
		data += m68k->GetX() ? "true" : "false";
		data += ",\"n\":";
		data += m68k->GetN() ? "true" : "false";
		data += ",\"z\":";
		data += m68k->GetZ() ? "true" : "false";
		data += ",\"v\":";
		data += m68k->GetV() ? "true" : "false";
		data += ",\"c\":";
		data += m68k->GetC() ? "true" : "false";
		data += "},\"width_bits\":32}";
	}
	else
	{
		IZ80* z80 = dynamic_cast<IZ80*>(processor->GetDevice());
		if (z80 == 0)
		{
			errorCode = "cpu_not_found";
			errorMessage = "The Z80 device could not be resolved";
			return false;
		}
		data += "\"af\":";
		AppendNumber(data, z80->GetAF());
		data += ",\"bc\":";
		AppendNumber(data, z80->GetBC());
		data += ",\"de\":";
		AppendNumber(data, z80->GetDE());
		data += ",\"hl\":";
		AppendNumber(data, z80->GetHL());
		data += ",\"af2\":";
		AppendNumber(data, z80->GetAF2());
		data += ",\"bc2\":";
		AppendNumber(data, z80->GetBC2());
		data += ",\"de2\":";
		AppendNumber(data, z80->GetDE2());
		data += ",\"hl2\":";
		AppendNumber(data, z80->GetHL2());
		data += ",\"ix\":";
		AppendNumber(data, z80->GetIX());
		data += ",\"iy\":";
		AppendNumber(data, z80->GetIY());
		data += ",\"sp\":";
		AppendNumber(data, z80->GetSP());
		data += ",\"pc\":";
		AppendNumber(data, z80->GetPC());
		data += ",\"i\":";
		AppendNumber(data, z80->GetI());
		data += ",\"r\":";
		AppendNumber(data, z80->GetR());
		data += "},\"flags\":{\"s\":";
		data += z80->GetFlagS() ? "true" : "false";
		data += ",\"z\":";
		data += z80->GetFlagZ() ? "true" : "false";
		data += ",\"y\":";
		data += z80->GetFlagY() ? "true" : "false";
		data += ",\"h\":";
		data += z80->GetFlagH() ? "true" : "false";
		data += ",\"x\":";
		data += z80->GetFlagX() ? "true" : "false";
		data += ",\"pv\":";
		data += z80->GetFlagPV() ? "true" : "false";
		data += ",\"n\":";
		data += z80->GetFlagN() ? "true" : "false";
		data += ",\"c\":";
		data += z80->GetFlagC() ? "true" : "false";
		data += "},\"interrupt\":{\"iff1\":";
		data += z80->GetIFF1() ? "true" : "false";
		data += ",\"iff2\":";
		data += z80->GetIFF2() ? "true" : "false";
		data += ",\"im\":";
		AppendNumber(data, z80->GetInterruptMode());
		data += "},\"width_bits\":16}";
	}
	return true;
}

bool ExodusMcpPlugin::BuildDisassemblyData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	const std::string cpu = ParamValue(request.params, "cpu");
	bool validName = false;
	IProcessor* processor = FindProcessor(cpu, validName);
	if (!validName)
	{
		errorCode = "invalid_params";
		errorMessage = "cpu must be m68k or z80";
		return false;
	}
	if (processor == 0)
	{
		errorCode = "cpu_not_found";
		errorMessage = "No " + cpu + " processor is present in the loaded target";
		return false;
	}

	unsigned long long requestedAddress = 0;
	const bool hasAddress = ParseUnsigned(ParamValue(request.params, "address"), requestedAddress);
	unsigned long long count = kDefaultDisassemblyCount;
	ParseUnsigned(ParamValue(request.params, "count"), count);
	if (count < 1)
	{
		count = 1;
	}
	if (count > kMaxDisassemblyCount)
	{
		count = kMaxDisassemblyCount;
	}

	IProcessor& target = *processor;
	unsigned int pcMask = target.GetPCMask();
	if (pcMask == 0)
	{
		// Some processors only populate the mask after debugger attachment;
		// derive it from the PC width instead of collapsing every address.
		const unsigned int pcWidth = target.GetPCWidth();
		pcMask = (pcWidth > 0 && pcWidth < 32) ? ((1u << pcWidth) - 1u) : 0xFFFFFFFFu;
	}
	const unsigned int livePc = TypedGetPC(cpu, target) & pcMask;
	const unsigned int startLocation = hasAddress ? (unsigned int)(requestedAddress & pcMask) : livePc;
	unsigned int location = startLocation;

	std::string lines;
	OpcodeInfo opcodeInfo;
	for (unsigned long long index = 0; index < count; ++index)
	{
		const bool validOpcode = target.GetOpcodeInfo(location, opcodeInfo) && opcodeInfo.GetIsValidOpcode();
		unsigned int size = validOpcode ? opcodeInfo.GetOpcodeSize() : target.GetMinimumOpcodeByteSize();
		if (size == 0)
		{
			size = 1;
		}
		if (size > 16)
		{
			size = 16;
		}

		if (!lines.empty())
		{
			lines += ",";
		}
		lines += "{\"address\":";
		AppendNumber(lines, location);
		lines += ",\"length\":";
		AppendNumber(lines, size);
		lines += ",\"bytes\":\"";
		for (unsigned int byteIndex = 0; byteIndex < size; ++byteIndex)
		{
			if (byteIndex > 0)
			{
				lines += " ";
			}
			AppendHex(lines, target.GetMemorySpaceByte((location + byteIndex) & pcMask) & 0xFF);
		}
		lines += "\",\"mnemonic\":";
		if (validOpcode)
		{
			AppendJsonString(lines, opcodeInfo.GetOpcodeNameDisassembly());
			lines += ",\"operands\":";
			AppendJsonString(lines, opcodeInfo.GetOpcodeArgumentsDisassembly());
			const std::wstring comment = opcodeInfo.GetDisassemblyComment();
			if (!comment.empty())
			{
				lines += ",\"comment\":";
				AppendJsonString(lines, comment);
			}
		}
		else
		{
			lines += "\"invalid\",\"operands\":\"\"}";
			location = (location + size) & pcMask;
			continue;
		}
		lines += "}";
		location = (location + size) & pcMask;
	}

	data = "{\"cpu\":";
	AppendJsonStringAscii(data, cpu);
	data += ",\"start_address\":";
	AppendNumber(data, startLocation);
	data += ",\"address_param_present\":";
	data += hasAddress ? "true" : "false";
	data += ",\"processor_pc\":";
	AppendNumber(data, livePc);
	data += ",\"requested_count\":";
	AppendNumber(data, count);
	data += ",\"disassembly_method\":\"linear sweep from the start address; not execution-verified\",\"lines\":[";
	data += lines;
	data += "]}";
	return true;
}

bool ExodusMcpPlugin::BuildTraceCaptureData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	const std::string cpu = ParamValue(request.params, "cpu");
	bool validName = false;
	IProcessor* processor = FindProcessor(cpu, validName);
	if (!validName)
	{
		errorCode = "invalid_params";
		errorMessage = "cpu must be m68k or z80";
		return false;
	}
	if (processor == 0)
	{
		errorCode = "cpu_not_found";
		errorMessage = "No " + cpu + " processor is present in the loaded target";
		return false;
	}

	unsigned long long maxEntries = kDefaultTraceEntries;
	unsigned long long timeoutMs = kDefaultTraceTimeoutMs;
	ParseUnsigned(ParamValue(request.params, "max_entries"), maxEntries);
	ParseUnsigned(ParamValue(request.params, "timeout_ms"), timeoutMs);
	if (maxEntries < 1)
	{
		maxEntries = 1;
	}
	if (maxEntries > kMaxTraceEntries)
	{
		maxEntries = kMaxTraceEntries;
	}
	if (timeoutMs < 100)
	{
		timeoutMs = 100;
	}
	if (timeoutMs > kMaxTraceTimeoutMs)
	{
		timeoutMs = kMaxTraceTimeoutMs;
	}

	IProcessor& target = *processor;
	const bool priorEnabled = target.GetTraceEnabled();
	const bool priorDisassemble = target.GetTraceDisassemble();

	// Never resize or clear the trace ring here: SetTraceLength/ClearTraceLog
	// mutate vectors the CPU worker thread pushes onto concurrently, and doing
	// so against a running system corrupts the heap (observed as an emulator
	// crash). Only toggle flags - the same operations the built-in debug
	// windows perform live - and cap the returned window by taking the tail.
	target.SetTraceDisassemble(true);
	target.SetTraceEnabled(true);

	const DWORD startTime = GetTickCount();
	bool timedOut = false;
	bool stopped = false;
	while (true)
	{
		if ((GetTickCount() - startTime) >= timeoutMs)
		{
			timedOut = true;
			break;
		}
		if (WaitForSingleObject(_stopEvent, 10) == WAIT_OBJECT_0)
		{
			stopped = true;
			break;
		}
	}

	target.SetTraceEnabled(priorEnabled);
	target.SetTraceDisassemble(priorDisassemble);
	if (stopped)
	{
		errorCode = "shutting_down";
		errorMessage = "Bridge shutdown interrupted the trace capture";
		return false;
	}

	// Give the worker thread time to finish any in-flight entry, then take
	// exactly one snapshot. Reading the log while tracing runs corrupts the
	// heap (observed as an emulator crash), so there must be no concurrent
	// access during the collection window.
	Sleep(150);
	std::vector<IProcessor::TraceLogEntry> entries = target.GetTraceLog();

	size_t firstIndex = 0;
	if (entries.size() > (size_t)maxEntries)
	{
		firstIndex = entries.size() - (size_t)maxEntries;
	}
	const size_t captured = entries.size() - firstIndex;

	std::string traceText;
	std::string sampleLines;
	const size_t sampleLimit = firstIndex + ((captured < 50) ? captured : 50);
	unsigned int addressCharWidth = target.GetPCCharWidth();
	if (addressCharWidth < 1 || addressCharWidth > 12)
	{
		addressCharWidth = 8;
	}
	for (size_t i = firstIndex; i < entries.size(); ++i)
	{
		const IProcessor::TraceLogEntry& entry = entries[i];
		char prefix[64] = {0};
		sprintf_s(prefix, sizeof(prefix), "%0*X %llu ", addressCharWidth, entry.address, (unsigned long long)entry.currentCycle);
		std::string text = prefix + ToUtf8(entry.disassemblyOpcode) + " " + ToUtf8(entry.disassemblyArgs);
		if (!traceText.empty())
		{
			traceText += "\n";
		}
		traceText += text;
		if (i < sampleLimit)
		{
			if (!sampleLines.empty())
			{
				sampleLines += ",";
			}
			sampleLines += "{\"address\":";
			AppendNumber(sampleLines, entry.address);
			sampleLines += ",\"cycle\":";
			AppendNumber(sampleLines, entry.currentCycle);
			sampleLines += ",\"text\":";
			AppendJsonStringAscii(sampleLines, text);
			sampleLines += "}";
		}
	}

	data = "{\"cpu\":";
	AppendJsonStringAscii(data, cpu);
	data += ",\"requested_entries\":";
	AppendNumber(data, maxEntries);
	data += ",\"captured\":";
	AppendNumber(data, captured);
	data += ",\"ring_total\":";
	AppendNumber(data, entries.size());
	data += ",\"timed_out\":";
	data += timedOut ? "true" : "false";
	data += ",\"duration_ms\":";
	AppendNumber(data, GetTickCount() - startTime);
	data += ",\"sampling_note\":\"Entries accumulate only while the system is running; a paused system yields few or none. Tracing is enabled for the capture window and the snapshot is taken once, after tracing is disabled again.\",\"sample\":[";
	data += sampleLines;
	data += "],\"trace_text\":";
	AppendJsonStringAscii(data, traceText);
	data += "}";
	return true;
}

//----------------------------------------------------------------------------------------------------------------------
// Formatting helpers
//----------------------------------------------------------------------------------------------------------------------
std::string ExodusMcpPlugin::ToUtf8(const std::wstring& value)
{
	if (value.empty())
	{
		return std::string();
	}
	const int byteCount = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), (int)value.size(), 0, 0, 0, 0);
	if (byteCount <= 0)
	{
		return std::string();
	}
	std::string result((size_t)byteCount, '\0');
	WideCharToMultiByte(CP_UTF8, 0, value.c_str(), (int)value.size(), &result[0], byteCount, 0, 0);
	return result;
}

void ExodusMcpPlugin::AppendJsonString(std::string& target, const std::wstring& value)
{
	AppendJsonStringAscii(target, ToUtf8(value));
}

void ExodusMcpPlugin::AppendJsonStringAscii(std::string& target, const std::string& value)
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

std::string ExodusMcpPlugin::Base64Encode(const unsigned char* data, size_t size)
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

std::string ExodusMcpPlugin::SanitizeIdentifier(const std::wstring& value)
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

bool ExodusMcpPlugin::ParseUnsigned(const std::string& text, unsigned long long& value)
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
