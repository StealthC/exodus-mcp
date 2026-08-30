#include "ExodusMcpPlugin.h"
#include <fstream>
#include <istream>

#include "BridgeWire.h"

#include "Processor/Processor.pkg"
#include "Processor/IBreakpoint.h"
#include "Processor/IWatchpoint.h"
#include "315-5313/IS315_5313.h"
#include "YM2612/IYM2612.h"
#include "SN76489/ISN76489.h"
#include "Memory/TimedBufferIntDevice.h"
#include "ImageInterface/IImage.h"
#include "DeviceInterface/IDeviceContext.h"
#include "M68000/IM68000.h"
#include "Z80/IZ80.h"
#include "Memory/IMemory.h"
#include "ExtensionInterface/LoadedModuleInfo.h"
#include "SystemInterface/ISystemGUIInterface.h"
#include "SystemInterface/ISystemResetInterface.h"
#include "HierarchicalStorage/HierarchicalStorage.pkg"
#include "Stream/Stream.pkg"
#include "MD1600IO/MDControl3.h"
#include "MD1600IO/MDControl6.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <list>

namespace
{
const wchar_t* const kPipePrefix = L"\\\\.\\pipe\\";
const char* const kPluginVersion = "0.7.1";
const size_t kMaxRequestSize = 64 * 1024;
const size_t kMaxWriteChunk = 32 * 1024;
const unsigned long long kMaxReadLength = 8 * 1024 * 1024;
const unsigned long long kMaxWriteLength = 4096;
const unsigned int kDefaultDisassemblyCount = 32;
const unsigned int kMaxDisassemblyCount = 256;
const unsigned int kDefaultTraceEntries = 1000;
const unsigned int kMaxTraceEntries = 10000;
const unsigned long long kDefaultTraceTimeoutMs = 5000;
const unsigned long long kMaxTraceTimeoutMs = 30000;
const unsigned int kMaxFrameAdvance = 60;
const unsigned int kMaxInputButtons = 16;
const char* const kSupportedOperations[] = {"status", "emulator_status", "mem_spaces", "mem_read", "regs_get", "disasm", "cpu_control", "breakpoint_set", "breakpoint_list", "breakpoint_remove", "watchpoint_set", "watchpoint_list", "watchpoint_remove", "vdp_status", "vdp_command_dma_status", "vdp_mem_read", "vdp_pixel_info", "frame_capture", "rom_load", "trace_capture", "mem_write", "state_save", "state_load", "frame_advance", "input_set", "sound_status", "audio_capture"};
const size_t kSupportedOperationCount = sizeof(kSupportedOperations) / sizeof(kSupportedOperations[0]);

// ScreenshotSink collects the RGB 8-bit pixels that S315_5313::GetScreenshot
// writes into an IImage target. Exodus addresses channels through planeNo
// (0=r, 1=g, 2=b), so the buffer layout is tightly packed RGB24 in scanline
// order. Every other IImage member is intentionally inert: the sink exists
// only to receive this one render pass.
class ScreenshotSink : public IImage
{
public:
	ScreenshotSink()
	:_width(0), _height(0)
	{ }

	virtual void SetImageFormat(unsigned int imageWidth, unsigned int imageHeight, PixelFormat pixelFormat = PIXELFORMAT_RGB, DataFormat dataFormat = DATAFORMAT_8BIT)
	{
		_width = (pixelFormat == PIXELFORMAT_RGB && dataFormat == DATAFORMAT_8BIT) ? imageWidth : 0;
		_height = (_width != 0) ? imageHeight : 0;
		_pixels.assign((size_t)_width * _height * 3, 0);
	}
	virtual void WritePixelData(unsigned int posX, unsigned int posY, unsigned int planeNo, unsigned char data)
	{
		if (posX >= _width || posY >= _height || planeNo >= 3)
		{
			return;
		}
		_pixels[((size_t)posY * _width + posX) * 3 + planeNo] = data;
	}

	unsigned int GetWidth() const { return _width; }
	unsigned int GetHeight() const { return _height; }
	const std::vector<unsigned char>& GetPixels() const { return _pixels; }

private:
	virtual unsigned int GetImageWidth() const { return _width; }
	virtual unsigned int GetImageHeight() const { return _height; }
	virtual PixelFormat GetPixelFormat() const { return PIXELFORMAT_RGB; }
	virtual DataFormat GetDataFormat() const { return DATAFORMAT_8BIT; }
	virtual unsigned int GetDataPlaneCount() const { return 3; }
	virtual void GetRawPixelData(unsigned int, unsigned int, unsigned int, PixelData&) const { }
	virtual void SetRawPixelData(unsigned int, unsigned int, unsigned int, PixelData) { }
	virtual void ReadPixelData(unsigned int, unsigned int, unsigned int, float&) const { }
	virtual void ReadPixelData(unsigned int, unsigned int, unsigned int, unsigned char&) const { }
	virtual void ReadPixelData(unsigned int, unsigned int, unsigned int, unsigned int&, unsigned int) const { }
	virtual void WritePixelData(unsigned int, unsigned int, unsigned int, float) { }
	virtual void WritePixelData(unsigned int, unsigned int, unsigned int, unsigned int, unsigned int) { }
	virtual bool LoadImageFile(Stream::IStream&) { return false; }
	virtual bool LoadPCXImage(Stream::IStream&) { return false; }
	virtual bool SavePCXImage(Stream::IStream&) { return false; }
	virtual bool LoadTIFFImage(Stream::IStream&) { return false; }
	virtual bool SaveTIFFImage(Stream::IStream&) { return false; }
	virtual bool LoadJPGImage(Stream::IStream&) { return false; }
	virtual bool SaveJPGImage(Stream::IStream&) { return false; }
	virtual bool LoadTGAImage(Stream::IStream&) { return false; }
	virtual bool SaveTGAImage(Stream::IStream&) { return false; }
	virtual bool LoadPNGImage(Stream::IStream&) { return false; }
	virtual bool SavePNGImage(Stream::IStream&) { return false; }
	virtual bool LoadBMPImage(Stream::IStream&) { return false; }
	virtual bool SaveBMPImage(Stream::IStream&) { return false; }
	virtual bool LoadDIBImage(Stream::IStream&, const BITMAPINFOHEADER*) { return false; }
	virtual bool SaveDIBImage(Stream::IStream&, BITMAPINFOHEADER*) { return false; }
	virtual void ResampleNearest(unsigned int, unsigned int) { }
	virtual void ResampleNearest(const IImage&, unsigned int, unsigned int) { }
	virtual void ResampleBilinear(unsigned int, unsigned int) { }
	virtual void ResampleBilinear(const IImage&, unsigned int, unsigned int) { }

	unsigned int _width;
	unsigned int _height;
	std::vector<unsigned char> _pixels;
};

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

std::string NumberToStringHex(unsigned long long value)
{
	char buffer[32] = {0};
	sprintf_s(buffer, sizeof(buffer), "%llX", value);
	return buffer;
}

// HexPadded renders value as zero-padded uppercase hex with at least the
// given digit width, prefixed with 0x. Canonical address rendering pads to
// the natural bus width (6 digits for the 24-bit 68K bus, 4 for the Z80).
std::string HexPadded(unsigned long long value, unsigned int width)
{
	char buffer[32] = {0};
	sprintf_s(buffer, sizeof(buffer), "%0*llX", (int)width, value);
	return "0x" + std::string(buffer);
}

std::string ParamValue(const std::map<std::string, std::string>& params, const char* key)
{
	std::map<std::string, std::string>::const_iterator found = params.find(key);
	return (found == params.end()) ? std::string() : found->second;
}

bool Utf8ToWide(const std::string& input, std::wstring& output)
{
	if (input.empty())
	{
		return false;
	}
	const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), (int)input.size(), 0, 0);
	if (size <= 0)
	{
		return false;
	}
	output.resize(size);
	return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), (int)input.size(), &output[0], size) == size;
}

std::wstring FileNameFromPath(const std::wstring& path)
{
	const size_t separator = path.find_last_of(L"\\/");
	return (separator == std::wstring::npos) ? path : path.substr(separator + 1);
}

bool IsSupportedROMPath(const std::wstring& path)
{
	const size_t extension = path.find_last_of(L'.');
	if (extension == std::wstring::npos)
	{
		return false;
	}
	const wchar_t* suffix = path.c_str() + extension;
	return (_wcsicmp(suffix, L".bin") == 0) || (_wcsicmp(suffix, L".gen") == 0) || (_wcsicmp(suffix, L".md") == 0);
}

// DirectoryFromPath returns the directory portion of a path, or "" when the
// path has no directory component.
std::wstring DirectoryFromPath(const std::wstring& path)
{
	const size_t separator = path.find_last_of(L"\\/");
	return (separator == std::wstring::npos) ? std::wstring() : path.substr(0, separator);
}

// IsRelativePath reports whether path is not an absolute Windows path
// (drive-letter, UNC, or root-relative).
bool IsRelativePath(const std::wstring& path)
{
	if (path.empty())
	{
		return true;
	}
	if (path.size() >= 2 && path[1] == L':')
	{
		return false;
	}
	if (path.size() >= 2 && path[0] == L'\\' && path[1] == L'\\')
	{
		return false;
	}
	return path[0] != L'\\' && path[0] != L'/';
}

// ExtractROMPathFromModuleFile recovers the cartridge path embedded in a
// generated module definition. Both the MCP rom_load bridge and the GUI
// "Load ROM File..." action build an XML module whose ROM16 device node
// stores the original ROM path as separate binary data (the tree loader
// restores it as the node's binary data buffer name).
bool ExtractROMPathFromModuleFile(const std::wstring& moduleFilePath, std::wstring& romPath)
{
	Stream::File moduleFile(Stream::IStream::TextEncoding::UTF8);
	if (!moduleFile.Open(moduleFilePath, Stream::File::OpenMode::ReadOnly, Stream::File::CreateMode::Open))
	{
		return false;
	}
	moduleFile.SetTextEncoding(Stream::IStream::TextEncoding::UTF8);
	moduleFile.ProcessByteOrderMark();
	HierarchicalStorageTree tree;
	if (!tree.LoadTree(moduleFile))
	{
		return false;
	}
	moduleFile.Close();

	std::list<IHierarchicalStorageNode*> pending;
	pending.push_back(&tree.GetRootNode());
	for (unsigned int depth = 0; depth < 6 && !pending.empty(); ++depth)
	{
		std::list<IHierarchicalStorageNode*> next;
		for (std::list<IHierarchicalStorageNode*>::const_iterator i = pending.begin(); i != pending.end(); ++i)
		{
			IHierarchicalStorageNode* node = *i;
			if (node->IsAttributePresent(L"BinaryDataPresent") && node->IsAttributePresent(L"SeparateBinaryData"))
			{
				std::wstring candidate = node->GetBinaryDataBufferName();
				if (!candidate.empty() && IsRelativePath(candidate))
				{
					const std::wstring moduleDir = DirectoryFromPath(moduleFilePath);
					if (!moduleDir.empty())
					{
						candidate = moduleDir + L"\\" + candidate;
					}
				}
				if (IsSupportedROMPath(candidate))
				{
					romPath = candidate;
					return true;
				}
			}
			const std::list<IHierarchicalStorageNode*> children = node->GetChildList();
			next.insert(next.end(), children.begin(), children.end());
		}
		pending.swap(next);
	}
	return false;
}

// DiscoverLoadedProgramModuleROM recovers the cartridge path of a ROM that
// was loaded outside the MCP rom_load bridge operation (for example through
// the Exodus GUI "Load ROM File..." action). The plugin only learns the ROM
// path from its own BuildROMLoadData, so without this the emulator_status
// "rom" object reports loaded=false even though a cartridge is running. The
// loaded program module is either the ROM file itself (direct cartridge
// load) or a generated module definition embedding the ROM path.
bool DiscoverLoadedProgramModuleROM(const ISystemExtensionInterface& system, std::wstring& romPath, unsigned long long& romSize)
{
	const std::list<unsigned int> moduleIDs = system.GetLoadedModuleIDs();
	for (std::list<unsigned int>::const_iterator i = moduleIDs.begin(); i != moduleIDs.end(); ++i)
	{
		LoadedModuleInfo moduleInfo;
		if (!system.GetLoadedModuleInfo(*i, moduleInfo) || !moduleInfo.GetIsProgramModule())
		{
			continue;
		}
		std::wstring candidatePath = moduleInfo.GetModuleFilePath();
		if (candidatePath.empty())
		{
			continue;
		}
		if (!IsSupportedROMPath(candidatePath) && !ExtractROMPathFromModuleFile(candidatePath, candidatePath))
		{
			continue;
		}
		WIN32_FILE_ATTRIBUTE_DATA attributes = {};
		if (!GetFileAttributesExW(candidatePath.c_str(), GetFileExInfoStandard, &attributes) || (attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			continue;
		}
		romPath = candidatePath;
		romSize = (static_cast<unsigned long long>(attributes.nFileSizeHigh) << 32) | attributes.nFileSizeLow;
		return true;
	}
	return false;
}

bool CreateROMModule(const std::wstring& romPath, std::wstring& modulePath, unsigned long long& romSizeOut, unsigned int& paddedSizeOut)
{
	if (!IsSupportedROMPath(romPath))
	{
		return false;
	}
	WIN32_FILE_ATTRIBUTE_DATA attributes = {};
	if (!GetFileAttributesExW(romPath.c_str(), GetFileExInfoStandard, &attributes) || (attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		return false;
	}
	const unsigned long long romSize = (static_cast<unsigned long long>(attributes.nFileSizeHigh) << 32) | attributes.nFileSizeLow;
	if (romSize == 0 || romSize > 0x1000000)
	{
		return false;
	}
	unsigned int paddedSize = 1;
	while (paddedSize < romSize)
	{
		paddedSize <<= 1;
	}
	romSizeOut = romSize;
	paddedSizeOut = paddedSize;

	wchar_t tempPath[MAX_PATH] = {};
	const DWORD tempPathLength = GetTempPathW(MAX_PATH, tempPath);
	if (tempPathLength == 0 || tempPathLength >= MAX_PATH)
	{
		return false;
	}
	std::wstring moduleDirectory = std::wstring(tempPath) + L"exodus-mcp";
	if (!CreateDirectoryW(moduleDirectory.c_str(), 0) && GetLastError() != ERROR_ALREADY_EXISTS)
	{
		return false;
	}
	modulePath = moduleDirectory + L"\\rom-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount()) + L".xml";

	const std::wstring fileName = FileNameFromPath(romPath);
	HierarchicalStorageTree tree;
	IHierarchicalStorageNode& root = tree.GetRootNode();
	root.SetName(L"Module");
	root.CreateAttribute(L"SystemClassName", L"SegaMegaDrive");
	root.CreateAttribute(L"ModuleClassName", fileName);
	root.CreateAttribute(L"ModuleInstanceName", fileName);
	root.CreateAttribute(L"ProgramModule", true);
	root.CreateChild(L"System.ImportConnector").CreateAttribute(L"ConnectorClassName", L"CartridgePort").CreateAttribute(L"ConnectorInstanceName", L"Cartridge Port");
	root.CreateChild(L"System.ImportBusInterface").CreateAttribute(L"ConnectorInstanceName", L"Cartridge Port").CreateAttribute(L"BusInterfaceName", L"BusInterface").CreateAttribute(L"ImportName", L"BusInterface");
	root.CreateChild(L"System.ImportSystemLine").CreateAttribute(L"ConnectorInstanceName", L"Cartridge Port").CreateAttribute(L"SystemLineName", L"CART").CreateAttribute(L"ImportName", L"CART");
	root.CreateChild(L"Device").CreateAttribute(L"DeviceName", L"ROM16").CreateAttribute(L"InstanceName", L"ROM").CreateAttribute(L"BinaryDataPresent", true).CreateAttribute(L"SeparateBinaryData", true).SetData(romPath);
	root.CreateChild(L"BusInterface.MapDevice").CreateAttribute(L"BusInterfaceName", L"BusInterface").CreateAttribute(L"DeviceInstanceName", L"ROM").CreateAttribute(L"CELineConditions", L"FCCPUSpace=0, CE0=1").CreateAttributeHex(L"MemoryMapBase", 0, 6).CreateAttributeHex(L"MemoryMapSize", paddedSize, 0).CreateAttributeHex(L"AddressMask", paddedSize - 1, 0).CreateAttribute(L"AddressDiscardLowerBitCount", 1);
	root.CreateChild(L"System.SetLineState").CreateAttribute(L"SystemLineName", L"CART").CreateAttribute(L"Value", 1);

	Stream::File moduleFile(Stream::IStream::TextEncoding::UTF8);
	if (!moduleFile.Open(modulePath, Stream::File::OpenMode::WriteOnly, Stream::File::CreateMode::Create))
	{
		return false;
	}
	moduleFile.InsertByteOrderMark();
	const bool saved = tree.SaveTree(moduleFile);
	moduleFile.Close();
	return saved;
}
}

ExodusMcpPlugin::ExodusMcpPlugin(const std::wstring& implementationName, const std::wstring& instanceName, unsigned int moduleID)
: Extension(implementationName, instanceName, moduleID),
  _stopEvent(0),
	_pipeThread(0),
	_loadedModuleCount(0),
	_bridgeEnabled(false),
	_romLoaded(false),
	_romPath(),
	_romSizeBytes(0),
	_romPaddedSizeBytes(0),
	_nextBreakpointID(1),
	_nextWatchpointID(1),
	_pixelInfoEnableFrameToken(0)
{ }

ExodusMcpPlugin::~ExodusMcpPlugin()
{
	StopBridge();
}

// Debug-CRT reports (assertions, invalid parameters) must never surface as
// the modal Abort/Retry/Ignore dialog: it silently freezes whichever thread
// triggered it, including the CPU worker and our pipe thread. Reports go to
// a log file instead, and the invalid-parameter handler returns so the CRT
// caller degrades to an error code rather than failing fast.
static void __cdecl ExodusMcpInvalidParameterHandler(const wchar_t*, const wchar_t*, const wchar_t*, unsigned int, uintptr_t)
{
}

bool ExodusMcpPlugin::BuildExtension()
{
	// In Debug builds, CRT errors and assertions would normally raise the
	// modal Abort/Retry/Ignore dialog, silently freezing whichever thread
	// triggered it. Route them to a log file instead and keep the invalid
	// parameter handler so callers degrade to error codes. Release builds
	// never show those dialogs, so only the shared handler is needed there.
	_set_invalid_parameter_handler(ExodusMcpInvalidParameterHandler);
#ifdef _DEBUG
	_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
	_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
	_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
	char reportPath[MAX_PATH] = {0};
	char tempDir[MAX_PATH] = {0};
	if (GetTempPathA(MAX_PATH, tempDir) != 0)
	{
		_sprintf_p(reportPath, sizeof(reportPath), "%sexodus-mcp-crt.log", tempDir);
		HANDLE reportFile = CreateFileA(reportPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);
		if (reportFile != INVALID_HANDLE_VALUE)
		{
			_CrtSetReportFile(_CRT_ERROR, reportFile);
			_CrtSetReportFile(_CRT_ASSERT, reportFile);
			_CrtSetReportFile(_CRT_WARN, reportFile);
		}
	}
#endif

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
			// Headroom above a full-speed frame capture response (about 290 KB
			// framed for a 320x224 RGB24 frame) so typical captures fit the
			// buffer without leaning on the WriteAll retry path.
			524288,
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

	mcpwire::WireRequest parsed;
	const bool ok = mcpwire::ParseRequestBody(body, expectedCapability, parsed, authorized);
	if (!ok)
	{
		return false;
	}
	request.id = parsed.id;
	request.method = parsed.method;
	request.params = parsed.params;
	return true;
}

bool ExodusMcpPlugin::WriteAll(HANDLE pipe, const std::string& data)
{
	std::string framed;
	framed.reserve(data.size() + 8);
	framed.append(mcpwire::MakeFrameHeader(data.size()));
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
			const DWORD error = GetLastError();
			if (error == ERROR_MORE_DATA && written > 0)
			{
				offset += written;
				continue;
			}
			if (error == ERROR_NO_DATA)
			{
				// The outbound buffer is momentarily full because the client
				// has not drained the earlier chunks yet. On this nonblocking
				// message-mode pipe that is transient while the client stays
				// alive; aborting here would truncate large responses such as
				// frame captures mid-frame and strand the client until its
				// deadline. Retry the same chunk after a short yield.
				Sleep(1);
				continue;
			}
			return false;
		}
		if (written == 0)
		{
			// Documented nonblocking message-pipe behavior can also report a
			// full buffer as a successful write of zero bytes; treat it like
			// ERROR_NO_DATA above instead of truncating the response.
			Sleep(1);
			continue;
		}
		offset += written;
	}
	return true;
}

namespace
{
// SEH-guarded wrappers around foreign device memory access. These virtual
// calls cross into emulator-owned objects whose internals we do not control;
// an access violation there used to take down the whole emulator process.
// The helpers keep only trivially destructible state so they satisfy the
// MSVC restriction on __try within functions requiring unwinding.

DWORD CaptureFault(void* faultingAddress, void** capturedAddress)
{
	*capturedAddress = faultingAddress;
	return EXCEPTION_EXECUTE_HANDLER;
}

DWORD ReadMemoryEntriesGuarded(IMemory* memory, unsigned int entrySize, unsigned long long address, unsigned long long length, unsigned char* output, void** faultingAddress)
{
	__try
	{
		unsigned int entryValue = 0;
		unsigned long long lastEntryIndex = ~0ULL;
		for (unsigned long long offset = 0; offset < length; ++offset)
		{
			const unsigned long long location = address + offset;
			const unsigned long long entryIndex = location / entrySize;
			if (entryIndex != lastEntryIndex)
			{
				entryValue = memory->ReadMemoryEntry((unsigned int)entryIndex);
				lastEntryIndex = entryIndex;
			}
			const unsigned int shiftInEntry = (unsigned int)(location % entrySize);
			const unsigned int byteShift = 8u * (entrySize - 1 - shiftInEntry);
			output[offset] = (unsigned char)((entryValue >> byteShift) & 0xFF);
		}
		return 0;
	}
	__except (CaptureFault(GetExceptionInformation()->ExceptionRecord->ExceptionAddress, faultingAddress))
	{
		return GetExceptionCode();
	}
}

DWORD ReadLatestGuarded(ITimedBufferInt* buffer, unsigned long long address, unsigned long long length, unsigned char* output, void** faultingAddress)
{
	__try
	{
		for (unsigned long long offset = 0; offset < length; ++offset)
		{
			output[offset] = (unsigned char)(buffer->ReadLatest((unsigned int)(address + offset)) & 0xFF);
		}
		return 0;
	}
	__except (CaptureFault(GetExceptionInformation()->ExceptionRecord->ExceptionAddress, faultingAddress))
	{
		return GetExceptionCode();
	}
}

// Writes a byte range into an entry-based memory device, reading each entry,
// patching its bytes, and writing it back. The byte order parameter controls
// which byte of an entry each offset lands in; big-endian places the first
// byte in the most significant position.
DWORD WriteMemoryEntriesGuarded(IMemory* memory, unsigned int entrySize, bool bigEndian, unsigned long long address, unsigned long long length, const unsigned char* input, void** faultingAddress)
{
	__try
	{
		unsigned long long offset = 0;
		while (offset < length)
		{
			const unsigned long long location = address + offset;
			const unsigned long long entryIndex = location / entrySize;
			const unsigned long long entryEnd = (entryIndex + 1) * entrySize;
			unsigned int entryValue = memory->ReadMemoryEntry((unsigned int)entryIndex);
			while (offset < length && (address + offset) < entryEnd)
			{
				const unsigned long long current = address + offset;
				const unsigned int shiftInEntry = (unsigned int)(current % entrySize);
				const unsigned int byteShift = bigEndian ? (8u * (entrySize - 1 - shiftInEntry)) : (8u * shiftInEntry);
				entryValue = (entryValue & ~(0xFFu << byteShift)) | ((unsigned int)input[offset] << byteShift);
				++offset;
			}
			memory->WriteMemoryEntry((unsigned int)entryIndex, entryValue);
		}
		return 0;
	}
	__except (CaptureFault(GetExceptionInformation()->ExceptionRecord->ExceptionAddress, faultingAddress))
	{
		return GetExceptionCode();
	}
}

// Writes one byte range through a processor's debugger memory path.
DWORD WriteBusBytesGuarded(IProcessor* processor, unsigned int busMask, unsigned long long address, unsigned long long length, const unsigned char* input, void** faultingAddress)
{
	__try
	{
		for (unsigned long long offset = 0; offset < length; ++offset)
		{
			processor->SetMemorySpaceByte((unsigned int)((address + offset) & busMask), input[offset]);
		}
		return 0;
	}
	__except (CaptureFault(GetExceptionInformation()->ExceptionRecord->ExceptionAddress, faultingAddress))
	{
		return GetExceptionCode();
	}
}

void DescribeFaultingModule(void* exceptionAddress, std::string& modulePath, unsigned long long& offset)
{
	HMODULE moduleBase = 0;
	char resolved[MAX_PATH] = {0};
	if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)exceptionAddress, &moduleBase))
	{
		GetModuleFileNameA(moduleBase, resolved, MAX_PATH);
	}
	const uintptr_t baseValue = (uintptr_t)moduleBase;
	modulePath = resolved;
	const uintptr_t addressValue = (uintptr_t)exceptionAddress;
	offset = (baseValue != 0) ? (addressValue - baseValue) : addressValue;
}

// Builds an error message carrying the faulting module and offset for an
// exception address captured by one of the guarded readers above.
std::string DescribeCaughtException(void* exceptionAddress, DWORD exceptionCode)
{
	std::string modulePath;
	unsigned long long offset = 0;
	DescribeFaultingModule(exceptionAddress, modulePath, offset);
	std::string message = "The emulator raised exception 0x";
	message += NumberToStringHex(exceptionCode);
	message += " while servicing this read at ";
	message += modulePath.empty() ? "unknown module" : modulePath;
	message += "+0x";
	message += NumberToStringHex(offset);
	message += "; the read was aborted without crashing the emulator";
	return message;
}
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
	else if (strcmp(method, "cpu_control") == 0)
	{
		success = BuildCPUControlData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "breakpoint_set") == 0)
	{
		success = BuildBreakpointSetData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "breakpoint_list") == 0)
	{
		success = BuildBreakpointListData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "breakpoint_remove") == 0)
	{
		success = BuildBreakpointRemoveData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "watchpoint_set") == 0)
	{
		success = BuildWatchpointSetData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "watchpoint_list") == 0)
	{
		success = BuildWatchpointListData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "watchpoint_remove") == 0)
	{
		success = BuildWatchpointRemoveData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "vdp_status") == 0)
	{
		payload = BuildVdpStatusData();
		success = true;
	}
	else if (strcmp(method, "vdp_command_dma_status") == 0)
	{
		payload = BuildVdpCommandDMAStatusData();
		success = true;
	}
	else if (strcmp(method, "vdp_mem_read") == 0)
	{
		success = BuildVDPMemoryReadData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "vdp_pixel_info") == 0)
	{
		success = BuildVDPPixelInfoData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "frame_capture") == 0)
	{
		success = BuildFrameCaptureData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "rom_load") == 0)
	{
		success = BuildROMLoadData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "trace_capture") == 0)
	{
		success = BuildTraceCaptureData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "mem_write") == 0)
	{
		success = BuildMemoryWriteData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "state_save") == 0)
	{
		success = BuildStateSaveData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "state_load") == 0)
	{
		success = BuildStateLoadData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "frame_advance") == 0)
	{
		success = BuildFrameAdvanceData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "input_set") == 0)
	{
		success = BuildInputSetData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "sound_status") == 0)
	{
		success = BuildSoundStatusData(request, payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "soft_reset") == 0)
	{
		success = BuildSoftResetData(payload, errorCode, errorMessage);
	}
	else if (strcmp(method, "audio_capture") == 0)
	{
		errorCode = "audio_unavailable";
		errorMessage = "The Exodus SDK exposes audio logging configuration but no safe bounded PCM capture buffer to this extension.";
		success = false;
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
	ISystemResetInterface* reset = FindSystemResetInterface();
	if (reset != 0 && reset->GetISystemResetInterfaceVersion() == ISystemResetInterface::ThisISystemResetInterfaceVersion() && reset->IsMegaDriveSoftResetAvailable())
	{
		data += ",\"soft_reset\"";
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
	// The plugin tracks the cartridge path only for ROMs loaded through the
	// MCP rom_load bridge operation. A cartridge loaded through the Exodus UI
	// (or by any other actor) is recovered from the loaded program module so
	// emulator_status always reports the running cartridge; path_source states
	// which mechanism provided it. padded_size_bytes is only known after the
	// MCP rom_load module creation, so a discovered cartridge reports the
	// file-derived size and padded_size_bytes stays 0 (unknown).
	bool romLoaded = _romLoaded;
	std::wstring romPath = _romPath;
	unsigned long long romSizeBytes = _romSizeBytes;
	unsigned long long romPaddedSizeBytes = _romPaddedSizeBytes;
	std::string romPathSource = "mcp_load";
	if (!romLoaded)
	{
		romLoaded = DiscoverLoadedProgramModuleROM(systemInterface, romPath, romSizeBytes);
		romPathSource = romLoaded ? "loaded_module" : "none";
	}

	data += "],\"rom\":{\"loaded\":";
	data += romLoaded ? "true" : "false";
	data += ",\"size_bytes\":";
	AppendNumber(data, romSizeBytes);
	data += ",\"padded_size_bytes\":";
	AppendNumber(data, romPaddedSizeBytes);
	data += ",\"path\":";
	AppendJsonString(data, romPath);
	data += ",\"path_source\":";
	AppendJsonStringAscii(data, romPathSource);
	data += "}}";
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
		space.device = device;
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

//----------------------------------------------------------------------------------------------------------------------
void ExodusMcpPlugin::PurgeManagedDebugState()
{
	// Processor-owned debug objects die with the loaded module. Every managed
	// breakpoint and watchpoint must be deleted before a ROM swap unloads the
	// current module, otherwise the managed maps would hold dangling pointers.
	for (std::map<unsigned long long, ManagedBreakpoint>::iterator i = _managedBreakpoints.begin(); i != _managedBreakpoints.end(); ++i)
	{
		i->second.processor->DeleteBreakpoint(i->second.breakpoint);
	}
	_managedBreakpoints.clear();
	for (std::map<unsigned long long, ManagedWatchpoint>::iterator i = _managedWatchpoints.begin(); i != _managedWatchpoints.end(); ++i)
	{
		i->second.processor->DeleteWatchpoint(i->second.watchpoint);
	}
	_managedWatchpoints.clear();
}

//----------------------------------------------------------------------------------------------------------------------
IS315_5313* ExodusMcpPlugin::FindVdp() const
{
	const std::list<IDevice*> devices = GetSystemInterface().GetLoadedDevices();
	for (std::list<IDevice*>::const_iterator i = devices.begin(); i != devices.end(); ++i)
	{
		if (IS315_5313* vdp = dynamic_cast<IS315_5313*>(*i))
		{
			return vdp;
		}
	}
	return 0;
}

//----------------------------------------------------------------------------------------------------------------------
ISystemResetInterface* ExodusMcpPlugin::FindSystemResetInterface() const
{
	return dynamic_cast<ISystemResetInterface*>(&GetSystemInterface());
}

bool ExodusMcpPlugin::BuildSoftResetData(std::string& data, std::string& errorCode, std::string& errorMessage)
{
	ISystemResetInterface* reset = FindSystemResetInterface();
	if (reset == 0 || reset->GetISystemResetInterfaceVersion() != ISystemResetInterface::ThisISystemResetInterfaceVersion() || !reset->IsMegaDriveSoftResetAvailable())
	{
		errorCode = "soft_reset_unavailable";
		errorMessage = "The loaded fork does not expose a compatible Mega Drive soft-reset coordinator.";
		return false;
	}
	SoftResetResult result;
	try
	{
		if (!reset->SoftReset(result) || result.status != SoftResetResult::Success)
		{
			errorCode = (result.status == SoftResetResult::Partial) ? "soft_reset_partial" : "soft_reset_unavailable";
			errorMessage = result.failureDetail != 0 ? result.failureDetail : "Native soft reset did not complete.";
			return false;
		}
	}
	catch (...)
	{
		errorCode = "soft_reset_unavailable";
		errorMessage = "Native soft reset raised an exception.";
		return false;
	}
	data = "{\"schema\":\"mega-drive-soft-reset/1\",\"reset_kind\":\"soft\",\"reset_source\":\"hardware_reset_line\",\"initial_run_state\":";
	data += result.initialRunning ? "\"running\"" : "\"paused\"";
	data += ",\"final_run_state\":";
	data += result.finalRunning ? "\"running\"" : "\"paused\"";
	data += ",\"state_changed\":";
	data += result.stateChanged ? "true" : "false";
	data += ",\"ram_preserved\":{\"work_ram\":";
	data += result.workRamPreserved ? "true" : "false";
	data += ",\"z80_ram\":";
	data += result.z80RamPreserved ? "true" : "false";
	data += "},\"vdp_preserved\":";
	data += result.vdpPreserved ? "true" : "false";
	data += ",\"external_reset_pulse\":";
	data += result.externalResetPulse ? "true" : "false";
	data += ",\"vector_fetch\":{\"valid\":";
	data += result.vectorFetchValid ? "true" : "false";
	data += ",\"sp\":";
	AppendNumber(data, result.stackPointer);
	data += ",\"pc\":";
	AppendNumber(data, result.programCounter);
	data += ",\"pc_mask\":";
	AppendNumber(data, result.programCounterMask);
	data += ",\"byte_order\":\"big-endian\",\"address_space\":\"m68k-bus\",\"source\":\"architectural_bus_fetch\"}}";
	return true;
}

ISystemGUIInterface* ExodusMcpPlugin::FindSystemGUIInterface() const
{
	// Extensions bind to the same System object the GUI uses, seen through
	// the narrower ISystemExtensionInterface view. System implements both
	// interfaces on one object, so the cross-cast down to the GUI view gives
	// access to its save-state API without any fork change.
	return dynamic_cast<ISystemGUIInterface*>(&GetSystemInterface());
}

//----------------------------------------------------------------------------------------------------------------------
std::string ExodusMcpPlugin::BuildVdpStatusData()
{
	IS315_5313* vdp = FindVdp();
	if (vdp == 0)
	{
		return "{\"vdp_found\":false}";
	}

	std::string data = "{\"vdp_found\":true,\"system_paused_during_read\":false,\"registers\":[";
	bool first = true;
	for (unsigned int location = 0; location < IS315_5313::RegisterCount; ++location)
	{
		if (!first)
		{
			data += ",";
		}
		first = false;
		data += "{\"register\":";
		AppendNumber(data, location);
		data += ",\"value\":";
		AppendNumber(data, vdp->GetRegisterData(location));
		data += "}";
	}
	data += "],\"decoded\":{\"display_enabled\":";
	data += vdp->RegGetDisplayEnabled() ? "true" : "false";
	data += ",\"extended_vram\":";
	data += vdp->RegGetEVRAM() ? "true" : "false";
	data += ",\"name_table_base_a\":";
	AppendNumber(data, vdp->RegGetNameTableBaseScrollA());
	data += ",\"name_table_base_b\":";
	AppendNumber(data, vdp->RegGetNameTableBaseScrollB());
	data += ",\"name_table_base_window\":";
	AppendNumber(data, vdp->RegGetNameTableBaseWindow());
	data += ",\"name_table_base_sprite\":";
	AppendNumber(data, vdp->RegGetNameTableBaseSprite());
	data += ",\"pattern_base_a\":";
	AppendNumber(data, vdp->RegGetPatternBaseScrollA());
	data += ",\"pattern_base_b\":";
	AppendNumber(data, vdp->RegGetPatternBaseScrollB());
	data += ",\"pattern_base_sprite\":";
	AppendNumber(data, vdp->RegGetPatternBaseSprite());
	data += ",\"hscroll_data_base\":";
	AppendNumber(data, vdp->RegGetHScrollDataBase());
	data += "},\"image_buffer\":{\"completed_plane\":";
	const unsigned int planeNo = vdp->GetImageCompletedBufferPlaneNo();
	AppendNumber(data, planeNo);
	data += ",\"line_count\":";
	AppendNumber(data, vdp->GetImageBufferLineCount(planeNo));
	data += ",\"line_width\":";
	AppendNumber(data, vdp->GetImageBufferLineWidth(planeNo, 0));
	data += ",\"last_rendered_frame_token\":";
	AppendNumber(data, vdp->GetImageLastRenderedFrameToken());
	data += "}}";
	return data;
}

//----------------------------------------------------------------------------------------------------------------------
std::string ExodusMcpPlugin::BuildVdpCommandDMAStatusData()
{
	IS315_5313* vdp = FindVdp();
	if (vdp == 0) return "{\"vdp_found\":false}";
	std::string data = "{\"vdp_found\":true,\"byte_order\":\"big-endian\",\"address_space\":\"vdp-internal\",\"registers\":[";
	for (unsigned int location = 0; location < IS315_5313::RegisterCount; ++location)
	{
		if (location != 0) data += ",";
		data += "{\"register\":"; AppendNumber(data, location);
		data += ",\"value\":"; AppendNumber(data, vdp->GetRegisterData(location)); data += "}";
	}
	data += "],\"command_latch\":{\"address\":null,\"address_valid\":null,\"code\":null,\"destination\":null,\"observability\":\"unavailable\",\"note\":\"The pinned IS315_5313 interface does not expose the complete internal command latch.\"},\"dma\":{";
	data += "\"enabled\":"; data += vdp->RegGetDMAEnabled() ? "true" : "false";
	data += ",\"active\":"; data += vdp->GetStatusFlagDMA() ? "true" : "false";
	data += ",\"length_counter\":"; AppendNumber(data, vdp->RegGetDMALengthCounter());
	data += ",\"source_address\":"; AppendNumber(data, vdp->RegGetDMASourceAddress());
	data += ",\"source_address_byte1\":"; AppendNumber(data, vdp->RegGetDMASourceAddressByte1());
	data += ",\"source_address_byte2\":"; AppendNumber(data, vdp->RegGetDMASourceAddressByte2());
	data += ",\"source_address_byte3\":"; AppendNumber(data, vdp->RegGetDMASourceAddressByte3());
	data += ",\"transfer_mode_bit1\":"; data += vdp->RegGetDMD1() ? "true" : "false";
	data += ",\"transfer_mode_bit0\":"; data += vdp->RegGetDMD0() ? "true" : "false";
	data += ",\"destination\":null,\"remaining_length\":null,\"observability\":\"partial\",\"note\":\"Destination and live remaining length are not separate public fields in the pinned interface.\"},\"capture_consistency\":\"composite_non_atomic\"}";
	return data;
}

bool ExodusMcpPlugin::BuildFrameCaptureData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	IS315_5313* vdp = FindVdp();
	if (vdp == 0)
	{
		errorCode = "vdp_not_found";
		errorMessage = "No Mega Drive VDP (315-5313) device is present in the loaded target";
		return false;
	}

	ScreenshotSink sink;
	if (!vdp->GetDevice()->GetScreenshot(sink) || sink.GetWidth() == 0 || sink.GetHeight() == 0)
	{
		errorCode = "frame_capture_failed";
		errorMessage = "Exodus could not provide a rendered frame from the VDP";
		return false;
	}

	const std::vector<unsigned char>& pixels = sink.GetPixels();
	data = "{\"width\":";
	AppendNumber(data, sink.GetWidth());
	data += ",\"height\":";
	AppendNumber(data, sink.GetHeight());
	data += ",\"pixel_format\":\"rgb24\",\"byte_order\":\"not-applicable\",\"encoding\":\"base64\",\"consistency\":\"live\",\"frame_token\":";
	AppendNumber(data, vdp->GetImageLastRenderedFrameToken());
	data += ",\"data\":\"";
	std::string encoded = Base64Encode(pixels.empty() ? (const unsigned char*)"" : &pixels[0], pixels.size());
	data += encoded;
	data += "\"}";
	return true;
}

//----------------------------------------------------------------------------------------------------------------------
bool ExodusMcpPlugin::BuildVDPMemoryReadData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	const std::string target = ParamValue(request.params, "target");
	unsigned long long requestedAddress = 0;
	unsigned long long length = 0;
	const bool validAddress = ParseUnsigned(ParamValue(request.params, "address"), requestedAddress);
	const bool validLength = ParseUnsigned(ParamValue(request.params, "length"), length);
	if (target.empty() || !validAddress || !validLength)
	{
		errorCode = "invalid_params";
		errorMessage = "vdp_mem_read requires target, address, and length parameters";
		return false;
	}
	if (length < 1 || length > kMaxReadLength)
	{
		errorCode = "length_out_of_range";
		errorMessage = "length must be between 1 and " + NumberToString(kMaxReadLength) + " bytes";
		return false;
	}

	IS315_5313* vdp = FindVdp();
	if (vdp == 0)
	{
		errorCode = "vdp_not_found";
		errorMessage = "No Mega Drive VDP (315-5313) device is present in the loaded target";
		return false;
	}

	ITimedBufferInt* buffer = 0;
	const char* spaceName = 0;
	if (target == "vram")
	{
		buffer = vdp->GetVRAMBuffer();
		spaceName = "VRAM";
	}
	else if (target == "cram")
	{
		buffer = vdp->GetCRAMBuffer();
		spaceName = "CRAM";
	}
	else if (target == "vsram")
	{
		buffer = vdp->GetVSRAMBuffer();
		spaceName = "VSRAM";
	}
	else
	{
		errorCode = "invalid_params";
		errorMessage = "target must be vram, cram, or vsram";
		return false;
	}

	const unsigned long long bufferSize = buffer->Size();
	if (requestedAddress >= bufferSize || length > bufferSize - requestedAddress)
	{
		errorCode = "out_of_range";
		errorMessage = "Requested range exceeds ";
		errorMessage += spaceName;
		errorMessage += " size of ";
		errorMessage += NumberToString(bufferSize);
		errorMessage += " bytes";
		return false;
	}

	// Same synchronization rule as mem_read: ReadLatest on these buffers is
	// only safe once the owning worker threads are parked.
	const bool wasRunning = GetSystemInterface().SystemRunning();
	if (wasRunning)
	{
		GetSystemInterface().StopSystem();
	}

	std::vector<unsigned char> bytes((size_t)length);
	void* faultingAddress = 0;
	const DWORD faultCode = ReadLatestGuarded(buffer, requestedAddress, length, bytes.empty() ? 0 : &bytes[0], &faultingAddress);
	if (faultCode != 0)
	{
		if (wasRunning)
		{
			GetSystemInterface().RunSystem();
		}
		errorCode = "read_fault";
		errorMessage = DescribeCaughtException(faultingAddress, faultCode);
		return false;
	}

	if (wasRunning)
	{
		GetSystemInterface().RunSystem();
	}

	data = "{\"target\":";
	AppendJsonStringAscii(data, target);
	data += ",\"address_space\":\"315-5313 ";
	data += spaceName;
	data += "\",\"address\":";
	AppendNumber(data, requestedAddress);
	data += ",\"length\":";
	AppendNumber(data, length);
	data += ",\"buffer_size\":";
	AppendNumber(data, bufferSize);
	data += ",\"entry_size\":2,\"byte_order\":\"big-endian\",\"encoding\":\"base64\",\"consistency\":\"live\",\"system_paused_during_read\":";
	data += wasRunning ? "true" : "false";
	data += ",\"data\":\"";
	data += Base64Encode(bytes.empty() ? 0 : &bytes[0], bytes.size());
	data += "\"}";
	return true;
}

//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
bool ExodusMcpPlugin::BuildVDPPixelInfoData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	IS315_5313* vdp = FindVdp();
	if (vdp == 0)
	{
		errorCode = "vdp_not_found";
		errorMessage = "No Mega Drive VDP (315-5313) device is present in the loaded target";
		return false;
	}

	unsigned long long parsedX = 0;
	unsigned long long parsedY = 0;
	const bool validX = ParseUnsigned(ParamValue(request.params, "x"), parsedX);
	const bool validY = ParseUnsigned(ParamValue(request.params, "y"), parsedY);
	if (!validX || !validY || parsedX > 0xFFFFFF || parsedY > 0xFFFF)
	{
		errorCode = "invalid_params";
		errorMessage = "vdp_pixel_info requires x and y parameters";
		return false;
	}

	// Full per-pixel attribution is only recorded while the VDP debug flag is
	// enabled, because it costs render performance. Enable it lazily and
	// remember the frame token at that moment: the completed buffer carries
	// valid attribution only after a frame has been rendered with the flag
	// active. Until then the caller retries after one frame.
	const bool alreadyEnabled = vdp->GetVideoEnableFullImageBufferInfo();
	if (!alreadyEnabled)
	{
		vdp->SetVideoEnableFullImageBufferInfo(true);
		_pixelInfoEnableFrameToken = vdp->GetImageLastRenderedFrameToken();
	}
	const unsigned int frameToken = vdp->GetImageLastRenderedFrameToken();
	const bool attributionReady = alreadyEnabled || (frameToken != _pixelInfoEnableFrameToken);

	const unsigned int targetX = (unsigned int)parsedX;
	const unsigned int targetY = (unsigned int)parsedY;
	const unsigned int planeNo = vdp->GetImageCompletedBufferPlaneNo();
	const unsigned int lineCount = vdp->GetImageBufferLineCount(planeNo);
	if (targetY >= lineCount)
	{
		errorCode = "out_of_range";
		errorMessage = "y exceeds the completed image buffer line count";
		return false;
	}
	const unsigned int lineWidth = vdp->GetImageBufferLineWidth(planeNo, targetY);
	if (targetX >= lineWidth)
	{
		errorCode = "out_of_range";
		errorMessage = "x exceeds the completed image buffer line width";
		return false;
	}

	data = "{\"attribution_ready\":";
	data += attributionReady ? "true" : "false";
	data += ",\"frame_token\":";
	AppendNumber(data, frameToken);
	data += ",\"buffer_plane\":";
	AppendNumber(data, planeNo);
	data += ",\"line_count\":";
	AppendNumber(data, lineCount);
	data += ",\"line_width\":";
	AppendNumber(data, lineWidth);
	if (!attributionReady)
	{
		data += "}";
		return true;
	}

	vdp->LockImageBufferData(planeNo);
	const IS315_5313::ImageBufferInfo* info = vdp->GetImageBufferInfo(planeNo, targetY, targetX);
	if (info == 0)
	{
		vdp->UnlockImageBufferData(planeNo);
		errorCode = "pixel_info_unavailable";
		errorMessage = "The VDP did not provide attribution data for the target pixel";
		return false;
	}

	const char* pixelSource = "unknown";
	bool mappingPresent = false;
	bool spritePresent = false;
	switch (info->pixelSource)
	{
	case IS315_5313::PixelSource::Sprite:
		pixelSource = "sprite";
		mappingPresent = true;
		spritePresent = true;
		break;
	case IS315_5313::PixelSource::LayerA:
		pixelSource = "layer_a";
		mappingPresent = true;
		break;
	case IS315_5313::PixelSource::LayerB:
		pixelSource = "layer_b";
		mappingPresent = true;
		break;
	case IS315_5313::PixelSource::Background:
		pixelSource = "background";
		break;
	case IS315_5313::PixelSource::Window:
		pixelSource = "window";
		mappingPresent = true;
		break;
	case IS315_5313::PixelSource::CRAMWrite:
		pixelSource = "cram_write";
		break;
	case IS315_5313::PixelSource::Border:
		pixelSource = "border";
		break;
	case IS315_5313::PixelSource::Blanking:
		pixelSource = "blanking";
		break;
	}

	const unsigned char red8 = vdp->ColorValueTo8BitValue(info->colorComponentR, info->pixelIsShadowed, info->pixelIsHighlighted);
	const unsigned char green8 = vdp->ColorValueTo8BitValue(info->colorComponentG, info->pixelIsShadowed, info->pixelIsHighlighted);
	const unsigned char blue8 = vdp->ColorValueTo8BitValue(info->colorComponentB, info->pixelIsShadowed, info->pixelIsHighlighted);

	data += ",\"source\":\"";
	data += pixelSource;
	data += "\",\"hcounter\":";
	AppendNumber(data, info->hcounter);
	data += ",\"vcounter\":";
	AppendNumber(data, info->vcounter);
	data += ",\"palette_row\":";
	AppendNumber(data, info->paletteRow);
	data += ",\"palette_entry\":";
	AppendNumber(data, info->paletteEntry);
	data += ",\"shadow_highlight_enabled\":";
	data += info->shadowHighlightEnabled ? "true" : "false";
	data += ",\"pixel_is_shadowed\":";
	data += info->pixelIsShadowed ? "true" : "false";
	data += ",\"pixel_is_highlighted\":";
	data += info->pixelIsHighlighted ? "true" : "false";
	data += ",\"color_rgb333\":[";
	AppendNumber(data, info->colorComponentR);
	data += ",";
	AppendNumber(data, info->colorComponentG);
	data += ",";
	AppendNumber(data, info->colorComponentB);
	data += "],\"color_888\":\"#";
	char colorHex[8] = {0};
	sprintf_s(colorHex, sizeof(colorHex), "%02X%02X%02X", red8, green8, blue8);
	data += colorHex;
	data += "\",\"mapping_present\":";
	data += mappingPresent ? "true" : "false";
	if (mappingPresent)
	{
		data += ",\"mapping_vram_address\":";
		AppendNumber(data, info->mappingVRAMAddress);
		data += ",\"mapping_data_word\":";
		AppendNumber(data, info->mappingData.GetData());
		data += ",\"tile\":";
		AppendNumber(data, info->mappingData.GetDataSegment(0, 11));
		data += ",\"hflip\":";
		data += info->mappingData.GetBit(11) ? "true" : "false";
		data += ",\"vflip\":";
		data += info->mappingData.GetBit(12) ? "true" : "false";
		data += ",\"priority\":";
		data += info->mappingData.GetBit(15) ? "true" : "false";
		data += ",\"pattern_row\":";
		AppendNumber(data, info->patternRowNo);
		data += ",\"pattern_column\":";
		AppendNumber(data, info->patternColumnNo);
	}
	data += ",\"sprite_present\":";
	data += spritePresent ? "true" : "false";
	if (spritePresent)
	{
		data += ",\"sprite_table_entry_no\":";
		AppendNumber(data, info->spriteTableEntryNo);
		data += ",\"sprite_table_entry_address\":";
		AppendNumber(data, info->spriteTableEntryAddress);
		data += ",\"sprite_cell_width\":";
		AppendNumber(data, info->spriteCellWidth);
		data += ",\"sprite_cell_height\":";
		AppendNumber(data, info->spriteCellHeight);
		data += ",\"sprite_cell_pos_x\":";
		AppendNumber(data, info->spriteCellPosX);
		data += ",\"sprite_cell_pos_y\":";
		AppendNumber(data, info->spriteCellPosY);
	}
	data += "}";

	vdp->UnlockImageBufferData(planeNo);
	return true;
}

//----------------------------------------------------------------------------------------------------------------------
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
		errorMessage = "Requested range exceeds space " + space->id + " size of " + NumberToString(space->sizeBytes) + " bytes; space spans " +
			HexPadded(0, 6) + "-" + (space->sizeBytes > 0 ? HexPadded(space->sizeBytes - 1, 6) : "unknown");
		return false;
	}

	// Bus-derived metadata only exists for processor spaces; memory-kind
	// spaces (RAM blocks and the VDP buffers) carry a null processor here,
	// so touching it crashed every generic read of those spaces.
	const bool isBusSpace = (space->kind == "bus");
	unsigned int busMask = 0;
	unsigned long long address = requestedAddress;
	if (isBusSpace)
	{
		busMask = space->processor->GetAddressBusMask();
		if (busMask == 0)
		{
			const unsigned int busWidth = space->processor->GetAddressBusWidth();
			busMask = (busWidth > 0 && busWidth < 32) ? ((1u << busWidth) - 1u) : 0xFFFFFFFFu;
		}
		address &= busMask;
	}

	// Timed-buffer devices (the VDP memory shells) mutate their write lists
	// on the owning worker thread; ReadLatest against them while the system
	// runs is an unsynchronized cross-thread access that has crashed the
	// emulator. StopSystem blocks until every worker is parked, so a brief
	// stop around the read makes it safe, and we restore the prior state.
	ITimedBufferIntDevice* timedBufferDevice = (space->device != 0) ? dynamic_cast<ITimedBufferIntDevice*>(space->device) : 0;
	const bool pauseForRead = (timedBufferDevice != 0) && GetSystemInterface().SystemRunning();
	if (pauseForRead)
	{
		GetSystemInterface().StopSystem();
	}

	std::vector<unsigned char> bytes((size_t)length);
	if (isBusSpace)
	{
		for (unsigned long long offset = 0; offset < length; ++offset)
		{
			bytes[(size_t)offset] = (unsigned char)(space->processor->GetMemorySpaceByte((unsigned int)((address + offset) & busMask)) & 0xFF);
		}
	}
	else
	{
		const unsigned int entrySize = (space->entrySize > 0) ? space->entrySize : 1;
		void* faultingAddress = 0;
		const DWORD faultCode = ReadMemoryEntriesGuarded(space->memory, entrySize, address, length, bytes.empty() ? 0 : &bytes[0], &faultingAddress);
		if (faultCode != 0)
		{
			if (pauseForRead)
			{
				GetSystemInterface().RunSystem();
			}
			errorCode = "read_fault";
			errorMessage = DescribeCaughtException(faultingAddress, faultCode);
			return false;
		}
	}

	if (pauseForRead)
	{
		GetSystemInterface().RunSystem();
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
	data += ",\"encoding\":\"base64\",\"consistency\":\"live\",\"system_paused_during_read\":";
	data += pauseForRead ? "true" : "false";
	data += ",\"data\":\"";
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
	data += ",\"byte_order\":\"not-applicable\",\"register_note\":\"Values are plain host integers; byte order is not applicable.\",\"system_paused_during_read\":false,\"registers\":{";

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
	data += ",\"disassembly_method\":\"linear sweep from the start address; not execution-verified\",\"system_paused_during_read\":false,\"lines\":[";
	data += lines;
	data += "]}";
	return true;
}

//----------------------------------------------------------------------------------------------------------------------
bool ExodusMcpPlugin::BuildCPUControlData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	const std::string action = ParamValue(request.params, "action");
	if (action == "pause")
	{
		GetSystemInterface().StopSystem();
		data = "{\"action\":\"pause\",\"system_running\":false}";
		return true;
	}
	if (action == "run")
	{
		GetSystemInterface().RunSystem();
		data = "{\"action\":\"run\",\"system_running\":true}";
		return true;
	}

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

	IDeviceContext* deviceContext = processor->GetDevice()->GetDeviceContext();
	if (deviceContext == 0)
	{
		errorCode = "cpu_not_found";
		errorMessage = "The selected processor is not attached to a device context";
		return false;
	}
	if (action == "step")
	{
		deviceContext->StopSystem();
		deviceContext->ExecuteDeviceStep();
	}
	else if (action == "step_over")
	{
		deviceContext->StopSystem();
		processor->BreakOnStepOverCurrentOpcode();
		deviceContext->RunSystem();
	}
	else if (action == "step_out")
	{
		deviceContext->StopSystem();
		processor->BreakOnStepOutCurrentOpcode();
		deviceContext->RunSystem();
	}
	else
	{
		errorCode = "invalid_params";
		errorMessage = "action must be pause, run, step, step_over, or step_out";
		return false;
	}

	data = "{\"action\":";
	AppendJsonStringAscii(data, action);
	data += ",\"cpu\":";
	AppendJsonStringAscii(data, cpu);
	data += ",\"processor_pc\":";
	AppendNumber(data, TypedGetPC(cpu, *processor));
	data += ",\"system_running\":";
	// Read the live state instead of assuming it: async actions such as
	// step_over/step_out can have their internal break land before this
	// response is built, so the processor may already be paused again.
	data += GetSystemInterface().SystemRunning() ? "true" : "false";
	data += "}";
	return true;
}

//----------------------------------------------------------------------------------------------------------------------
// Maps an IBreakpoint location condition to the wire-name used by the MCP
// tools. Keep in sync with the enum order in IBreakpoint.h.
//----------------------------------------------------------------------------------------------------------------------
static const char* BreakpointConditionName(IBreakpoint::Condition condition)
{
	switch (condition)
	{
	case IBreakpoint::Condition::Greater:
		return "greater";
	case IBreakpoint::Condition::Less:
		return "less";
	case IBreakpoint::Condition::GreaterAndLess:
		return "range";
	case IBreakpoint::Condition::Equal:
	default:
		return "equal";
	}
}

//----------------------------------------------------------------------------------------------------------------------
bool ExodusMcpPlugin::BuildBreakpointSetData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	const std::string cpu = ParamValue(request.params, "cpu");
	bool validName = false;
	IProcessor* processor = FindProcessor(cpu, validName);
	unsigned long long address = 0;
	if (!validName || !ParseUnsigned(ParamValue(request.params, "address"), address))
	{
		errorCode = "invalid_params";
		errorMessage = "cpu must be m68k or z80 and address must be an unsigned integer";
		return false;
	}
	if (processor == 0 || address > processor->GetAddressBusMask())
	{
		errorCode = "invalid_params";
		errorMessage = "address is outside the selected processor address bus";
		return false;
	}

	// Optional location condition: equal (default), greater, less, or a range
	// with exclusive bounds (data1 < location < data2). The server validates
	// the same contract; the plugin re-checks so other clients over the wire
	// protocol get the same errors.
	IBreakpoint::Condition condition = IBreakpoint::Condition::Equal;
	const std::string conditionName = ParamValue(request.params, "condition");
	if (conditionName == "greater")
	{
		condition = IBreakpoint::Condition::Greater;
	}
	else if (conditionName == "less")
	{
		condition = IBreakpoint::Condition::Less;
	}
	else if (conditionName == "range")
	{
		condition = IBreakpoint::Condition::GreaterAndLess;
	}
	else if (!conditionName.empty() && conditionName != "equal")
	{
		errorCode = "invalid_params";
		errorMessage = "condition must be equal, greater, less, or range";
		return false;
	}
	unsigned long long rangeEnd = 0;
	const bool hasRangeEnd = ParseUnsigned(ParamValue(request.params, "range_end"), rangeEnd);
	if (condition == IBreakpoint::Condition::GreaterAndLess)
	{
		if (!hasRangeEnd)
		{
			errorCode = "invalid_params";
			errorMessage = "condition=range requires range_end";
			return false;
		}
		if (rangeEnd <= address)
		{
			errorCode = "invalid_params";
			errorMessage = "range_end must be above address (range bounds are exclusive)";
			return false;
		}
	}
	else if (hasRangeEnd)
	{
		errorCode = "invalid_params";
		errorMessage = "range_end applies only to condition=range";
		return false;
	}

	// Optional break-on-counter: pause only on every Nth hit instead of every
	// hit. The emulator core evaluates the live hit counter at break time, so
	// ignored hits never pause the system. ParseUnsigned zeroes its output on
	// failure, so the default must be restored explicitly whenever the
	// parameter is absent.
	const bool breakOnCounter = ParamValue(request.params, "break_on_counter") == "true";
	unsigned long long breakCounter = 1;
	bool hasBreakCounter = false;
	const std::string breakCounterParam = ParamValue(request.params, "break_counter");
	if (!breakCounterParam.empty())
	{
		if (!ParseUnsigned(breakCounterParam, breakCounter))
		{
			errorCode = "invalid_params";
			errorMessage = "break_counter must be an unsigned integer";
			return false;
		}
		hasBreakCounter = true;
	}
	if (breakOnCounter)
	{
		if (hasBreakCounter && breakCounter == 0)
		{
			errorCode = "invalid_params";
			errorMessage = "break_counter must be at least 1";
			return false;
		}
		if (!hasBreakCounter)
		{
			breakCounter = 1;
		}
	}
	else if (hasBreakCounter)
	{
		errorCode = "invalid_params";
		errorMessage = "break_counter applies only when break_on_counter is true";
		return false;
	}

	IBreakpoint* breakpoint = processor->CreateBreakpoint();
	if (breakpoint == 0 || !processor->LockBreakpoint(breakpoint))
	{
		errorCode = "breakpoint_error";
		errorMessage = "Exodus could not create a breakpoint";
		return false;
	}
	breakpoint->SetEnabled(true);
	breakpoint->SetLogEvent(false);
	breakpoint->SetBreakEvent(true);
	breakpoint->SetLocationCondition(condition);
	breakpoint->SetLocationConditionData1((unsigned int)address);
	breakpoint->SetLocationMask(processor->GetAddressBusMask());
	if (condition == IBreakpoint::Condition::GreaterAndLess)
	{
		breakpoint->SetLocationConditionData2((unsigned int)rangeEnd);
	}
	breakpoint->SetBreakOnCounter(breakOnCounter);
	if (breakOnCounter)
	{
		breakpoint->SetBreakCounter((unsigned int)breakCounter);
	}
	const unsigned long long breakpointID = _nextBreakpointID++;
	breakpoint->SetName(L"MCP breakpoint " + std::to_wstring(breakpointID));
	processor->UnlockBreakpoint(breakpoint);

	ManagedBreakpoint managed;
	managed.processor = processor;
	managed.breakpoint = breakpoint;
	managed.cpu = cpu;
	_managedBreakpoints[breakpointID] = managed;
	data = "{\"breakpoint_id\":";
	AppendNumber(data, breakpointID);
	data += ",\"cpu\":";
	AppendJsonStringAscii(data, cpu);
	data += ",\"address\":";
	AppendNumber(data, address);
	data += ",\"condition\":";
	AppendJsonStringAscii(data, BreakpointConditionName(condition));
	data += ",\"range_end\":";
	AppendNumber(data, condition == IBreakpoint::Condition::GreaterAndLess ? rangeEnd : 0);
	data += ",\"break_on_counter\":";
	data += breakOnCounter ? "true" : "false";
	data += ",\"break_counter\":";
	AppendNumber(data, breakCounter);
	data += "}";
	return true;
}

//----------------------------------------------------------------------------------------------------------------------
bool ExodusMcpPlugin::BuildBreakpointListData(const BridgeRequest&, std::string& data, std::string&, std::string&)
{
	data = "{\"breakpoints\":[";
	bool first = true;
	for (std::map<unsigned long long, ManagedBreakpoint>::const_iterator i = _managedBreakpoints.begin(); i != _managedBreakpoints.end(); ++i)
	{
		const ManagedBreakpoint& managed = i->second;
		if (!managed.processor->LockBreakpoint(managed.breakpoint))
		{
			continue;
		}
		if (!first)
		{
			data += ",";
		}
		first = false;
		data += "{\"breakpoint_id\":";
		AppendNumber(data, i->first);
		data += ",\"cpu\":";
		AppendJsonStringAscii(data, managed.cpu);
		data += ",\"address\":";
		AppendNumber(data, managed.breakpoint->GetLocationConditionData1());
		data += ",\"condition\":";
		AppendJsonStringAscii(data, BreakpointConditionName(managed.breakpoint->GetLocationCondition()));
		data += ",\"range_end\":";
		AppendNumber(data, managed.breakpoint->GetLocationConditionData2());
		data += ",\"break_on_counter\":";
		data += managed.breakpoint->GetBreakOnCounter() ? "true" : "false";
		data += ",\"break_counter\":";
		// Report the effective default (1) when the feature is off; the core
		// stores 0 for that state, which would contradict the set echo.
		AppendNumber(data, managed.breakpoint->GetBreakOnCounter() ? managed.breakpoint->GetBreakCounter() : 1);
		data += ",\"enabled\":";
		data += managed.breakpoint->GetEnabled() ? "true" : "false";
		data += ",\"hit_count\":";
		AppendNumber(data, managed.breakpoint->GetHitCounter());
		data += "}";
		managed.processor->UnlockBreakpoint(managed.breakpoint);
	}
	data += "]}";
	return true;
}

//----------------------------------------------------------------------------------------------------------------------
bool ExodusMcpPlugin::BuildBreakpointRemoveData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	unsigned long long breakpointID = 0;
	if (!ParseUnsigned(ParamValue(request.params, "breakpoint_id"), breakpointID))
	{
		errorCode = "invalid_params";
		errorMessage = "breakpoint_id must be an unsigned integer";
		return false;
	}
	std::map<unsigned long long, ManagedBreakpoint>::iterator found = _managedBreakpoints.find(breakpointID);
	if (found == _managedBreakpoints.end())
	{
		errorCode = "breakpoint_not_found";
		errorMessage = "No MCP-managed breakpoint has that id";
		return false;
	}
	found->second.processor->DeleteBreakpoint(found->second.breakpoint);
	_managedBreakpoints.erase(found);
	data = "{\"removed\":true,\"breakpoint_id\":";
	AppendNumber(data, breakpointID);
	data += "}";
	return true;
}

//----------------------------------------------------------------------------------------------------------------------
bool ExodusMcpPlugin::BuildWatchpointSetData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	const std::string cpu = ParamValue(request.params, "cpu");
	bool validName = false;
	IProcessor* processor = FindProcessor(cpu, validName);
	unsigned long long address = 0;
	unsigned long long length = 1;
	const bool validAddress = ParseUnsigned(ParamValue(request.params, "address"), address);
	const std::string lengthParam = ParamValue(request.params, "length");
	const bool validLength = lengthParam.empty() || ParseUnsigned(lengthParam, length);
	std::string access = ParamValue(request.params, "access");
	if (access.empty())
	{
		access = "any";
	}
	if (!validName || !validAddress || !validLength || (access != "read" && access != "write" && access != "any"))
	{
		errorCode = "invalid_params";
		errorMessage = "cpu must be m68k or z80, address and length must be unsigned integers, and access must be read, write, or any";
		return false;
	}
	if (length == 0)
	{
		errorCode = "invalid_params";
		errorMessage = "length must be at least 1";
		return false;
	}
	if (processor == 0 || address > processor->GetAddressBusMask() || (address + length - 1) > processor->GetAddressBusMask())
	{
		errorCode = "invalid_params";
		errorMessage = "watched range is outside the selected processor address bus";
		return false;
	}

	IWatchpoint* watchpoint = processor->CreateWatchpoint();
	if (watchpoint == 0 || !processor->LockWatchpoint(watchpoint))
	{
		errorCode = "watchpoint_error";
		errorMessage = "Exodus could not create a watchpoint";
		return false;
	}
	watchpoint->SetEnabled(true);
	watchpoint->SetLogEvent(false);
	watchpoint->SetBreakEvent(true);
	watchpoint->SetOnRead(access == "read" || access == "any");
	watchpoint->SetOnWrite(access == "write" || access == "any");
	watchpoint->SetLocationMask(processor->GetAddressBusMask());
	if (length == 1)
	{
		watchpoint->SetLocationCondition(IWatchpoint::Condition::Equal);
		watchpoint->SetLocationConditionData1((unsigned int)address);
	}
	else
	{
		// Exodus range conditions are strict (location > data1 && location < data2),
		// so an inclusive [address, address+length-1] range needs the neighbors.
		// A range starting at 0 cannot be expressed because data1 would wrap.
		watchpoint->SetLocationCondition(IWatchpoint::Condition::GreaterAndLess);
		watchpoint->SetLocationConditionData1((unsigned int)(address - 1));
		watchpoint->SetLocationConditionData2((unsigned int)(address + length));
	}
	const unsigned long long watchpointID = _nextWatchpointID++;
	watchpoint->SetName(L"MCP watchpoint " + std::to_wstring(watchpointID));
	processor->UnlockWatchpoint(watchpoint);

	ManagedWatchpoint managed;
	managed.processor = processor;
	managed.watchpoint = watchpoint;
	managed.cpu = cpu;
	managed.address = address;
	managed.length = length;
	managed.access = (access == "read") ? "read" : ((access == "write") ? "write" : "any");
	_managedWatchpoints[watchpointID] = managed;
	data = "{\"watchpoint_id\":";
	AppendNumber(data, watchpointID);
	data += ",\"cpu\":";
	AppendJsonStringAscii(data, cpu);
	data += ",\"address\":";
	AppendNumber(data, address);
	data += ",\"length\":";
	AppendNumber(data, length);
	data += ",\"access\":";
	AppendJsonStringAscii(data, managed.access);
	data += ",\"break_on_hit\":true}";
	return true;
}

//----------------------------------------------------------------------------------------------------------------------
bool ExodusMcpPlugin::BuildWatchpointListData(const BridgeRequest&, std::string& data, std::string&, std::string&)
{
	data = "{\"watchpoints\":[";
	bool first = true;
	for (std::map<unsigned long long, ManagedWatchpoint>::const_iterator i = _managedWatchpoints.begin(); i != _managedWatchpoints.end(); ++i)
	{
		const ManagedWatchpoint& managed = i->second;
		if (!managed.processor->LockWatchpoint(managed.watchpoint))
		{
			continue;
		}
		if (!first)
		{
			data += ",";
		}
		first = false;
		data += "{\"watchpoint_id\":";
		AppendNumber(data, i->first);
		data += ",\"cpu\":";
		AppendJsonStringAscii(data, managed.cpu);
		data += ",\"address\":";
		AppendNumber(data, managed.address);
		data += ",\"length\":";
		AppendNumber(data, managed.length);
		data += ",\"access\":";
		AppendJsonStringAscii(data, managed.access);
		data += ",\"enabled\":";
		data += managed.watchpoint->GetEnabled() ? "true" : "false";
		data += ",\"hit_count\":";
		AppendNumber(data, managed.watchpoint->GetHitCounter());
		data += "}";
		managed.processor->UnlockWatchpoint(managed.watchpoint);
	}
	data += "]}";
	return true;
}

//----------------------------------------------------------------------------------------------------------------------
bool ExodusMcpPlugin::BuildWatchpointRemoveData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	unsigned long long watchpointID = 0;
	if (!ParseUnsigned(ParamValue(request.params, "watchpoint_id"), watchpointID))
	{
		errorCode = "invalid_params";
		errorMessage = "watchpoint_id must be an unsigned integer";
		return false;
	}
	std::map<unsigned long long, ManagedWatchpoint>::iterator found = _managedWatchpoints.find(watchpointID);
	if (found == _managedWatchpoints.end())
	{
		errorCode = "watchpoint_not_found";
		errorMessage = "No MCP-managed watchpoint has that id";
		return false;
	}
	found->second.processor->DeleteWatchpoint(found->second.watchpoint);
	_managedWatchpoints.erase(found);
	data = "{\"removed\":true,\"watchpoint_id\":";
	AppendNumber(data, watchpointID);
	data += "}";
	return true;
}

//----------------------------------------------------------------------------------------------------------------------
bool ExodusMcpPlugin::BuildROMLoadData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	std::wstring romPath;
	if (!Utf8ToWide(ParamValue(request.params, "path"), romPath))
	{
		errorCode = "invalid_params";
		errorMessage = "path must be valid UTF-8";
		return false;
	}

	std::wstring modulePath;
	unsigned long long romSize = 0;
	unsigned int romPaddedSize = 0;
	if (!CreateROMModule(romPath, modulePath, romSize, romPaddedSize))
	{
		errorCode = "rom_load_failed";
		errorMessage = "ROM path must name an existing file no larger than 16 MiB";
		return false;
	}

	ISystemExtensionInterface& system = GetSystemInterface();
	IGUIExtensionInterface& gui = GetGUIInterface();
	const bool wasRunning = system.SystemRunning();
	const bool runAfterLoad = wasRunning || (ParamValue(request.params, "run") == "true");
	PurgeManagedDebugState();
	system.StopSystem();

	const std::list<unsigned int> moduleIDs = system.GetLoadedModuleIDs();
	for (std::list<unsigned int>::const_iterator i = moduleIDs.begin(); i != moduleIDs.end(); ++i)
	{
		LoadedModuleInfo moduleInfo;
		if (system.GetLoadedModuleInfo(*i, moduleInfo) && moduleInfo.GetIsProgramModule())
		{
			gui.UnloadModule(*i);
		}
	}

	system.FlagInitialize();
	if (!gui.LoadModuleFromFile(modulePath))
	{
		if (runAfterLoad)
		{
			system.RunSystem();
		}
		errorCode = "rom_load_failed";
		errorMessage = "Exodus could not load the generated ROM module";
		return false;
	}
	if (runAfterLoad)
	{
		system.RunSystem();
	}

	_romLoaded = true;
	_romPath = romPath;
	_romSizeBytes = romSize;
	_romPaddedSizeBytes = romPaddedSize;

	data = "{\"loaded\":true,\"path\":";
	AppendJsonString(data, romPath);
	data += ",\"module_path\":";
	AppendJsonString(data, modulePath);
	data += ",\"size_bytes\":";
	AppendNumber(data, romSize);
	data += ",\"padded_size_bytes\":";
	AppendNumber(data, romPaddedSize);
	data += ",\"system_running\":";
	data += runAfterLoad ? "true" : "false";
	data += "}";
	return true;
}

// SEH wrapper around the trace capture body. The emulator has a history of
// access violations inside trace capture paths (the original crash motivated
// the flag-toggle workaround), so every entry into this code runs guarded and
// reports the faulting module instead of killing the process.
DWORD ExodusMcpPlugin::TraceCaptureGuarded(ExodusMcpPlugin* plugin, const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage, bool& success, void** faultingAddress)
{
	__try
	{
		success = plugin->TraceCaptureInner(request, data, errorCode, errorMessage);
		return 0;
	}
	__except (CaptureFault(GetExceptionInformation()->ExceptionRecord->ExceptionAddress, faultingAddress))
	{
		return GetExceptionCode();
	}
}

//----------------------------------------------------------------------------------------------------------------------
bool ExodusMcpPlugin::BuildTraceCaptureData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	void* faultingAddress = 0;
	bool success = false;
	const DWORD faultCode = TraceCaptureGuarded(this, request, data, errorCode, errorMessage, success, &faultingAddress);
	if (faultCode != 0)
	{
		errorCode = "trace_capture_fault";
		errorMessage = DescribeCaughtException(faultingAddress, faultCode);
		return false;
	}
	return success;
}

//----------------------------------------------------------------------------------------------------------------------
bool ExodusMcpPlugin::TraceCaptureInner(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	std::string cpu = ParamValue(request.params, "cpu");

	// Event-driven mode: an optional watchpoint_id turns the managed
	// watchpoint into the capture stop condition. The processor and cpu are
	// taken from that watchpoint (the request cpu may stay empty and is only
	// validated, when present, against the watchpoint's cpu).
	unsigned long long watchpointID = 0;
	const bool watchpointMode = ParseUnsigned(ParamValue(request.params, "watchpoint_id"), watchpointID);
	ManagedWatchpoint* triggerWatchpoint = 0;
	IProcessor* processor = 0;
	if (watchpointMode)
	{
		std::map<unsigned long long, ManagedWatchpoint>::iterator found = _managedWatchpoints.find(watchpointID);
		if (found == _managedWatchpoints.end())
		{
			errorCode = "invalid_params";
			errorMessage = "unknown watchpoint_id " + NumberToString(watchpointID) + ": list managed watchpoints with watchpoint_list";
			return false;
		}
		triggerWatchpoint = &found->second;
		processor = triggerWatchpoint->processor;
		if (processor == 0)
		{
			errorCode = "watchpoint_error";
			errorMessage = "the watchpoint no longer references a live processor";
			return false;
		}
		if (!cpu.empty() && _stricmp(cpu.c_str(), triggerWatchpoint->cpu.c_str()) != 0)
		{
			errorCode = "invalid_params";
			errorMessage = "watchpoint_id " + NumberToString(watchpointID) + " watches cpu " + triggerWatchpoint->cpu + ", not " + cpu;
			return false;
		}
		cpu = triggerWatchpoint->cpu;
	}
	else
	{
		bool validName = false;
		processor = FindProcessor(cpu, validName);
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

	// force_run makes plain captures resume a parked system for the window
	// (coverage-style tools need entries even when the system was paused).
	// Prior run state is restored at the end.
	const bool forceRun = ParamValue(request.params, "force_run") == "true";

	IProcessor& target = *processor;

	// The whole configuration sequence runs with the system stopped: the CPU
	// worker contends for the same debug mutex our configuration calls take,
	// and debug-state getters have been observed to starve against it while
	// the system runs. Run state is captured first and restored at the end.
	const bool wasRunning = GetSystemInterface().SystemRunning();
	GetSystemInterface().StopSystem();

	// Baseline hit counters for the whole managed set: the event-driven
	// response reports every watchpoint that fired during the window, not
	// just the requested trigger.
	std::map<unsigned long long, unsigned long long> baselineHits;
	if (watchpointMode)
	{
		for (std::map<unsigned long long, ManagedWatchpoint>::const_iterator i = _managedWatchpoints.begin(); i != _managedWatchpoints.end(); ++i)
		{
			IWatchpoint* watchpoint = i->second.watchpoint;
			if (i->second.processor != 0 && i->second.processor->LockWatchpoint(watchpoint))
			{
				baselineHits[i->first] = watchpoint->GetHitCounter();
				i->second.processor->UnlockWatchpoint(watchpoint);
			}
		}
	}

	const bool priorEnabled = target.GetTraceEnabled();
	const bool priorDisassemble = target.GetTraceDisassemble();
	const bool priorToFile = target.IsTraceFileLoggingEnabled();

	// Route trace output through the on-disk trace log. The in-memory ring
	// accessor GetTraceLog returns STL containers with embedded strings
	// through the marshal layer, and unpacking that marshaled return value in
	// this plugin crashed the emulator with an access violation (observed
	// inside Marshal::Ret<...>::operator vector, even on a paused system).
	// The file path crosses the boundary as a plain string, the worker thread
	// writes the entries host-side, and this plugin reads the bytes back
	// itself, so no complex object ever crosses the boundary.
	char tempDir[MAX_PATH] = {0};
	char tempPath[MAX_PATH] = {0};
	if (GetTempPathA(MAX_PATH, tempDir) == 0 || GetTempFileNameA(tempDir, "exmcp", 0, tempPath) == 0)
	{
		if (wasRunning)
		{
			GetSystemInterface().RunSystem();
		}
		errorCode = "trace_capture_failed";
		errorMessage = "Could not create a temporary trace file path";
		return false;
	}
	// The path crosses as plain UTF-8 bytes: SetTraceLoggingFilePath's
	// Marshal::In<std::wstring> parameter does not interoperate with this
	// plugin's template instantiations (the host stored an empty path), so
	// the fork provides a POD-only setter instead.
	target.SetTraceFileLoggingPathAscii(tempPath);
	target.SetTraceFileLoggingEnabled(true);
	target.SetTraceDisassemble(true);
	target.SetTraceEnabled(true);

	// Event-driven mode: keep the trigger watchpoint disarmed during a short
	// warm-up. A resumed system can sit exactly on the watched instruction
	// after a rollback pause, so an instant first hit would otherwise end the
	// capture before any trace entry is committed. The trigger is re-armed
	// between two stopped states (see the capture phases below); the prior
	// enabled state is restored at the end.
	bool priorTriggerEnabled = true;
	if (watchpointMode && triggerWatchpoint != 0 && triggerWatchpoint->processor != 0 &&
		triggerWatchpoint->processor->LockWatchpoint(triggerWatchpoint->watchpoint))
	{
		priorTriggerEnabled = triggerWatchpoint->watchpoint->GetEnabled();
		triggerWatchpoint->watchpoint->SetEnabled(false);
		triggerWatchpoint->processor->UnlockWatchpoint(triggerWatchpoint->watchpoint);
	}

	// Event-driven mode always resumes the system for the capture window even
	// when it was parked: the contract is "run until the watchpoint fires".
	// force_run does the same for plain captures (coverage). Plain mode keeps
	// its established behavior otherwise (entries only accumulate while the
	// system happens to be running). Prior run state is restored at the end
	// in every mode.
	if (wasRunning || watchpointMode || forceRun)
	{
		GetSystemInterface().RunSystem();
	}

	const DWORD startTime = GetTickCount();
	bool timedOut = false;
	bool stopped = false;
	bool pausedDuringWindow = false;
	const unsigned long long warmUpMs = watchpointMode ? ((timeoutMs < 150) ? timeoutMs : 150) : 0;
	unsigned long long lastRunCheck = 0;
	const unsigned long long runCheckInterval = 50;

	// Capture phase one (event-driven only): accumulate trace entries with
	// the trigger disarmed. Sensing stops only on the bridge stop event or
	// the warm-up bound; the overall timeout still covers the whole window.
	if (warmUpMs > 0)
	{
		while (true)
		{
			if ((GetTickCount() - startTime) >= warmUpMs)
			{
				break;
			}
			if (WaitForSingleObject(_stopEvent, 10) == WAIT_OBJECT_0)
			{
				stopped = true;
				break;
			}
		}
	}

	// Re-arm the trigger between stopped states: every watchpoint API call
	// takes the debug mutex, and those getters have been observed to starve
	// while the CPU worker runs (see TRACE-CRASH-INVESTIGATION.md). With the
	// system parked the lock is uncontended, so the arming is deterministic.
	if (!stopped && watchpointMode)
	{
		GetSystemInterface().StopSystem();
		if (triggerWatchpoint != 0 && triggerWatchpoint->processor != 0 &&
			triggerWatchpoint->processor->LockWatchpoint(triggerWatchpoint->watchpoint))
		{
			triggerWatchpoint->watchpoint->SetEnabled(true);
			triggerWatchpoint->processor->UnlockWatchpoint(triggerWatchpoint->watchpoint);
		}
		GetSystemInterface().RunSystem();
	}

	// Capture phase two: sense the trigger. SystemRunning is cheap; the 50 ms
	// cadence plus a 30 ms post-arm grace keeps the poll from tripping on the
	// worker spin-up after RunSystem.
	while (!stopped && !timedOut)
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
		if (watchpointMode)
		{
			const unsigned long long elapsed = GetTickCount() - startTime;
			if ((elapsed - lastRunCheck) >= runCheckInterval && (elapsed - warmUpMs) >= 30)
			{
				lastRunCheck = elapsed;
				if (!GetSystemInterface().SystemRunning())
				{
					pausedDuringWindow = true;
					break;
				}
			}
		}
	}

	GetSystemInterface().StopSystem();
	target.SetTraceEnabled(priorEnabled);
	target.SetTraceDisassemble(priorDisassemble);
	// Disabling the file log closes the stream, flushing any pending entries
	// the worker had queued for the next commit.
	target.SetTraceFileLoggingEnabled(priorToFile);
	if (watchpointMode && triggerWatchpoint != 0 && triggerWatchpoint->processor != 0 &&
		triggerWatchpoint->processor->LockWatchpoint(triggerWatchpoint->watchpoint))
	{
		triggerWatchpoint->watchpoint->SetEnabled(priorTriggerEnabled);
		triggerWatchpoint->processor->UnlockWatchpoint(triggerWatchpoint->watchpoint);
	}

	// Parse the trace file: the worker writes one ASCII line per entry as
	// 0xADDR(hex) \t opcode \t args \t ;comment \t cycle(decimal) \t time.
	std::ifstream traceFile(tempPath, std::ios::binary);
	std::vector<std::string> entryAddresses;
	std::vector<std::string> entryOpcodes;
	std::vector<std::string> entryArgs;
	std::vector<unsigned long long> entryCycles;
	if (traceFile)
	{
		std::string content((std::istreambuf_iterator<char>(traceFile)), std::istreambuf_iterator<char>());
		size_t lineStart = 0;
		while (lineStart < content.size())
		{
			size_t lineEnd = content.find('\n', lineStart);
			if (lineEnd == std::string::npos)
			{
				lineEnd = content.size();
			}
			std::string line = content.substr(lineStart, lineEnd - lineStart);
			lineStart = lineEnd + 1;
			if (!line.empty() && line[line.size() - 1] == '\r')
			{
				line.erase(line.size() - 1);
			}
			if (line.empty())
			{
				continue;
			}
			std::vector<std::string> fields;
			size_t fieldStart = 0;
			while (true)
			{
				size_t tab = line.find('\t', fieldStart);
				if (tab == std::string::npos)
				{
					fields.push_back(line.substr(fieldStart));
					break;
				}
				fields.push_back(line.substr(fieldStart, tab - fieldStart));
				fieldStart = tab + 1;
			}
			if (fields.size() < 6)
			{
				continue;
			}
			const std::string& addressField = fields[0];
			const char* addressBegin = addressField.c_str();
			if (addressBegin[0] == '0' && (addressBegin[1] == 'x' || addressBegin[1] == 'X'))
			{
				addressBegin += 2;
			}
			char* addressEnd = 0;
			unsigned long long address = strtoull(addressBegin, &addressEnd, 16);
			char* cycleEnd = 0;
			unsigned long long cycle = strtoull(fields[4].c_str(), &cycleEnd, 10);
			if (addressEnd == addressBegin || fields[4].empty() || cycleEnd == fields[4].c_str())
			{
				continue;
			}
			char addressText[16] = {0};
			sprintf_s(addressText, sizeof(addressText), "%llX", address);
			entryAddresses.push_back(addressText);
			entryOpcodes.push_back(fields[1]);
			entryArgs.push_back(fields[2]);
			entryCycles.push_back(cycle);
		}
	}
	traceFile.close();

	if (stopped)
	{
		if (wasRunning)
		{
			GetSystemInterface().RunSystem();
		}
		errorCode = "shutting_down";
		errorMessage = "Bridge shutdown interrupted the trace capture";
		return false;
	}

	// Event-driven mode: report every managed watchpoint whose hit counter
	// advanced during the capture window. Computed while the system is still
	// parked, before the pending restore below re-enters the run state.
	std::vector<unsigned long long> watchpointIDsHit;
	// A hit is authoritative from the counter: a watchpoint that fired always
	// pauses the system, so hit counters are the ground truth either way.
	if (watchpointMode)
	{
		for (std::map<unsigned long long, ManagedWatchpoint>::const_iterator i = _managedWatchpoints.begin(); i != _managedWatchpoints.end(); ++i)
		{
			unsigned long long current = 0;
			if (i->second.processor != 0 && i->second.processor->LockWatchpoint(i->second.watchpoint))
			{
				current = i->second.watchpoint->GetHitCounter();
				i->second.processor->UnlockWatchpoint(i->second.watchpoint);
			}
			unsigned long long baseline = 0;
			std::map<unsigned long long, unsigned long long>::const_iterator foundBaseline = baselineHits.find(i->first);
			if (foundBaseline != baselineHits.end())
			{
				baseline = foundBaseline->second;
			}
			if (current > baseline)
			{
				watchpointIDsHit.push_back(i->first);
			}
		}
	}
	const char* stopReason = "timeout";
	if (watchpointMode && pausedDuringWindow)
	{
		stopReason = watchpointIDsHit.empty() ? "pause" : "watchpoint_hit";
	}
	const bool stoppedOnWatchpoint = !watchpointIDsHit.empty();

	const size_t ringTotal = entryAddresses.size();
	// Keep an empty capture file around for inspection; a non-empty one has
	// already been consumed and is deleted.
	if (ringTotal != 0)
	{
		DeleteFileA(tempPath);
	}
	if (wasRunning)
	{
		GetSystemInterface().RunSystem();
	}
	size_t firstIndex = 0;
	if (ringTotal > (size_t)maxEntries)
	{
		firstIndex = ringTotal - (size_t)maxEntries;
	}
	const size_t captured = ringTotal - firstIndex;

	std::string traceText;
	std::string sampleLines;
	const size_t sampleLimit = firstIndex + ((captured < 50) ? captured : 50);
	unsigned int addressCharWidth = target.GetPCCharWidth();
	if (addressCharWidth < 1 || addressCharWidth > 12)
	{
		addressCharWidth = 8;
	}
	for (size_t i = firstIndex; i < ringTotal; ++i)
	{
		char prefix[64] = {0};
		sprintf_s(prefix, sizeof(prefix), "%0*X %llu ", addressCharWidth, (unsigned int)strtoul(entryAddresses[i].c_str(), 0, 16), entryCycles[i]);
		std::string text = prefix + entryOpcodes[i] + " " + entryArgs[i];
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
			AppendNumber(sampleLines, (unsigned long long)strtoul(entryAddresses[i].c_str(), 0, 16));
			sampleLines += ",\"cycle\":";
			AppendNumber(sampleLines, entryCycles[i]);
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
	AppendNumber(data, ringTotal);
	data += ",\"timed_out\":";
	data += timedOut ? "true" : "false";
	data += ",\"duration_ms\":";
	AppendNumber(data, GetTickCount() - startTime);
	data += ",\"capture_channel\":\"trace-file\",";
	if (watchpointMode)
	{
		data += "\"watchpoint_mode\":true,\"watchpoint_id\":";
		AppendNumber(data, watchpointID);
		data += ",\"stopped_on_watchpoint\":";
		data += stoppedOnWatchpoint ? "true" : "false";
		data += ",\"stop_reason\":";
		AppendJsonStringAscii(data, stopReason);
		data += ",\"watchpoint_ids_hit\":[";
		bool firstHit = true;
		for (size_t i = 0; i < watchpointIDsHit.size(); ++i)
		{
			if (!firstHit)
			{
				data += ",";
			}
			firstHit = false;
			AppendNumber(data, watchpointIDsHit[i]);
		}
		data += "],";
		data += "\"event_note\":\"Event-driven capture: the system ran during the window even if it was parked; the trigger watchpoint stayed disarmed through a short warm-up so an instant resume hit cannot truncate the window; the capture stopped on the watchpoint hit (or timeout), and the prior run state was restored.\",";
	}
	data += "\"sampling_note\":\"";
	if (watchpointMode)
	{
		data += "The capture runs the system toward the watchpoint, so entries reflect the instructions that led up to the hit. ";
	}
	else if (forceRun)
	{
		data += "The capture ran the system during the window even if it was parked; the prior run state was restored afterwards. ";
	}
	else
	{
		data += "Entries accumulate only while the system is running; a paused system yields none. ";
	}
	data += "The capture routes the processor trace log through a temporary on-disk file, because unpacking the marshaled in-memory ring across the extension boundary is unsafe for this plugin.\",\"sample\":[";
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
	mcpwire::AppendJsonString(target, ToUtf8(value));
}

void ExodusMcpPlugin::AppendJsonStringAscii(std::string& target, const std::string& value)
{
	mcpwire::AppendJsonString(target, value);
}

std::string ExodusMcpPlugin::Base64Encode(const unsigned char* data, size_t size)
{
	return mcpwire::Base64Encode(data, size);
}

bool ExodusMcpPlugin::Base64Decode(const std::string& input, std::vector<unsigned char>& output)
{
	return mcpwire::Base64Decode(input, output);
}

std::string ExodusMcpPlugin::SanitizeIdentifier(const std::wstring& value)
{
	return mcpwire::SanitizeIdentifier(value);
}

bool ExodusMcpPlugin::ParseUnsigned(const std::string& text, unsigned long long& value)
{
	return mcpwire::ParseUnsigned(text, value);
}

//----------------------------------------------------------------------------------------------------------------------
// Phase 4 command payloads: controlled experimentation under exclusive
// context leases. The Go server enforces the lease; these builders only
// perform the requested emulator mutation.
//----------------------------------------------------------------------------------------------------------------------

bool ExodusMcpPlugin::BuildMemoryWriteData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	const std::string spaceId = ParamValue(request.params, "space");
	unsigned long long requestedAddress = 0;
	unsigned long long length = 0;
	const bool validAddress = ParseUnsigned(ParamValue(request.params, "address"), requestedAddress);
	const bool validLength = ParseUnsigned(ParamValue(request.params, "length"), length);
	if (spaceId.empty() || !validAddress || !validLength)
	{
		errorCode = "invalid_params";
		errorMessage = "mem_write requires space, address, and length parameters";
		return false;
	}
	if (length < 1 || length > kMaxWriteLength)
	{
		errorCode = "length_out_of_range";
		errorMessage = "length must be between 1 and " + NumberToString(kMaxWriteLength) + " bytes";
		return false;
	}

	std::vector<unsigned char> bytes;
	if (!Base64Decode(ParamValue(request.params, "data"), bytes) || bytes.size() != (size_t)length)
	{
		errorCode = "invalid_params";
		errorMessage = "data must be valid base64 matching the declared length";
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
		errorMessage = "Requested range exceeds space " + space->id + " size of " + NumberToString(space->sizeBytes) + " bytes; space spans " +
			HexPadded(0, 6) + "-" + (space->sizeBytes > 0 ? HexPadded(space->sizeBytes - 1, 6) : "unknown");
		return false;
	}

	// Timed-buffer devices (the VDP memory shells) are owned by their worker
	// thread and cannot be written through the debugger path; refuse instead
	// of corrupting their write lists.
	if (space->device != 0 && dynamic_cast<ITimedBufferIntDevice*>(space->device) != 0)
	{
		errorCode = "write_not_supported";
		errorMessage = "space " + spaceId + " is a timed-buffer device and cannot be written through the debugger path";
		return false;
	}

	const bool isBusSpace = (space->kind == "bus");
	unsigned int busMask = 0;
	unsigned long long address = requestedAddress;
	if (isBusSpace)
	{
		busMask = space->processor->GetAddressBusMask();
		if (busMask == 0)
		{
			const unsigned int busWidth = space->processor->GetAddressBusWidth();
			busMask = (busWidth > 0 && busWidth < 32) ? ((1u << busWidth) - 1u) : 0xFFFFFFFFu;
		}
		address &= busMask;
	}
	else if (space->memory == 0)
	{
		errorCode = "write_not_supported";
		errorMessage = "space " + spaceId + " has no writable memory backing";
		return false;
	}

	// Pause around the write so the debug path never races the executing
	// workers, mirroring the timed-buffer read discipline.
	const bool pauseForWrite = GetSystemInterface().SystemRunning();
	if (pauseForWrite)
	{
		GetSystemInterface().StopSystem();
	}

	bool written = true;
	void* faultingAddress = 0;
	DWORD faultCode = 0;
	if (isBusSpace)
	{
		faultCode = WriteBusBytesGuarded(space->processor, busMask, address, length, bytes.empty() ? 0 : &bytes[0], &faultingAddress);
		if (faultCode != 0)
		{
			written = false;
		}
	}
	else
	{
		const unsigned int entrySize = (space->entrySize > 0) ? space->entrySize : 1;
		const bool bigEndian = (strcmp(space->byteOrder, "big-endian") == 0);
		faultCode = WriteMemoryEntriesGuarded(space->memory, entrySize, bigEndian, address, length, bytes.empty() ? 0 : &bytes[0], &faultingAddress);
		if (faultCode != 0)
		{
			written = false;
		}
	}

	if (pauseForWrite)
	{
		GetSystemInterface().RunSystem();
	}

	if (!written)
	{
		errorCode = "write_fault";
		errorMessage = DescribeCaughtException(faultingAddress, faultCode);
		return false;
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
	data += ",\"encoding\":\"base64\",\"consistency\":\"live\",\"written\":\"";
	data += Base64Encode(bytes.empty() ? 0 : &bytes[0], bytes.size());
	data += "\",\"system_paused_during_write\":";
	data += pauseForWrite ? "true" : "false";
	data += "}";
	return true;
}

bool ExodusMcpPlugin::BuildStateSaveData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	std::wstring path;
	if (!Utf8ToWide(ParamValue(request.params, "path"), path) || path.empty())
	{
		errorCode = "invalid_params";
		errorMessage = "path must be a valid UTF-8 Windows file path";
		return false;
	}
	ISystemGUIInterface* gui = FindSystemGUIInterface();
	if (gui == 0)
	{
		errorCode = "state_api_unavailable";
		errorMessage = "The connected Exodus build does not expose the system save-state interface";
		return false;
	}

	// Create the parent directory so the zip writer never fails on a missing
	// folder; only one level is expected (server-side per-context folders).
	const size_t separator = path.find_last_of(L"\\/");
	if (separator != std::wstring::npos)
	{
		const std::wstring directory = path.substr(0, separator);
		if (!CreateDirectoryW(directory.c_str(), 0) && GetLastError() != ERROR_ALREADY_EXISTS)
		{
			errorCode = "state_save_failed";
			errorMessage = "Could not create snapshot directory";
			return false;
		}
	}

	if (!gui->SaveState(path, ISystemGUIInterface::FileType::ZIP, false))
	{
		errorCode = "state_save_failed";
		errorMessage = "Exodus could not save the system state to the requested path";
		return false;
	}
	data = "{\"saved\":true,\"file_type\":\"zip\",\"system_running\":";
	data += GetSystemInterface().SystemRunning() ? "true" : "false";
	data += "}";
	return true;
}

bool ExodusMcpPlugin::BuildStateLoadData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	std::wstring path;
	if (!Utf8ToWide(ParamValue(request.params, "path"), path) || path.empty())
	{
		errorCode = "invalid_params";
		errorMessage = "path must be a valid UTF-8 Windows file path";
		return false;
	}
	ISystemGUIInterface* gui = FindSystemGUIInterface();
	if (gui == 0)
	{
		errorCode = "state_api_unavailable";
		errorMessage = "The connected Exodus build does not expose the system save-state interface";
		return false;
	}
	if (!gui->LoadState(path, ISystemGUIInterface::FileType::ZIP, false))
	{
		errorCode = "state_load_failed";
		errorMessage = "Exodus could not load the system state from the requested path";
		return false;
	}
	data = "{\"loaded\":true,\"file_type\":\"zip\",\"system_running\":";
	data += GetSystemInterface().SystemRunning() ? "true" : "false";
	data += "}";
	return true;
}

bool ExodusMcpPlugin::BuildFrameAdvanceData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	unsigned long long frames = 1;
	if (!ParamValue(request.params, "frames").empty() && !ParseUnsigned(ParamValue(request.params, "frames"), frames))
	{
		errorCode = "invalid_params";
		errorMessage = "frames must be an unsigned integer";
		return false;
	}
	if (frames < 1 || frames > kMaxFrameAdvance)
	{
		errorCode = "invalid_params";
		errorMessage = "frames must be between 1 and " + NumberToString(kMaxFrameAdvance);
		return false;
	}

	IS315_5313* vdp = FindVdp();
	if (vdp == 0)
	{
		errorCode = "vdp_not_found";
		errorMessage = "No Mega Drive VDP (315-5313) device is present in the loaded target";
		return false;
	}

	GetSystemInterface().StopSystem();
	unsigned long long completed = 0;
	for (unsigned long long frame = 0; frame < frames; ++frame)
	{
		const unsigned int tokenBefore = vdp->GetImageLastRenderedFrameToken();
		GetSystemInterface().RunSystem();
		bool advanced = false;
		// One rendered frame takes about 16.7 ms at 60 Hz; wait up to two
		// seconds per frame so a halted display (blank screen at boot) times
		// out with a clear error instead of spinning forever.
		for (int attempt = 0; attempt < 2000; ++attempt)
		{
			if (vdp->GetImageLastRenderedFrameToken() != tokenBefore)
			{
				advanced = true;
				break;
			}
			Sleep(1);
		}
		GetSystemInterface().StopSystem();
		if (!advanced)
		{
			errorCode = "frame_timeout";
			errorMessage = "The VDP did not render a new frame within 2000 ms; the display may be disabled or the system halted. Completed " + NumberToString(completed) + " of " + NumberToString(frames) + " requested frames";
			return false;
		}
		++completed;
	}

	data = "{\"frames_requested\":";
	AppendNumber(data, frames);
	data += ",\"frames_completed\":";
	AppendNumber(data, completed);
	data += ",\"frame_token\":";
	AppendNumber(data, vdp->GetImageLastRenderedFrameToken());
	data += ",\"system_running\":false}";
	return true;
}

bool ExodusMcpPlugin::BuildInputSetData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	const std::string state = ParamValue(request.params, "state");
	if (state != "down" && state != "up")
	{
		errorCode = "invalid_params";
		errorMessage = "state must be down or up";
		return false;
	}
	unsigned long long player = 1;
	if (!ParamValue(request.params, "player").empty() && !ParseUnsigned(ParamValue(request.params, "player"), player))
	{
		errorCode = "invalid_params";
		errorMessage = "player must be an unsigned integer";
		return false;
	}
	if (player < 1 || player > 4)
	{
		errorCode = "invalid_params";
		errorMessage = "player must be between 1 and 4";
		return false;
	}
	const std::string buttonsParam = ParamValue(request.params, "buttons");
	if (buttonsParam.empty())
	{
		errorCode = "invalid_params";
		errorMessage = "buttons must name at least one button";
		return false;
	}

	// Collect the controller devices in instance order; the Nth controller
	// answers player port N.
	const std::list<IDevice*> devices = GetSystemInterface().GetLoadedDevices();
	std::vector<IDevice*> controllers;
	for (std::list<IDevice*>::const_iterator i = devices.begin(); i != devices.end(); ++i)
	{
		if (dynamic_cast<MDControl3*>(*i) != 0 || dynamic_cast<MDControl6*>(*i) != 0)
		{
			controllers.push_back(*i);
		}
	}
	if (player > controllers.size())
	{
		errorCode = "controller_not_found";
		errorMessage = "No controller device is connected to player port " + NumberToString(player);
		return false;
	}
	IDevice* controller = controllers[(size_t)(player - 1)];

	// Split the comma-separated button list and capitalize each name to match
	// the key code vocabulary (Up, Down, Left, Right, A, B, C, Start, X, Y,
	// Z, Mode).
	std::vector<std::string> buttons;
	std::string remaining = buttonsParam;
	while (!remaining.empty())
	{
		const size_t comma = remaining.find(',');
		const std::string button = (comma == std::string::npos) ? remaining : remaining.substr(0, comma);
		if (!button.empty())
		{
			buttons.push_back(button);
		}
		remaining = (comma == std::string::npos) ? std::string() : remaining.substr(comma + 1);
	}
	if (buttons.empty() || buttons.size() > kMaxInputButtons)
	{
		errorCode = "invalid_params";
		errorMessage = "buttons must name between 1 and " + NumberToString(kMaxInputButtons) + " buttons";
		return false;
	}

	std::string applied;
	for (size_t i = 0; i < buttons.size(); ++i)
	{
		const std::string& raw = buttons[i];
		std::wstring keyName;
		keyName += (raw.size() >= 1) ? (wchar_t)(unsigned char)toupper((unsigned char)raw[0]) : L'\0';
		for (size_t c = 1; c < raw.size(); ++c)
		{
			keyName += (wchar_t)(unsigned char)tolower((unsigned char)raw[c]);
		}
		const unsigned int keyCodeID = controller->GetKeyCodeID(keyName);
		if (keyCodeID == 0)
		{
			errorCode = "invalid_params";
			errorMessage = "Unknown button: " + raw;
			return false;
		}
		if (state == "down")
		{
			controller->HandleInputKeyDown(keyCodeID);
		}
		else
		{
			controller->HandleInputKeyUp(keyCodeID);
		}
		if (!applied.empty())
		{
			applied += ",";
		}
		applied += raw;
	}

	data = "{\"player\":";
	AppendNumber(data, player);
	data += ",\"buttons\":[";
	AppendJsonStringAscii(data, applied);
	data += "],\"state\":";
	AppendJsonStringAscii(data, state);
	data += ",\"controller_instance\":";
	AppendJsonString(data, controller->GetDeviceInstanceName());
	data += ",\"button_count\":";
	AppendNumber(data, buttons.size());
	data += "}";
	return true;
}

bool ExodusMcpPlugin::BuildSoundStatusData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage)
{
	std::string component = ParamValue(request.params, "component");
	if (component.empty()) component = "both";
	if (component != "both" && component != "ym2612" && component != "psg") { errorCode = "invalid_params"; errorMessage = "component must be ym2612, psg, or both"; return false; }
	IYM2612* ym = 0; ISN76489* psg = 0;
	const std::list<IDevice*> devices = GetSystemInterface().GetLoadedDevices();
	for (std::list<IDevice*>::const_iterator i = devices.begin(); i != devices.end(); ++i) { if (!ym && component != "psg") ym = dynamic_cast<IYM2612*>(*i); if (!psg && component != "ym2612") psg = dynamic_cast<ISN76489*>(*i); }
	data = "{\"component\":"; AppendJsonStringAscii(data, component); data += ",\"byte_order\":\"not-applicable\",\"address_space\":\"device-state\",\"devices\":{\"ym2612\":{\"available\":"; data += ym ? "true" : "false";
	if (ym) {
		data += ",\"device\":\"YM2612\",\"registers\":[";
		for (unsigned int r=0;r<IYM2612::RegisterCountTotal;++r) { if(r)data+=","; data+="{\"register\":"; AppendNumber(data,r); data+=",\"value\":"; AppendNumber(data,ym->GetRegisterData(r)); data+="}"; }
		data += "],\"channels\":[";
		for (unsigned int c=0;c<IYM2612::ChannelCount;++c) { if(c)data+=","; data+="{\"channel\":"; AppendNumber(data,c); data+=",\"f_number\":"; AppendNumber(data,ym->GetFrequencyData(c)); data+=",\"block\":"; AppendNumber(data,ym->GetBlockData(c)); data+=",\"algorithm\":"; AppendNumber(data,ym->GetAlgorithmData(c)); data+=",\"feedback\":"; AppendNumber(data,ym->GetFeedbackData(c)); data+=",\"pan\":{\"left\":"; data+=ym->GetOutputLeft(c)?"true":"false"; data+=",\"right\":"; data+=ym->GetOutputRight(c)?"true":"false"; data+="},\"operators\":[";
			for(unsigned int o=0;o<IYM2612::OperatorCount;++o) { if(o)data+=","; data+="{\"operator\":"; AppendNumber(data,o); data+=",\"key_on\":"; data+=ym->GetKeyState(c,o)?"true":"false"; data+=",\"total_level\":"; AppendNumber(data,ym->GetTotalLevelData(c,o)); data+=",\"detune\":"; AppendNumber(data,ym->GetDetuneData(c,o)); data+=",\"multiple\":"; AppendNumber(data,ym->GetMultipleData(c,o)); data+=",\"envelope\":{"; data+="\"attack_rate\":"; AppendNumber(data,ym->GetAttackRateData(c,o)); data+=",\"decay_rate\":"; AppendNumber(data,ym->GetDecayRateData(c,o)); data+=",\"sustain_rate\":"; AppendNumber(data,ym->GetSustainRateData(c,o)); data+=",\"sustain_level\":"; AppendNumber(data,ym->GetSustainLevelData(c,o)); data+=",\"release_rate\":"; AppendNumber(data,ym->GetReleaseRateData(c,o)); data+="}}"; }
			data += "]}";
		}
		data += "],\"dac\":{\"enabled\":"; data+=ym->GetDACEnabled()?"true":"false"; data+=",\"value\":"; AppendNumber(data,ym->GetDACData()); data+="}";
	}
	data += "},\"psg\":{\"available\":"; data += psg ? "true" : "false";
	if (psg) { data += ",\"device\":\"PSG\",\"channels\":["; for(unsigned int c=0;c<ISN76489::ChannelCount;++c) { if(c)data+=","; data+="{\"channel\":"; AppendNumber(data,c); data+=",\"tone\":"; AppendNumber(data,psg->GetToneRegisterExternal(c)); data+=",\"volume\":"; AppendNumber(data,psg->GetVolumeRegisterExternal(c)); data+=",\"mute\":"; data+=psg->GetVolumeRegisterExternal(c)>=15?"true":"false"; data+="}"; } data += "],\"noise\":{\"mode\":null,\"mode_observable\":false,\"shift_register\":"; AppendNumber(data,psg->GetNoiseShiftRegisterExternal()); data += "}"; }
	data += "},\"notes\":[\"Raw registers are read-only snapshots.\",\"PSG noise mode is not exposed by the pinned SDK and is reported as null.\"]}}";
	return true;
}
