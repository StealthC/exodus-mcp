#include "ExodusMcpPlugin.h"

#include <cstdio>
#include <string>

namespace
{
const char* const kStatusMethod = "method=status";
const char* const kCapabilityPrefix = "capability=";
const char* const kPluginVersion = "0.1.0";

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
		// Loading the extension without bridge configuration is intentional: it
		// must never make a normal Exodus launch fail.
		return true;
	}
	return StartBridge();
}

bool ExodusMcpPlugin::LoadBridgeConfiguration()
{
	return ReadEnvironment(L"EXODUS_MCP_PIPE_NAME", _pipeName) &&
		ReadEnvironment(L"EXODUS_MCP_CAPABILITY", _capability) &&
		_pipeName.compare(0, 9, L"\\\\.\\pipe\\") == 0;
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

std::string ExodusMcpPlugin::MakeStatusResponse() const
{
	char response[256] = {0};
	sprintf_s(response,
		sizeof(response),
		"{\"protocol_version\":1,\"plugin_version\":\"%s\",\"lifecycle\":\"ready\",\"bridge_enabled\":%s,\"loaded_module_count\":%u}\n",
		kPluginVersion,
		_bridgeEnabled ? "true" : "false",
		_loadedModuleCount);
	return response;
}

bool ExodusMcpPlugin::AuthorizeStatusRequest(const char* request, DWORD requestLength) const
{
	const std::string input(request, requestLength);
	std::string capability(kCapabilityPrefix);
	for (std::wstring::const_iterator i = _capability.begin(); i != _capability.end(); ++i)
	{
		// The server generates URL-safe ASCII capabilities. Rejecting any other
		// form prevents a lossy Unicode-to-byte conversion in the wire protocol.
		if (*i > 0x7f)
		{
			return false;
		}
		capability += static_cast<char>(*i);
	}
	return input == capability + "\n" + kStatusMethod + "\n";
}

DWORD WINAPI ExodusMcpPlugin::PipeThreadEntry(void* parameter)
{
	static_cast<ExodusMcpPlugin*>(parameter)->PipeThread();
	return 0;
}

void ExodusMcpPlugin::PipeThread()
{
	while (WaitForSingleObject(_stopEvent, 0) != WAIT_OBJECT_0)
	{
		HANDLE pipe = CreateNamedPipeW(
			_pipeName.c_str(),
			PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT,
			1,
			1024,
			1024,
			0,
			0);
		if (pipe == INVALID_HANDLE_VALUE)
		{
			WaitForSingleObject(_stopEvent, 100);
			continue;
		}

		BOOL connected = ConnectNamedPipe(pipe, 0);
		DWORD connectError = connected ? ERROR_SUCCESS : GetLastError();
		while (!connected && connectError == ERROR_PIPE_LISTENING && WaitForSingleObject(_stopEvent, 10) != WAIT_OBJECT_0)
		{
			connected = ConnectNamedPipe(pipe, 0);
			connectError = connected ? ERROR_SUCCESS : GetLastError();
		}
		if (!connected && connectError == ERROR_PIPE_CONNECTED)
		{
			connected = TRUE;
		}
		if (connected)
		{
			char request[1024] = {0};
			DWORD received = 0;
			while (!ReadFile(pipe, request, sizeof(request), &received, 0) && GetLastError() == ERROR_NO_DATA && WaitForSingleObject(_stopEvent, 10) != WAIT_OBJECT_0)
			{ }
			if (received > 0 && AuthorizeStatusRequest(request, received))
			{
				const std::string response = MakeStatusResponse();
				DWORD sent = 0;
				WriteFile(pipe, response.c_str(), static_cast<DWORD>(response.size()), &sent, 0);
			}
			FlushFileBuffers(pipe);
			DisconnectNamedPipe(pipe);
		}
		CloseHandle(pipe);
	}
}
