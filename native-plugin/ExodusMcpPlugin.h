#ifndef EXODUS_MCP_PLUGIN_H
#define EXODUS_MCP_PLUGIN_H

#include "Extension/Extension.pkg"
#include <windows.h>
#include <string>

// ExodusMcpPlugin is deliberately read-only. It owns a local named-pipe
// endpoint and reports a snapshot captured while Exodus initializes it.
class ExodusMcpPlugin : public Extension
{
public:
	ExodusMcpPlugin(const std::wstring& implementationName, const std::wstring& instanceName, unsigned int moduleID);
	virtual ~ExodusMcpPlugin();

	virtual bool BuildExtension();

private:
	bool LoadBridgeConfiguration();
	bool StartBridge();
	void StopBridge();
	void CaptureModuleSnapshot();
	std::string MakeStatusResponse() const;
	bool AuthorizeStatusRequest(const char* request, DWORD requestLength) const;
	static DWORD WINAPI PipeThreadEntry(void* parameter);
	void PipeThread();

	HANDLE _stopEvent;
	HANDLE _pipeThread;
	std::wstring _pipeName;
	std::wstring _capability;
	unsigned int _loadedModuleCount;
	bool _bridgeEnabled;
};

#endif
