#ifndef EXODUS_MCP_PLUGIN_H
#define EXODUS_MCP_PLUGIN_H

#include "Extension/Extension.pkg"
#include <windows.h>
#include <map>
#include <string>
#include <vector>

class IProcessor;
class IMemory;
class IBreakpoint;
class IWatchpoint;

// ExodusMcpPlugin is the persistent native bridge for exodus-mcp. It is
// read-only in this increment: it never mutates emulator state, loads ROMs,
// injects input, or runs scripts. Commands are serialized by construction,
// because a single pipe thread accepts and processes one connection at a time.
class ExodusMcpPlugin : public Extension
{
public:
	ExodusMcpPlugin(const std::wstring& implementationName, const std::wstring& instanceName, unsigned int moduleID);
	virtual ~ExodusMcpPlugin();

	virtual bool BuildExtension();

private:
	struct BridgeRequest
	{
		std::string id;
		std::string method;
		std::map<std::string, std::string> params;
	};

	struct MemorySpace
	{
		std::string id;
		std::string kind;
		IProcessor* processor;
		IMemory* memory;
		unsigned long long sizeBytes;
		unsigned int entrySize;
		const char* byteOrder;
		std::wstring deviceInstanceName;
		std::wstring deviceDisplayName;
	};

	struct ManagedBreakpoint
	{
		IProcessor* processor;
		IBreakpoint* breakpoint;
		std::string cpu;
	};

	struct ManagedWatchpoint
	{
		IProcessor* processor;
		IWatchpoint* watchpoint;
		std::string cpu;
		unsigned long long address;
		unsigned long long length;
		const char* access;
	};

	// Bridge lifecycle
	bool LoadBridgeConfiguration();
	bool StartBridge();
	void StopBridge();
	void CaptureModuleSnapshot();
	static DWORD WINAPI PipeThreadEntry(void* parameter);
	void PipeThread();
	void HandleConnection(HANDLE pipe, const std::string& requestBody);
	void DrainUntilClientClose(HANDLE pipe, DWORD pipeListeningError);
	bool WaitForRequest(HANDLE pipe, DWORD pipeListeningError, std::string& request);

	// Wire protocol
	bool ParseRequest(const std::string& body, BridgeRequest& request, bool& authorized) const;
	std::string ExecuteCommand(const BridgeRequest& request, bool& ok, std::string& errorCode, std::string& errorMessage);

	// Command payload builders; successful builders return a JSON object body.
	// Failing builders return false with a machine-readable error code.
	std::string BuildStatusData() const;
	std::string BuildEmulatorStatusData();
	std::string BuildSpaceCatalogData();
	bool BuildMemoryReadData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildRegistersData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildDisassemblyData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildCPUControlData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildBreakpointSetData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildBreakpointListData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildBreakpointRemoveData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildWatchpointSetData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildWatchpointListData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildWatchpointRemoveData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildROMLoadData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildTraceCaptureData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);

	// Emulator inspection helpers
	std::vector<MemorySpace> BuildSpaceCatalog();
	const MemorySpace* FindSpace(const std::vector<MemorySpace>& catalog, const std::string& spaceId) const;
	IProcessor* FindProcessor(const std::string& cpuName, bool& validName) const;
	unsigned int TypedGetPC(const std::string& cpuName, IProcessor& target) const;
	void PurgeManagedDebugState();

	// Formatting helpers
	static std::string ToUtf8(const std::wstring& value);
	static void AppendJsonString(std::string& target, const std::wstring& value);
	static void AppendJsonStringAscii(std::string& target, const std::string& value);
	static std::string Base64Encode(const unsigned char* data, size_t size);
	static std::string SanitizeIdentifier(const std::wstring& value);
	static bool ParseUnsigned(const std::string& text, unsigned long long& value);
	bool WriteAll(HANDLE pipe, const std::string& data);

	HANDLE _stopEvent;
	HANDLE _pipeThread;
	std::wstring _pipeName;
	std::wstring _capability;
	unsigned int _loadedModuleCount;
	bool _bridgeEnabled;
	unsigned long long _nextBreakpointID;
	std::map<unsigned long long, ManagedBreakpoint> _managedBreakpoints;
	unsigned long long _nextWatchpointID;
	std::map<unsigned long long, ManagedWatchpoint> _managedWatchpoints;
};

#endif
