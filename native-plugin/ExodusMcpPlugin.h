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
class IS315_5313;
class IYM2612;
class ISN76489;
class ISystemGUIInterface;
class ISystemResetInterface;

// ExodusMcpPlugin is the persistent native bridge for exodus-mcp. Inspection
// commands are read-only; state-changing commands are narrowly scoped to
// explicitly implemented native operations. Commands are serialized by
// construction, because a single pipe thread accepts and processes one
// connection at a time.
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
		IDevice* device;
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

	struct TraceSessionSegment
	{
		unsigned int index;
		std::wstring path;
		unsigned long long bytes;
		bool sealed;
	};

	struct TraceSessionWatch
	{
		unsigned long long watchpointID;
		std::string cpu;
		unsigned long long address;
		unsigned long long length;
		std::string access;
		unsigned long long baselineHits;
		unsigned long long lastReportedHits;
		bool lost;
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
	static DWORD TraceCaptureGuarded(ExodusMcpPlugin* plugin, const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage, bool& success, void** faultingAddress);
	bool TraceCaptureInner(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildTraceSessionStartData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildTraceSessionStatusData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildTraceSessionDrainData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildTraceSessionStopData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	static DWORD WINAPI TraceSessionThreadEntry(void* parameter);
	void TraceSessionThread();
	void FinishTraceSessionLocked(const std::string& stopReason);
	void SealTraceSessionSegmentLocked(bool closeFile);
	void RotateTraceSessionSegmentLocked(bool rotateAccessStream);
	void ArmTraceSessionTraceLocked();
	void EvictTraceSessionSegmentsLocked();
	bool HasSealedTraceSessionSegmentLocked(unsigned int fromSegment) const;
	void SealTraceSessionAccessSegmentLocked();
	void RotateTraceSessionAccessSegmentLocked();
	void EvictTraceSessionAccessSegmentsLocked();
	bool HasSealedTraceSessionAccessSegmentLocked(unsigned int fromSegment) const;
	void DeleteTraceSessionAccessFilesLocked();
	void AppendTraceSessionAccessJsonLocked(std::string& data);
	bool DrainTraceSessionStreamLocked(const std::vector<TraceSessionSegment>& segments, unsigned int& drainSegment, unsigned long long& drainOffset, unsigned long long maxBytes, std::string& encoded, unsigned int& segmentIndex, unsigned long long& offset, unsigned long long& segmentBytes, unsigned long long& readBytes, bool& done, bool& readFailure);
	std::string BuildTraceSessionStatusJsonLocked(bool consumeWatchDeltas);
	void AppendTraceSessionWatchesJsonLocked(std::string& data, bool consumeDeltas);
	void NoteTraceSessionLocked(const std::string& note);
	void ReleaseTraceSessionWatchesLocked();
	void DeleteTraceSessionFilesLocked();
	void ShutdownTraceSession();
	void ReapTraceSessionThread();
	std::string BuildVdpStatusData();
	std::string BuildVdpCommandDMAStatusData();
	bool BuildVDPMemoryReadData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildVDPPixelInfoData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildFrameCaptureData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildMemoryWriteData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildStateSaveData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildStateLoadData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildFrameAdvanceData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildInputSetData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildSoundStatusData(const BridgeRequest& request, std::string& data, std::string& errorCode, std::string& errorMessage);
	bool BuildSoftResetData(std::string& data, std::string& errorCode, std::string& errorMessage);

	// Emulator inspection helpers
	std::vector<MemorySpace> BuildSpaceCatalog();
	const MemorySpace* FindSpace(const std::vector<MemorySpace>& catalog, const std::string& spaceId) const;
	IProcessor* FindProcessor(const std::string& cpuName, bool& validName) const;
	unsigned int TypedGetPC(const std::string& cpuName, IProcessor& target) const;
	IS315_5313* FindVdp() const;
	void PurgeManagedDebugState();
	ISystemGUIInterface* FindSystemGUIInterface() const;
	ISystemResetInterface* FindSystemResetInterface() const;

	// Formatting helpers
	static std::string ToUtf8(const std::wstring& value);
	static void AppendJsonString(std::string& target, const std::wstring& value);
	static void AppendJsonStringAscii(std::string& target, const std::string& value);
	static std::string Base64Encode(const unsigned char* data, size_t size);
	static bool Base64Decode(const std::string& input, std::vector<unsigned char>& output);
	static std::string SanitizeIdentifier(const std::wstring& value);
	static bool ParseUnsigned(const std::string& text, unsigned long long& value);
	bool WriteAll(HANDLE pipe, const std::string& data);

	HANDLE _stopEvent;
	HANDLE _pipeThread;
	std::wstring _pipeName;
	std::wstring _capability;
	unsigned int _loadedModuleCount;
	bool _bridgeEnabled;
	// The most recent ROM loaded through the bridge (rom_load). emulator_status
	// reports these so server-side tools can bound reads (header parsing,
	// checksums) without mirroring Exodus's own module introspection.
	bool _romLoaded;
	std::wstring _romPath;
	unsigned long long _romSizeBytes;
	unsigned long long _romPaddedSizeBytes;
	unsigned long long _nextBreakpointID;
	std::map<unsigned long long, ManagedBreakpoint> _managedBreakpoints;
	unsigned long long _nextWatchpointID;
	unsigned int _pixelInfoEnableFrameToken;

	// Continuous trace session state. The lock guards the session state
	// machine shared by the pipe thread (start/status/drain/stop) and the
	// monitor thread that arms and seals segments; the processor trace calls
	// it protects are the same ones trace_capture uses.
	CRITICAL_SECTION _traceSessionLock;
	HANDLE _traceSessionStopEvent;
	HANDLE _traceSessionThread;
	bool _traceSessionActive;
	bool _traceSessionCapturing;
	std::string _traceSessionID;
	std::string _traceSessionCPU;
	std::string _traceSessionMode;
	bool _traceSessionDisassemble;
	unsigned long long _traceSessionWindowMs;
	unsigned long long _traceSessionIntervalMs;
	unsigned long long _traceSessionSegmentMs;
	unsigned long long _traceSessionStopAfterVdpFrames;
	unsigned int _traceSessionStartVdpFrameToken;
	unsigned long long _traceSessionMaxTotalBytes;
	unsigned int _traceSessionMaxSegments;
	unsigned long long _traceSessionStartedTick;
	unsigned long long _traceSessionWindowStartTick;
	unsigned long long _traceSessionIntervalStartTick;
	unsigned long long _traceSessionSegmentStartTick;
	unsigned long long _traceSessionWindowsStarted;
	unsigned long long _traceSessionWindowsCompleted;
	unsigned long long _traceSessionBytesWritten;
	unsigned long long _traceSessionEvictedSegments;
	unsigned long long _traceSessionEvictedBytes;
	unsigned long long _traceSessionEvictedUnread;
	unsigned int _traceSessionNextSegment;
	unsigned int _traceSessionDrainSegment;
	unsigned long long _traceSessionDrainOffset;
	std::string _traceSessionStopReason;
	bool _traceSessionAutoStopped;
	bool _traceSessionPriorEnabled;
	bool _traceSessionPriorDisassemble;
	bool _traceSessionPriorFile;
	bool _traceSessionSetupPause;
	bool _traceSessionSetupPausedSystem;
	bool _traceSessionWatchesArmed;
	bool _traceSessionWatchesReleased;
	IProcessor* _traceSessionProcessor;
	std::wstring _traceSessionDir;
	std::vector<TraceSessionSegment> _traceSessionSegments;
	std::vector<TraceSessionWatch> _traceSessionWatches;
	std::vector<std::string> _traceSessionNotes;

	// Per-access read/write capture. The engine writes one line per observed
	// access into rotated segments of its own; the plugin never sees individual
	// records, only sealed files it drains, so a CPU running at full speed can
	// never block on the bridge.
	bool _traceSessionAccessEnabled;
	std::string _traceSessionAccessMode;
	bool _traceSessionAccessIncludeRegisters;
	unsigned long long _traceSessionAccessMaxBytes;
	unsigned long long _traceSessionAccessRecords;
	unsigned long long _traceSessionAccessFailures;
	unsigned long long _traceSessionAccessBytesWritten;
	unsigned long long _traceSessionAccessEvictedSegments;
	unsigned long long _traceSessionAccessEvictedBytes;
	unsigned long long _traceSessionAccessEvictedUnread;
	unsigned int _traceSessionAccessNextSegment;
	unsigned int _traceSessionAccessDrainSegment;
	unsigned long long _traceSessionAccessDrainOffset;
	std::vector<TraceSessionSegment> _traceSessionAccessSegments;
	std::map<unsigned long long, ManagedWatchpoint> _managedWatchpoints;
};

#endif
