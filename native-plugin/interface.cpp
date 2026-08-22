#include "DeviceInterface/DeviceInterface.pkg"
#include "ExodusMcpPlugin.h"

IExtension* GetExodusMcpPlugin(const wchar_t* implementationName, const wchar_t* instanceName, unsigned int moduleID)
{
	return static_cast<IExtension*>(new ExodusMcpPlugin(implementationName, instanceName, moduleID));
}

void DeleteExodusMcpPlugin(IExtension* extension)
{
	delete static_cast<ExodusMcpPlugin*>(extension);
}

#ifdef EX_DLLINTERFACE
extern "C" __declspec(dllexport) unsigned int GetInterfaceVersion()
{
	return EXODUS_INTERFACEVERSION;
}

extern "C" __declspec(dllexport) bool GetExtensionEntry(unsigned int entryNo, IExtensionInfo& entry)
{
	if (entryNo != 0)
	{
		return false;
	}
	entry.SetExtensionSettings(
		GetExodusMcpPlugin,
		DeleteExodusMcpPlugin,
		L"Global.ExodusMcp",
		L"ExodusMcpPlugin",
		1,
		L"Copyright (c) 2026 StealthC",
		L"Local authenticated bridge for exodus-mcp.",
		true);
	return true;
}
#endif
