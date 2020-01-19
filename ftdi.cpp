#include "ftdi.H"

static HMODULE m_hmodule = 0;
static FT_HANDLE m_ftHandle = 0;

typedef FT_STATUS(WINAPI* PtrToOpen)(PVOID, FT_HANDLE*);
PtrToOpen m_pOpen;

typedef FT_STATUS(WINAPI* PtrToOpenEx)(PVOID, DWORD, FT_HANDLE*);
PtrToOpenEx m_pOpenEx;

typedef FT_STATUS(WINAPI* PtrToListDevices)(PVOID, PVOID, DWORD);
PtrToListDevices m_pListDevices;

typedef FT_STATUS(WINAPI* PtrToClose)(FT_HANDLE);
PtrToClose m_pClose;

typedef FT_STATUS(WINAPI* PtrToRead)(FT_HANDLE, LPVOID, DWORD, LPDWORD);
PtrToRead m_pRead;

typedef FT_STATUS(WINAPI* PtrToWrite)(FT_HANDLE, LPVOID, DWORD, LPDWORD);
PtrToWrite m_pWrite;

typedef FT_STATUS(WINAPI* PtrToResetDevice)(FT_HANDLE);
PtrToResetDevice m_pResetDevice;

typedef FT_STATUS(WINAPI* PtrToPurge)(FT_HANDLE, ULONG);
PtrToPurge m_pPurge;

typedef FT_STATUS(WINAPI* PtrToSetTimeouts)(FT_HANDLE, ULONG, ULONG);
PtrToSetTimeouts m_pSetTimeouts;

typedef FT_STATUS(WINAPI* PtrToGetQueueStatus)(FT_HANDLE, LPDWORD);
PtrToGetQueueStatus m_pGetQueueStatus;

static void AfxMessageBox(const char* str)
{
	MessageBox(0, str, "Error", MB_OK);
}

int LoadFTDI()
{
	if (m_hmodule != 0)
		return 0;

	m_hmodule = LoadLibrary("Ftd2xx.dll");

	if (m_hmodule == NULL)
	{
		
		MessageBox(0, "Error: Can't Load ft8u245.dll", "Error", MB_OK);
		return 1;
	}

	m_pWrite = (PtrToWrite)GetProcAddress(m_hmodule, "FT_Write");
	if (m_pWrite == NULL)
	{
		AfxMessageBox("Error: Can't Find FT_Write");
		return 1;
	}

	m_pRead = (PtrToRead)GetProcAddress(m_hmodule, "FT_Read");
	if (m_pRead == NULL)
	{
		AfxMessageBox("Error: Can't Find FT_Read");
		return 1;
	}

	m_pOpen = (PtrToOpen)GetProcAddress(m_hmodule, "FT_Open");
	if (m_pOpen == NULL)
	{
		AfxMessageBox("Error: Can't Find FT_Open");
		return 1;
	}

	m_pOpenEx = (PtrToOpenEx)GetProcAddress(m_hmodule, "FT_OpenEx");
	if (m_pOpenEx == NULL)
	{
		AfxMessageBox("Error: Can't Find FT_OpenEx");
		return 1;
	}

	m_pListDevices = (PtrToListDevices)GetProcAddress(m_hmodule, "FT_ListDevices");
	if (m_pListDevices == NULL)
	{
		AfxMessageBox("Error: Can't Find FT_ListDevices");
		return 1;
	}

	m_pClose = (PtrToClose)GetProcAddress(m_hmodule, "FT_Close");
	if (m_pClose == NULL)
	{
		AfxMessageBox("Error: Can't Find FT_Close");
		return 1;
	}

	m_pResetDevice = (PtrToResetDevice)GetProcAddress(m_hmodule, "FT_ResetDevice");
	if (m_pResetDevice == NULL)
	{
		AfxMessageBox("Error: Can't Find FT_ResetDevice");
		return 1;
	}

	m_pPurge = (PtrToPurge)GetProcAddress(m_hmodule, "FT_Purge");
	if (m_pPurge == NULL)
	{
		AfxMessageBox("Error: Can't Find FT_Purge");
		return 1;
	}

	m_pSetTimeouts = (PtrToSetTimeouts)GetProcAddress(m_hmodule, "FT_SetTimeouts");
	if (m_pSetTimeouts == NULL)
	{
		AfxMessageBox("Error: Can't Find FT_SetTimeouts");
		return 1;
	}

	m_pGetQueueStatus = (PtrToGetQueueStatus)GetProcAddress(m_hmodule, "FT_GetQueueStatus");
	if (m_pGetQueueStatus == NULL)
	{
		AfxMessageBox("Error: Can't Find FT_GetQueueStatus");
		return 1;
	}
	return 0;
}

FT_STATUS FTDI_Read(LPVOID lpvBuffer, DWORD dwBuffSize, LPDWORD lpdwBytesRead)
{
	if (!m_pRead)
	{
		AfxMessageBox("FT_Read is not valid!");
		return FT_INVALID_HANDLE;
	}

	return (*m_pRead)(m_ftHandle, lpvBuffer, dwBuffSize, lpdwBytesRead);
}

FT_STATUS FTDI_Write(LPVOID lpvBuffer, DWORD dwBuffSize, LPDWORD lpdwBytes)
{
	if (!m_pWrite)
	{
		AfxMessageBox("FT_Write is not valid!");
		return FT_INVALID_HANDLE;
	}

	return (*m_pWrite)(m_ftHandle, lpvBuffer, dwBuffSize, lpdwBytes);
}

FT_STATUS FTDI_Open(PVOID pvDevice)
{
	if (!m_pOpen)
	{
		AfxMessageBox("FT_Open is not valid!");
		return FT_INVALID_HANDLE;
	}

	return (*m_pOpen)(pvDevice, &m_ftHandle);
}

FT_STATUS FTDI_OpenEx(PVOID pArg1, DWORD dwFlags)
{
	if (!m_pOpenEx)
	{
		AfxMessageBox("FT_OpenEx is not valid!");
		return FT_INVALID_HANDLE;
	}

	return (*m_pOpenEx)(pArg1, dwFlags, &m_ftHandle);
}

FT_STATUS FTDI_ListDevices(PVOID pArg1, PVOID pArg2, DWORD dwFlags)
{
	if (!m_pListDevices)
	{
		AfxMessageBox("FT_ListDevices is not valid!");
		return FT_INVALID_HANDLE;
	}

	return (*m_pListDevices)(pArg1, pArg2, dwFlags);
}

FT_STATUS FTDI_Close()
{
	if (!m_pClose)
	{
		AfxMessageBox("FT_Close is not valid!");
		return FT_INVALID_HANDLE;
	}

	return (*m_pClose)(m_ftHandle);
}

FT_STATUS FTDI_ResetDevice()
{
	if (!m_pResetDevice)
	{
		AfxMessageBox("FT_ResetDevice is not valid!");
		return FT_INVALID_HANDLE;
	}

	return (*m_pResetDevice)(m_ftHandle);
}

FT_STATUS FTDI_Purge(ULONG dwMask)
{
	if (!m_pPurge)
	{
		AfxMessageBox("FT_Purge is not valid!");
		return FT_INVALID_HANDLE;
	}

	return (*m_pPurge)(m_ftHandle, dwMask);
}

FT_STATUS FTDI_SetTimeouts(ULONG dwReadTimeout, ULONG dwWriteTimeout)
{
	if (!m_pSetTimeouts)
	{
		AfxMessageBox("FT_SetTimeouts is not valid!");
		return FT_INVALID_HANDLE;
	}

	return (*m_pSetTimeouts)(m_ftHandle, dwReadTimeout, dwWriteTimeout);
}

FT_STATUS FTDI_GetQueueStatus(LPDWORD lpdwAmountInRxQueue)
{
	if (!m_pGetQueueStatus)
	{
		AfxMessageBox("FT_GetQueueStatus is not valid!");
		return FT_INVALID_HANDLE;
	}

	return (*m_pGetQueueStatus)(m_ftHandle, lpdwAmountInRxQueue);
}
