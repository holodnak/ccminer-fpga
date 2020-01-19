#pragma once

#include <Windows.h>
#include "FTD2XX.H"

int LoadFTDI();

FT_STATUS FTDI_Read(LPVOID lpvBuffer, DWORD dwBuffSize, LPDWORD lpdwBytesRead);
FT_STATUS FTDI_Write(LPVOID lpvBuffer, DWORD dwBuffSize, LPDWORD lpdwBytes);
FT_STATUS FTDI_Open(PVOID pvDevice);
FT_STATUS FTDI_OpenEx(PVOID pArg1, DWORD dwFlags);
FT_STATUS FTDI_ListDevices(PVOID pArg1, PVOID pArg2, DWORD dwFlags);
FT_STATUS FTDI_Close();
FT_STATUS FTDI_ResetDevice();
FT_STATUS FTDI_Purge(ULONG dwMask);
FT_STATUS FTDI_SetTimeouts(ULONG dwReadTimeout, ULONG dwWriteTimeout);
FT_STATUS FTDI_GetQueueStatus(LPDWORD lpdwAmountInRxQueue);
