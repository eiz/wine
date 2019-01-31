/*
 * Implementation of mscoree.dll
 * Microsoft Component Object Runtime Execution Engine
 *
 * Copyright 2019 Mackenzie Straight
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>
#include <stdio.h>

#define COBJMACROS
#include "wine/unicode.h"
#include "wine/library.h"
#include "windef.h"
#include "winbase.h"
#include "winuser.h"
#include "winnls.h"
#include "winreg.h"
#include "ole2.h"
#include "ocidl.h"
#include "shellapi.h"

#include "cor.h"
#include "mscoree.h"
#include "cordebug.h"
#include "metahost.h"
#include "wine/list.h"
#include "mscoree_private.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(mscoree);

static CRITICAL_SECTION mscoree_ops_lock;
static mscoree_operations *mscoree_ops;
static HMODULE cornative_hModule;
static mscoree_operations cornative_ops;
const static mscoree_operations cormono_ops =
{
    cormono_LoadStringRC,
    cormono_CreateObject,
    cormono_OpenCtrs,
    cormono_CollectCtrs,
    cormono_CloseCtrs,
    cormono_CLRCreateInstance,
    cormono_ClrCreateManagedInstance,
    cormono_CoEEShutDownCOM,
    cormono_CoInitializeCor,
    cormono_CorBindToCurrentRuntime,
    cormono_CorBindToRuntimeEx,
    cormono_CorBindToRuntimeHost,
    cormono_CorExitProcess,
    cormono_CorIsLatestSvc,
    cormono_CreateConfigStream,
    cormono_CreateDebuggingInterfaceFromVersion,
    cormono_CreateInterface,
    cormono_DllCanUnloadNow,
    cormono_DllGetClassObject,
    cormono_DllRegisterServer,
    cormono_DllUnregisterServer,
    cormono_GetAssemblyMDImport,
    cormono_GetCORSystemDirectory,
    cormono_GetCORVersion,
    cormono_GetFileVersion,
    cormono_GetProcessExecutableHeap,
    cormono_GetRealProcAddress,
    cormono_GetRequestedRuntimeInfo,
    cormono_GetRequestedRuntimeVersion,
    cormono_GetVersionFromProcess,
    cormono_LoadLibraryShim,
    cormono_LoadStringRCEx,
    cormono_LockClrVersion,
    NULL, /* ND_CopyObjDst */
    NULL, /* ND_CopyObjSrc */
    NULL, /* ND_RI2 */
    NULL, /* ND_RI4 */
    NULL, /* ND_RI8 */
    NULL, /* ND_RU1 */
    NULL, /* ND_WI2 */
    NULL, /* ND_WI4 */
    NULL, /* ND_WI8 */
    NULL, /* ND_WU1 */
    NULL, /* StrongNameSignatureVerification */
    NULL, /* StrongNameSignatureVerificationEx */
    NULL, /* _CorDllMain */
    NULL, /* _CorExeMain2 */
    cormono__CorExeMain,
};

static inline HRESULT cornative_load_proc(LPCSTR procname, PVOID *ppv)
{
    if (!(*ppv = GetProcAddress(cornative_hModule, procname)))
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    return S_OK;
}

#define CORNATIVE_SYMBOL_EX(name, value) do \
    { \
        hr = cornative_load_proc(value, (PVOID *)&cornative_ops.name); \
        if (!SUCCEEDED(hr)) \
        { \
            TRACE("Failed to load mscoreei symbol " #name " , hr=%x", hr); \
            goto out; \
        } \
    } \
    while (0)
#define CORNATIVE_SYMBOL(name) CORNATIVE_SYMBOL_EX(name, #name)

static HRESULT cornative_load(void)
{
    HRESULT hr = S_OK;
    HANDLE hfind = INVALID_HANDLE_VALUE;
    LSTATUS lst;
    char rootbuf[MAX_PATH];
    char pathbuf[MAX_PATH];
    char versbuf[MAX_PATH];
    DWORD rootlen = sizeof(rootbuf);
    WIN32_FIND_DATAA finddata;

    if (cornative_hModule) goto out;

    /* TODO: use the old-style RegQueryValueExA for down-level compatibility */
    lst = RegGetValueA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\.NETFramework",
        "InstallRoot",
        RRF_RT_REG_SZ,
        NULL,
        (PVOID)rootbuf,
        &rootlen);

    if (lst != ERROR_SUCCESS)
    {
        hr = HRESULT_FROM_WIN32(lst);
        TRACE("couldn't get native CLR install root hr=%x\n", hr);
        goto out;
    }

    memset(versbuf, 0, sizeof(versbuf));
    snprintf(pathbuf, sizeof(pathbuf), "%s\\v*", rootbuf);
    hfind = FindFirstFileA(pathbuf, &finddata);

    if (hfind == INVALID_HANDLE_VALUE)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        TRACE("couldn't open native CLR root %s\n", pathbuf);
        goto out;
    }

    do
    {
        if (strcmp(finddata.cFileName, versbuf) > 0)
        {
            snprintf(versbuf, sizeof(versbuf), "%s", finddata.cFileName);
        }
    }
    while (FindNextFileA(hfind, &finddata));

    if (!*versbuf)
    {
        hr = E_NOTIMPL;
        goto out;
    }

    snprintf(pathbuf, sizeof(pathbuf), "%s\\%s\\mscoreei.dll", rootbuf, versbuf);
    cornative_hModule = LoadLibraryA(pathbuf);

    if (!cornative_hModule)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());

        ERR("failed to load native CLR at %s, hr=%x\n", pathbuf, hr);
        goto out;
    }

    CORNATIVE_SYMBOL(LoadStringRC);
    CORNATIVE_SYMBOL_EX(CreateObject, (LPCSTR)24);
    CORNATIVE_SYMBOL(OpenCtrs);
    CORNATIVE_SYMBOL(CollectCtrs);
    CORNATIVE_SYMBOL(CloseCtrs);
    CORNATIVE_SYMBOL(CLRCreateInstance);
    CORNATIVE_SYMBOL(ClrCreateManagedInstance);
    CORNATIVE_SYMBOL(CoEEShutDownCOM);
    CORNATIVE_SYMBOL(CoInitializeCor);
    CORNATIVE_SYMBOL(CorBindToCurrentRuntime);
    CORNATIVE_SYMBOL(CorBindToRuntimeEx);
    CORNATIVE_SYMBOL(CorBindToRuntimeHost);
    CORNATIVE_SYMBOL(CorExitProcess);
    CORNATIVE_SYMBOL(CorIsLatestSvc);
    CORNATIVE_SYMBOL(CreateConfigStream);
    CORNATIVE_SYMBOL(CreateDebuggingInterfaceFromVersion);
    CORNATIVE_SYMBOL(CreateInterface);
    CORNATIVE_SYMBOL(DllCanUnloadNow);
    CORNATIVE_SYMBOL(DllRegisterServer);
    CORNATIVE_SYMBOL(DllUnregisterServer);
    CORNATIVE_SYMBOL(GetAssemblyMDImport);
    CORNATIVE_SYMBOL(GetCORSystemDirectory);
    CORNATIVE_SYMBOL(GetCORVersion);
    CORNATIVE_SYMBOL(GetFileVersion);
    CORNATIVE_SYMBOL(GetProcessExecutableHeap);
    CORNATIVE_SYMBOL(GetRealProcAddress);
    CORNATIVE_SYMBOL(GetRequestedRuntimeInfo);
    CORNATIVE_SYMBOL(GetRequestedRuntimeVersion);
    CORNATIVE_SYMBOL(GetVersionFromProcess);
    CORNATIVE_SYMBOL(LoadLibraryShim);
    CORNATIVE_SYMBOL(LoadStringRCEx);
    CORNATIVE_SYMBOL(LockClrVersion);
    CORNATIVE_SYMBOL(ND_CopyObjDst);
    CORNATIVE_SYMBOL(ND_CopyObjSrc);
    CORNATIVE_SYMBOL(ND_RI2);
    CORNATIVE_SYMBOL(ND_RI4);
    CORNATIVE_SYMBOL(ND_RI8);
    CORNATIVE_SYMBOL(ND_RU1);
    CORNATIVE_SYMBOL(ND_WI2);
    CORNATIVE_SYMBOL(ND_WI4);
    CORNATIVE_SYMBOL(ND_WI8);
    CORNATIVE_SYMBOL(ND_WU1);
    CORNATIVE_SYMBOL(StrongNameSignatureVerification);
    CORNATIVE_SYMBOL(StrongNameSignatureVerificationEx);
    CORNATIVE_SYMBOL(_CorDllMain);
    CORNATIVE_SYMBOL(_CorExeMain2);
    CORNATIVE_SYMBOL(_CorExeMain);

    InterlockedExchangePointer((PVOID *)&mscoree_ops, (PVOID)&cornative_ops);

out:
    if (!SUCCEEDED(hr))
    {
        FreeLibrary(cornative_hModule);
        cornative_hModule = NULL;
        memset(&cornative_ops, 0, sizeof(cornative_ops));
    }

    if (hfind != INVALID_HANDLE_VALUE)
    {
        FindClose(hfind);
    }

    return hr;
}

void mscoree_operations_init(void)
{
    InitializeCriticalSection(&mscoree_ops_lock);
}

mscoree_operations *mscoree_get_ops(void)
{
    if (!InterlockedCompareExchangePointer((PVOID *)&mscoree_ops, mscoree_ops, mscoree_ops))
    {
        EnterCriticalSection(&mscoree_ops_lock);

        if (mscoree_ops)
        {
            /*
             * Double checked lock here depends on the writer of mscoree_ops
             * doing a memory barrier on CPUs with weak memory models.
             */
            LeaveCriticalSection(&mscoree_ops_lock);
            return mscoree_ops;
        }

        if (!SUCCEEDED(cornative_load()))
        {
            InterlockedExchangePointer((PVOID *)&mscoree_ops, (PVOID)&cormono_ops);
        }

        LeaveCriticalSection(&mscoree_ops_lock);
    }

    return mscoree_ops;
}

/* Operation stubs */
/* TODO: convert entire exported DLL surface to use these wrappers. */

HRESULT WINAPI LoadStringRC(UINT resId, LPWSTR buffer, int iBufLen, int bQuiet)
{
    return mscoree_get_ops()->LoadStringRC(resId, buffer, iBufLen, bQuiet);
}

HRESULT WINAPI CreateObject(REFIID riid, void **ppv)
{
    return mscoree_get_ops()->CreateObject(riid, ppv);
}

DWORD WINAPI OpenCtrs(LPWSTR pContext)
{
    return mscoree_get_ops()->OpenCtrs(pContext);
}

DWORD WINAPI CollectCtrs(
    LPWSTR pQuery, LPVOID *ppData, LPDWORD pcbData, LPDWORD pObjectsReturned)
{
    return mscoree_get_ops()->CollectCtrs(
        pQuery, ppData, pcbData, pObjectsReturned);
}

DWORD WINAPI CloseCtrs(void)
{
    return mscoree_get_ops()->CloseCtrs();
}

HRESULT WINAPI CLRCreateInstance(
    REFCLSID clsid, REFIID riid, LPVOID *ppInterface)
{
    return mscoree_get_ops()->CLRCreateInstance(clsid, riid, ppInterface);
}

HRESULT WINAPI ClrCreateManagedInstance(
    LPCWSTR pTypeName, REFIID riid, void **ppObject)
{
    return mscoree_get_ops()->ClrCreateManagedInstance(
        pTypeName, riid, ppObject);
}

void WINAPI CoEEShutDownCOM(void)
{
    mscoree_get_ops()->CoEEShutDownCOM();
}

HRESULT WINAPI CoInitializeCor(DWORD fFlags)
{
    return mscoree_get_ops()->CoInitializeCor(fFlags);
}

HRESULT WINAPI CorBindToCurrentRuntime(
    LPCWSTR filename, REFCLSID rclsid, REFIID riid, LPVOID *ppv)
{
    return mscoree_get_ops()->CorBindToCurrentRuntime(
        filename, rclsid, riid, ppv);
}

HRESULT WINAPI CorBindToRuntimeEx(
    LPWSTR szVersion, LPWSTR szBuildFlavor, DWORD nflags, REFCLSID rslsid,
    REFIID riid, LPVOID *ppv)
{
    return mscoree_get_ops()->CorBindToRuntimeEx(
        szVersion, szBuildFlavor, nflags, rslsid, riid, ppv);
}

HRESULT WINAPI CorBindToRuntimeHost(
    LPCWSTR pwszVersion, LPCWSTR pwszBuildFlavor,
    LPCWSTR pwszHostConfigFile, VOID *pReserved,
    DWORD startupFlags, REFCLSID rclsid,
    REFIID riid, LPVOID *ppv)
{
    return mscoree_get_ops()->CorBindToRuntimeHost(
        pwszVersion, pwszBuildFlavor, pwszHostConfigFile, pReserved,
        startupFlags, rclsid, riid, ppv);
}

void WINAPI CorExitProcess(int exitCode)
{
    mscoree_get_ops()->CorExitProcess(exitCode);
}

HRESULT WINAPI CorIsLatestSvc(int *unk1, int *unk2)
{
    return mscoree_get_ops()->CorIsLatestSvc(unk1, unk2);
}

HRESULT WINAPI CreateConfigStream(const WCHAR *filename, IStream **stream)
{
    return mscoree_get_ops()->CreateConfigStream(filename, stream);
}

HRESULT WINAPI CreateDebuggingInterfaceFromVersion(
    int nDebugVersion, LPCWSTR version, IUnknown **ppv)
{
    return mscoree_get_ops()->CreateDebuggingInterfaceFromVersion(
        nDebugVersion, version, ppv);
}

HRESULT WINAPI CreateInterface(REFCLSID clsid, REFIID riid, LPVOID *ppInterface)
{
    return mscoree_get_ops()->CreateInterface(clsid, riid, ppInterface);
}

HRESULT WINAPI DllCanUnloadNow(void)
{
    return mscoree_get_ops()->DllCanUnloadNow();
}

HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
    return mscoree_get_ops()->DllGetClassObject(rclsid, riid, ppv);
}

HRESULT WINAPI DllRegisterServer(void)
{
    return mscoree_get_ops()->DllRegisterServer();
}

HRESULT WINAPI DllUnregisterServer(void)
{
    return mscoree_get_ops()->DllUnregisterServer();
}

HRESULT WINAPI GetAssemblyMDImport(
    LPCWSTR szFileName, REFIID riid, IUnknown **ppIUnk)
{
    return mscoree_get_ops()->GetAssemblyMDImport(
        szFileName, riid, ppIUnk);
}

HRESULT WINAPI GetCORSystemDirectory(
    LPWSTR pbuffer, DWORD cchBuffer, DWORD *dwLength)
{
    return mscoree_get_ops()->GetCORSystemDirectory(
        pbuffer, cchBuffer, dwLength);
}

HRESULT WINAPI GetCORVersion(LPWSTR pbuffer, DWORD cchBuffer, DWORD *dwLength)
{
    return mscoree_get_ops()->GetCORVersion(pbuffer, cchBuffer, dwLength);
}

HRESULT WINAPI GetFileVersion(
    LPCWSTR szFilename, LPWSTR szBuffer, DWORD cchBuffer, DWORD *dwLength)
{
    return mscoree_get_ops()->GetFileVersion(
        szFilename, szBuffer, cchBuffer, dwLength);
}

PVOID WINAPI GetProcessExecutableHeap(void)
{
    return mscoree_get_ops()->GetProcessExecutableHeap();
}

HRESULT WINAPI GetRealProcAddress(LPCSTR procname, void **ppv)
{
    return mscoree_get_ops()->GetRealProcAddress(procname, ppv);
}

HRESULT WINAPI GetRequestedRuntimeInfo(
    LPCWSTR pExe, LPCWSTR pwszVersion, LPCWSTR pConfigurationFile,
    DWORD startupFlags, DWORD runtimeInfoFlags, LPWSTR pDirectory,
    DWORD dwDirectory, DWORD *dwDirectoryLength, LPWSTR pVersion,
    DWORD cchBuffer, DWORD *dwlength)
{
    return mscoree_get_ops()->GetRequestedRuntimeInfo(
        pExe, pwszVersion, pConfigurationFile, startupFlags, runtimeInfoFlags,
        pDirectory, dwDirectory, dwDirectoryLength, pVersion,
        cchBuffer, dwlength);
}

HRESULT WINAPI GetRequestedRuntimeVersion(
    LPWSTR pExe, LPWSTR pVersion, DWORD cchBuffer, DWORD *dwlength)
{
    return mscoree_get_ops()->GetRequestedRuntimeVersion(
        pExe, pVersion, cchBuffer, dwlength);
}

HRESULT WINAPI GetVersionFromProcess(
    HANDLE hProcess, LPWSTR pVersion, DWORD cchBuffer, DWORD *dwLength)
{

    return mscoree_get_ops()->GetVersionFromProcess(
        hProcess, pVersion, cchBuffer, dwLength);
}

HRESULT WINAPI LoadLibraryShim(
    LPCWSTR szDllName, LPCWSTR szVersion, LPVOID pvReserved, HMODULE * phModDll)
{
    return mscoree_get_ops()->LoadLibraryShim(
        szDllName, szVersion, pvReserved, phModDll);
}

HRESULT WINAPI LoadStringRCEx(
    LCID culture, UINT resId, LPWSTR pBuffer,
    int iBufLen, int bQuiet, int* pBufLen)
{
    return mscoree_get_ops()->LoadStringRCEx(
        culture, resId, pBuffer, iBufLen, bQuiet, pBufLen);
}

HRESULT WINAPI LockClrVersion(
    FLockClrVersionCallback hostCallback,
    FLockClrVersionCallback *pBeginHostSetup,
    FLockClrVersionCallback *pEndHostSetup)
{
    return mscoree_get_ops()->LockClrVersion(
        hostCallback, pBeginHostSetup, pEndHostSetup);
}

__int32 WINAPI _CorExeMain(void)
{
    return mscoree_get_ops()->_CorExeMain();
}
