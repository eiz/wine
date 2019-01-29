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
    NULL, /* LoadStringRC */
    cormono_CreateObject,
    NULL, /* CloseCtrs */
    NULL, /* CLRCreateInstance */
    NULL, /* ClrCreateManagedInstance */
    NULL, /* CoEEShutDownCOM */
    NULL, /* CoInitializeCor */
    NULL, /* CorBindToCurrentRuntime */
    NULL, /* CorBindToRuntimeEx */
    NULL, /* CorBindToRuntimeHost */
    NULL, /* CorExitProcess */
    NULL, /* CorIsLatestSvc */
    NULL, /* CreateConfigStream */
    NULL, /* CreateDebuggingInterfaceFromVersion */
    NULL, /* CreateInterface */
    NULL, /* DllCanUnloadNow */
    NULL, /* DllGetClassObject */
    NULL, /* DllRegisterServer */
    NULL, /* DllUnregisterServer */
    NULL, /* GetAssemblyMDImport */
    NULL, /* GetCORSystemDirectory */
    NULL, /* GetCORVersion */
    NULL, /* GetFileVersion */
    cormono_GetProcessExecutableHeap,
    NULL, /* GetRealProcAddress */
    NULL, /* GetRequestedRuntimeInfo */
    NULL, /* GetRequestedRuntimeVersion */
    NULL, /* GetVersionFromProcess */
    NULL, /* LoadLibraryShim */
    NULL, /* LoadStringRCEx */
    NULL, /* LockClrVersion */
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

HRESULT WINAPI CreateObject(REFIID riid, void **ppv)
{
    return mscoree_get_ops()->CreateObject(riid, ppv);
}

PVOID WINAPI GetProcessExecutableHeap(void)
{
    return mscoree_get_ops()->GetProcessExecutableHeap();
}

__int32 WINAPI _CorExeMain(void)
{
    return mscoree_get_ops()->_CorExeMain();
}
