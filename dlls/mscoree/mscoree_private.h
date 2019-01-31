/*
 *
 * Copyright 2008 Alistair Leslie-Hughes
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

#ifndef __MSCOREE_PRIVATE__
#define __MSCOREE_PRIVATE__

extern char *WtoA(LPCWSTR wstr) DECLSPEC_HIDDEN;

extern HRESULT CLRMetaHost_CreateInstance(REFIID riid, void **ppobj) DECLSPEC_HIDDEN;
extern HRESULT CLRMetaHostPolicy_CreateInstance(REFIID riid, void **ppobj) DECLSPEC_HIDDEN;

extern HRESULT WINAPI CLRMetaHost_GetVersionFromFile(ICLRMetaHost* iface,
    LPCWSTR pwzFilePath, LPWSTR pwzBuffer, DWORD *pcchBuffer) DECLSPEC_HIDDEN;

typedef struct _VTableFixup {
    DWORD rva;
    WORD count;
    WORD type;
} VTableFixup;

typedef struct tagASSEMBLY ASSEMBLY;

typedef BOOL (WINAPI *NativeEntryPointFunc)(HINSTANCE, DWORD, LPVOID);

extern HRESULT assembly_create(ASSEMBLY **out, LPCWSTR file) DECLSPEC_HIDDEN;
extern HRESULT assembly_from_hmodule(ASSEMBLY **out, HMODULE hmodule) DECLSPEC_HIDDEN;
extern HRESULT assembly_release(ASSEMBLY *assembly) DECLSPEC_HIDDEN;
extern HRESULT assembly_get_runtime_version(ASSEMBLY *assembly, LPSTR *version) DECLSPEC_HIDDEN;
extern HRESULT assembly_get_vtable_fixups(ASSEMBLY *assembly, VTableFixup **fixups, DWORD *count) DECLSPEC_HIDDEN;
extern HRESULT assembly_get_native_entrypoint(ASSEMBLY *assembly, NativeEntryPointFunc *func) DECLSPEC_HIDDEN;

/* Mono embedding */
typedef struct _MonoDomain MonoDomain;
typedef struct _MonoAssembly MonoAssembly;
typedef struct _MonoAssemblyName MonoAssemblyName;
typedef struct _MonoType MonoType;
typedef struct _MonoImage MonoImage;
typedef struct _MonoClass MonoClass;
typedef struct _MonoObject MonoObject;
typedef struct _MonoString MonoString;
typedef struct _MonoMethod MonoMethod;
typedef struct _MonoProfiler MonoProfiler;
typedef struct _MonoThread MonoThread;

typedef struct RuntimeHost RuntimeHost;

typedef struct CLRRuntimeInfo
{
    ICLRRuntimeInfo ICLRRuntimeInfo_iface;
    DWORD major;
    DWORD minor;
    DWORD build;
    struct RuntimeHost *loaded_runtime;
} CLRRuntimeInfo;

struct RuntimeHost
{
    ICorRuntimeHost ICorRuntimeHost_iface;
    ICLRRuntimeHost ICLRRuntimeHost_iface;
    CLRRuntimeInfo *version;
    struct list domains;
    MonoDomain *default_domain;
    CRITICAL_SECTION lock;
    LONG ref;
};

typedef struct CorProcess
{
    struct list entry;
    ICorDebugProcess *pProcess;
} CorProcess;

typedef struct CorDebug
{
    ICorDebug ICorDebug_iface;
    ICorDebugProcessEnum ICorDebugProcessEnum_iface;
    LONG ref;

    ICLRRuntimeHost *runtimehost;

    /* ICorDebug Callback */
    ICorDebugManagedCallback *pCallback;
    ICorDebugManagedCallback2 *pCallback2;

    /* Debug Processes */
    struct list processes;
} CorDebug;

extern HRESULT get_runtime_info(LPCWSTR exefile, LPCWSTR version, LPCWSTR config_file,
    DWORD startup_flags, DWORD runtimeinfo_flags, BOOL legacy, ICLRRuntimeInfo **result) DECLSPEC_HIDDEN;

extern HRESULT ICLRRuntimeInfo_GetRuntimeHost(ICLRRuntimeInfo *iface, RuntimeHost **result) DECLSPEC_HIDDEN;

extern HRESULT MetaDataDispenser_CreateInstance(IUnknown **ppUnk) DECLSPEC_HIDDEN;

typedef struct parsed_config_file
{
    struct list supported_runtimes;
} parsed_config_file;

typedef struct supported_runtime
{
    struct list entry;
    LPWSTR version;
} supported_runtime;

extern HRESULT parse_config_file(LPCWSTR filename, parsed_config_file *result) DECLSPEC_HIDDEN;

extern void free_parsed_config_file(parsed_config_file *file) DECLSPEC_HIDDEN;

typedef enum {
	MONO_IMAGE_OK,
	MONO_IMAGE_ERROR_ERRNO,
	MONO_IMAGE_MISSING_ASSEMBLYREF,
	MONO_IMAGE_IMAGE_INVALID
} MonoImageOpenStatus;

typedef MonoAssembly* (CDECL *MonoAssemblyPreLoadFunc)(MonoAssemblyName *aname, char **assemblies_path, void *user_data);

typedef void (CDECL *MonoProfileFunc)(MonoProfiler *prof);

typedef void (CDECL *MonoPrintCallback) (const char *string, INT is_stdout);

extern BOOL is_mono_started DECLSPEC_HIDDEN;

extern MonoImage* (CDECL *mono_assembly_get_image)(MonoAssembly *assembly) DECLSPEC_HIDDEN;
extern MonoAssembly* (CDECL *mono_assembly_load_from)(MonoImage *image, const char *fname, MonoImageOpenStatus *status) DECLSPEC_HIDDEN;
extern MonoAssembly* (CDECL *mono_assembly_open)(const char *filename, MonoImageOpenStatus *status) DECLSPEC_HIDDEN;
extern void (CDECL *mono_callspec_set_assembly)(MonoAssembly *assembly) DECLSPEC_HIDDEN;
extern MonoClass* (CDECL *mono_class_from_mono_type)(MonoType *type) DECLSPEC_HIDDEN;
extern MonoClass* (CDECL *mono_class_from_name)(MonoImage *image, const char* name_space, const char *name) DECLSPEC_HIDDEN;
extern MonoMethod* (CDECL *mono_class_get_method_from_name)(MonoClass *klass, const char *name, int param_count) DECLSPEC_HIDDEN;
extern MonoAssembly* (CDECL *mono_domain_assembly_open)(MonoDomain *domain, const char *name) DECLSPEC_HIDDEN;
extern MonoDomain* (CDECL *mono_domain_get)(void) DECLSPEC_HIDDEN;
extern MonoDomain* (CDECL *mono_domain_get_by_id)(int id) DECLSPEC_HIDDEN;
extern BOOL (CDECL *mono_domain_set)(MonoDomain *domain, BOOL force) DECLSPEC_HIDDEN;
extern void (CDECL *mono_domain_set_config)(MonoDomain *domain,const char *base_dir,const char *config_file_name) DECLSPEC_HIDDEN;
extern int (CDECL *mono_jit_exec)(MonoDomain *domain, MonoAssembly *assembly, int argc, char *argv[]) DECLSPEC_HIDDEN;
extern MonoDomain* (CDECL *mono_jit_init_version)(const char *domain_name, const char *runtime_version) DECLSPEC_HIDDEN;
extern MonoImage* (CDECL *mono_image_open_from_module_handle)(HMODULE module_handle, char* fname, UINT has_entry_point, MonoImageOpenStatus* status) DECLSPEC_HIDDEN;
extern void* (CDECL *mono_marshal_get_vtfixup_ftnptr)(MonoImage *image, DWORD token, WORD type) DECLSPEC_HIDDEN;
extern MonoDomain* (CDECL *mono_object_get_domain)(MonoObject *obj) DECLSPEC_HIDDEN;
extern MonoMethod* (CDECL *mono_object_get_virtual_method)(MonoObject *obj, MonoMethod *method) DECLSPEC_HIDDEN;
extern MonoObject* (CDECL *mono_object_new)(MonoDomain *domain, MonoClass *klass) DECLSPEC_HIDDEN;
extern void* (CDECL *mono_object_unbox)(MonoObject *obj) DECLSPEC_HIDDEN;
extern MonoType* (CDECL *mono_reflection_type_from_name)(char *name, MonoImage *image) DECLSPEC_HIDDEN;
extern MonoObject* (CDECL *mono_runtime_invoke)(MonoMethod *method, void *obj, void **params, MonoObject **exc) DECLSPEC_HIDDEN;
extern void (CDECL *mono_runtime_object_init)(MonoObject *this_obj) DECLSPEC_HIDDEN;
extern void (CDECL *mono_runtime_quit)(void) DECLSPEC_HIDDEN;
extern MonoString* (CDECL *mono_string_new)(MonoDomain *domain, const char *str) DECLSPEC_HIDDEN;
extern MonoThread* (CDECL *mono_thread_attach)(MonoDomain *domain) DECLSPEC_HIDDEN;
extern void (CDECL *mono_thread_manage)(void) DECLSPEC_HIDDEN;
extern void (CDECL *mono_trace_set_print_handler)(MonoPrintCallback callback) DECLSPEC_HIDDEN;
extern void (CDECL *mono_trace_set_printerr_handler)(MonoPrintCallback callback) DECLSPEC_HIDDEN;

/* loaded runtime interfaces */
extern void expect_no_runtimes(void) DECLSPEC_HIDDEN;

extern HRESULT RuntimeHost_Construct(CLRRuntimeInfo *runtime_version, RuntimeHost** result) DECLSPEC_HIDDEN;

extern void RuntimeHost_ExitProcess(RuntimeHost *This, INT exitcode) DECLSPEC_HIDDEN;

extern HRESULT RuntimeHost_GetInterface(RuntimeHost *This, REFCLSID clsid, REFIID riid, void **ppv) DECLSPEC_HIDDEN;

extern HRESULT RuntimeHost_GetIUnknownForObject(RuntimeHost *This, MonoObject *obj, IUnknown **ppUnk) DECLSPEC_HIDDEN;

extern HRESULT RuntimeHost_CreateManagedInstance(RuntimeHost *This, LPCWSTR name,
    MonoDomain *domain, MonoObject **result) DECLSPEC_HIDDEN;

HRESULT WINAPI CLRMetaHost_ExitProcess(ICLRMetaHost* iface, INT32 iExitCode) DECLSPEC_HIDDEN;

HRESULT WINAPI CLRMetaHost_GetRuntime(ICLRMetaHost* iface, LPCWSTR pwzVersion, REFIID iid, LPVOID *ppRuntime) DECLSPEC_HIDDEN;

extern HRESULT CorDebug_Create(ICLRRuntimeHost *runtimehost, IUnknown** ppUnk) DECLSPEC_HIDDEN;

extern HRESULT create_monodata(REFIID riid, LPVOID *ppObj) DECLSPEC_HIDDEN;

extern HRESULT get_file_from_strongname(WCHAR* stringnameW, WCHAR* assemblies_path, int path_length) DECLSPEC_HIDDEN;

extern void runtimehost_init(void) DECLSPEC_HIDDEN;
extern void runtimehost_uninit(void) DECLSPEC_HIDDEN;

typedef struct {
    HRESULT (WINAPI *LoadStringRC)(UINT, LPWSTR, int, int);
    HRESULT (WINAPI *CreateObject)(REFIID, PVOID *);
    DWORD (WINAPI *OpenCtrs)(LPWSTR);
    DWORD (WINAPI *CollectCtrs)(LPWSTR, LPVOID *, LPDWORD, LPDWORD);
    DWORD (WINAPI *CloseCtrs)(void);
    HRESULT (WINAPI *CLRCreateInstance)(REFCLSID, REFIID, LPVOID *);
    HRESULT (WINAPI *ClrCreateManagedInstance)(LPCWSTR, REFIID, void **);
    void (WINAPI *CoEEShutDownCOM)(void);
    HRESULT (WINAPI *CoInitializeCor)(DWORD);
    HRESULT (WINAPI *CorBindToCurrentRuntime)(
        LPCWSTR, REFCLSID, REFIID, LPVOID *);
    HRESULT (WINAPI *CorBindToRuntimeEx)(
        LPWSTR, LPWSTR, DWORD, REFCLSID, REFIID, LPVOID*);
    HRESULT (WINAPI *CorBindToRuntimeHost)(
        LPCWSTR, LPCWSTR, LPCWSTR, PVOID, DWORD, REFCLSID, REFIID, LPVOID *);
    void (WINAPI *CorExitProcess)(int);
    HRESULT (WINAPI *CorIsLatestSvc)(int *, int *);
    HRESULT (WINAPI *CreateConfigStream)(const WCHAR *, IStream **);
    HRESULT (WINAPI *CreateDebuggingInterfaceFromVersion)(
        int, LPCWSTR, IUnknown **);
    HRESULT (WINAPI *CreateInterface)(REFCLSID, REFIID, LPVOID *);
    HRESULT (WINAPI *DllCanUnloadNow)(void);
    HRESULT (WINAPI *DllGetClassObject)(REFCLSID, REFIID, LPVOID *);
    HRESULT (WINAPI *DllRegisterServer)(void);
    HRESULT (WINAPI *DllUnregisterServer)(void);
    HRESULT (WINAPI *GetAssemblyMDImport)(LPCWSTR, REFIID, IUnknown **);
    HRESULT (WINAPI *GetCORSystemDirectory)(LPWSTR, DWORD, DWORD *);
    HRESULT (WINAPI *GetCORVersion)(LPWSTR, DWORD, DWORD *);
    HRESULT (WINAPI *GetFileVersion)(LPCWSTR, LPWSTR, DWORD, DWORD *);
    PVOID (WINAPI *GetProcessExecutableHeap)(void);
    HRESULT (WINAPI *GetRealProcAddress)(LPCSTR, PVOID *);
    HRESULT (WINAPI *GetRequestedRuntimeInfo)(
        LPCWSTR, LPCWSTR, LPCWSTR, DWORD, DWORD, LPWSTR, DWORD, DWORD *,
        LPWSTR, DWORD, DWORD *);
    HRESULT (WINAPI *GetRequestedRuntimeVersion)(
        LPWSTR, LPWSTR, DWORD, DWORD *);
    HRESULT (WINAPI *GetVersionFromProcess)(HANDLE, LPWSTR, DWORD, DWORD *);
    HRESULT (WINAPI *LoadLibraryShim)(LPCWSTR, LPCWSTR, LPVOID, HMODULE *);
    HRESULT (WINAPI *LoadStringRCEx)(LCID, UINT, LPWSTR, int, int, int *);
    HRESULT (WINAPI *LockClrVersion)(
        FLockClrVersionCallback,
        FLockClrVersionCallback *,
        FLockClrVersionCallback *);
    void (WINAPI *ND_CopyObjDst)(PVOID, PVOID, LONG, LONG);
    void (WINAPI *ND_CopyObjSrc)(PVOID, LONG, PVOID, LONG);
    void (WINAPI *ND_RI2)(PVOID, LONG);
    void (WINAPI *ND_RI4)(PVOID, LONG);
    void (WINAPI *ND_RI8)(PVOID, LONG);
    void (WINAPI *ND_RU1)(PVOID, LONG);
    void (WINAPI *ND_WI2)(PVOID, LONG, LONG);
    void (WINAPI *ND_WI4)(PVOID, LONG, LONG);
    void (WINAPI *ND_WI8)(PVOID, LONG, LONGLONG);
    void (WINAPI *ND_WU1)(PVOID, LONG, LONG);
    void (WINAPI *StrongNameSignatureVerification)(LPWSTR, LONG, PVOID);
    void (WINAPI *StrongNameSignatureVerificationEx)(LPWSTR, LONG, PVOID);
    void (WINAPI *_CorDllMain)(LONG, LONG, PVOID);
    void (WINAPI *_CorExeMain2)(PVOID, LONG, PVOID, PVOID, PVOID);
    __int32 (WINAPI *_CorExeMain)(void);
} mscoree_operations;

extern void mscoree_operations_init(void) DECLSPEC_HIDDEN;
extern mscoree_operations *mscoree_get_ops(void) DECLSPEC_HIDDEN;

extern HRESULT WINAPI cormono_LoadStringRC(
    UINT resId, LPWSTR buffer, int iBufLen, int bQuiet) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_CreateObject(
    REFIID riid, void **ppv) DECLSPEC_HIDDEN;
extern DWORD WINAPI cormono_OpenCtrs(LPWSTR pContext) DECLSPEC_HIDDEN;
extern DWORD WINAPI cormono_CollectCtrs(
    LPWSTR pQuery, LPVOID *ppData, LPDWORD pcbData,
    LPDWORD pObjectsReturned) DECLSPEC_HIDDEN;
extern DWORD WINAPI cormono_CloseCtrs(void) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_CLRCreateInstance(
    REFCLSID clsid, REFIID riid, LPVOID *ppInterface) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_ClrCreateManagedInstance(
    LPCWSTR pTypeName, REFIID riid, void **ppObject) DECLSPEC_HIDDEN;
extern void WINAPI cormono_CoEEShutDownCOM(void) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_CoInitializeCor(DWORD fFlags) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_CorBindToCurrentRuntime(
    LPCWSTR filename, REFCLSID rclsid, REFIID riid,
    LPVOID *ppv) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_CorBindToRuntimeEx(
    LPWSTR szVersion, LPWSTR szBuildFlavor, DWORD nflags, REFCLSID rslsid,
    REFIID riid, LPVOID *ppv) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_CorBindToRuntimeHost(
    LPCWSTR pwszVersion, LPCWSTR pwszBuildFlavor,
    LPCWSTR pwszHostConfigFile, VOID *pReserved,
    DWORD startupFlags, REFCLSID rclsid,
    REFIID riid, LPVOID *ppv) DECLSPEC_HIDDEN;
extern void WINAPI cormono_CorExitProcess(int exitCode) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_CorIsLatestSvc(
    int *unk1, int *unk2) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_CreateConfigStream(
    const WCHAR *filename, IStream **stream) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_CreateDebuggingInterfaceFromVersion(
    int nDebugVersion, LPCWSTR version, IUnknown **ppv) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_CreateInterface(
    REFCLSID clsid, REFIID riid, LPVOID *ppInterface) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_DllCanUnloadNow(VOID) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_DllGetClassObject(
    REFCLSID rclsid, REFIID riid, LPVOID* ppv) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_DllRegisterServer(void) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_DllUnregisterServer(void) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_GetAssemblyMDImport(
    LPCWSTR szFileName, REFIID riid, IUnknown **ppIUnk) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_GetCORSystemDirectory(
    LPWSTR pbuffer, DWORD cchBuffer, DWORD *dwLength) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_GetCORVersion(
    LPWSTR pbuffer, DWORD cchBuffer, DWORD *dwLength) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_GetFileVersion(
    LPCWSTR szFilename, LPWSTR szBuffer, DWORD cchBuffer,
    DWORD *dwLength) DECLSPEC_HIDDEN;
extern PVOID WINAPI cormono_GetProcessExecutableHeap(void);
extern HRESULT WINAPI cormono_GetRealProcAddress(
    LPCSTR procname, void **ppv) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_GetRequestedRuntimeInfo(
    LPCWSTR pExe, LPCWSTR pwszVersion, LPCWSTR pConfigurationFile,
    DWORD startupFlags, DWORD runtimeInfoFlags, LPWSTR pDirectory,
    DWORD dwDirectory, DWORD *dwDirectoryLength, LPWSTR pVersion,
    DWORD cchBuffer, DWORD *dwlength) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_GetRequestedRuntimeVersion(
    LPWSTR pExe, LPWSTR pVersion, DWORD cchBuffer,
    DWORD *dwlength) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_GetVersionFromProcess(
    HANDLE hProcess, LPWSTR pVersion, DWORD cchBuffer,
    DWORD *dwLength) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_LoadLibraryShim(
    LPCWSTR szDllName, LPCWSTR szVersion, LPVOID pvReserved,
    HMODULE * phModDll) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_LoadStringRCEx(
    LCID culture, UINT resId, LPWSTR pBuffer,
    int iBufLen, int bQuiet, int *pBufLen) DECLSPEC_HIDDEN;
extern HRESULT WINAPI cormono_LockClrVersion(
    FLockClrVersionCallback hostCallback,
    FLockClrVersionCallback *pBeginHostSetup,
    FLockClrVersionCallback *pEndHostSetup) DECLSPEC_HIDDEN;
extern __int32 WINAPI cormono__CorExeMain(void) DECLSPEC_HIDDEN;

#endif   /* __MSCOREE_PRIVATE__ */
