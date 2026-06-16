// bridge_windows.c - the CNG Key Storage Provider C ABI.
//
// Windows calls GetKeyStorageInterface for the function table, then invokes its entries. Each
// supported entry forwards to a Go function exported from bridge_windows.go; the rest return
// NTE_NOT_SUPPORTED.
//
// Compiled by cgo against the CPDK header <ncrypt_provider.h>, which defines
// NCRYPT_KEY_STORAGE_FUNCTION_TABLE and the GetKeyStorageInterface prototype.

#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <ncrypt_provider.h>
#include <string.h>

#include "_cgo_export.h"

static SECURITY_STATUS copyOut(void *data, int len, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult) {
    if (pcbResult != NULL) {
        *pcbResult = (DWORD)len;
    }
    if (pbOutput == NULL) {
        return ERROR_SUCCESS; // sizing call
    }
    if (cbOutput < (DWORD)len) {
        return NTE_BUFFER_TOO_SMALL;
    }
    memcpy(pbOutput, data, (size_t)len);
    return ERROR_SUCCESS;
}

// ---- Supported functions ---------------------------------------------------

static SECURITY_STATUS WINAPI ksp_OpenProvider(NCRYPT_PROV_HANDLE *phProvider, LPCWSTR pszProviderName, DWORD dwFlags) {
    (void)pszProviderName; (void)dwFlags;
    struct GoOpenProvider_return r = GoOpenProvider();
    if (r.r1 != 0) return (SECURITY_STATUS)r.r1;
    *phProvider = (NCRYPT_PROV_HANDLE)r.r0;
    return ERROR_SUCCESS;
}

static SECURITY_STATUS WINAPI ksp_OpenKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE *phKey, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags) {
    (void)dwLegacyKeySpec; (void)dwFlags;
    struct GoOpenKey_return r = GoOpenKey((uintptr_t)hProvider, (void *)pszKeyName);
    if (r.r1 != 0) return (SECURITY_STATUS)r.r1;
    *phKey = (NCRYPT_KEY_HANDLE)r.r0;
    return ERROR_SUCCESS;
}

static SECURITY_STATUS WINAPI ksp_GetKeyProperty(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, LPCWSTR pszProperty, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags) {
    (void)hProvider; (void)dwFlags;
    struct GoGetKeyProperty_return r = GoGetKeyProperty((uintptr_t)hKey, (void *)pszProperty);
    if (r.r2 != 0) return (SECURITY_STATUS)r.r2;
    SECURITY_STATUS st = copyOut(r.r0, r.r1, pbOutput, cbOutput, pcbResult);
    if (r.r0 != NULL) free(r.r0);
    return st;
}

static SECURITY_STATUS WINAPI ksp_ExportKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, NCRYPT_KEY_HANDLE hExportKey, LPCWSTR pszBlobType, NCryptBufferDesc *pParameterList, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags) {
    (void)hProvider; (void)hExportKey; (void)pParameterList; (void)dwFlags;
    // Only public-key blobs are exportable.
    if (wcscmp(pszBlobType, BCRYPT_RSAPUBLIC_BLOB) != 0 &&
        wcscmp(pszBlobType, BCRYPT_ECCPUBLIC_BLOB) != 0 &&
        wcscmp(pszBlobType, BCRYPT_PUBLIC_KEY_BLOB) != 0) {
        return NTE_NOT_SUPPORTED;
    }
    struct GoExportKey_return r = GoExportKey((uintptr_t)hKey);
    if (r.r2 != 0) return (SECURITY_STATUS)r.r2;
    SECURITY_STATUS st = copyOut(r.r0, r.r1, pbOutput, cbOutput, pcbResult);
    if (r.r0 != NULL) free(r.r0);
    return st;
}

static SECURITY_STATUS WINAPI ksp_SignHash(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, VOID *pPaddingInfo, PBYTE pbHashValue, DWORD cbHashValue, PBYTE pbSignature, DWORD cbSignature, DWORD *pcbResult, DWORD dwFlags) {
    (void)hProvider;
    // Sizing call: report the exact signature size without contacting Infisical.
    if (pbSignature == NULL) {
        struct GoSignatureMaxSize_return sz = GoSignatureMaxSize((uintptr_t)hKey);
        if (sz.r1 != 0) return (SECURITY_STATUS)sz.r1;
        if (pcbResult != NULL) *pcbResult = (DWORD)sz.r0;
        return ERROR_SUCCESS;
    }
    struct GoSignHash_return r = GoSignHash((uintptr_t)hKey, (unsigned int)dwFlags, pPaddingInfo, pbHashValue, (unsigned int)cbHashValue);
    if (r.r2 != 0) return (SECURITY_STATUS)r.r2;
    SECURITY_STATUS st = copyOut(r.r0, r.r1, pbSignature, cbSignature, pcbResult);
    if (r.r0 != NULL) free(r.r0);
    return st;
}

static SECURITY_STATUS WINAPI ksp_FreeProvider(NCRYPT_PROV_HANDLE hProvider) {
    GoFreeHandle((uintptr_t)hProvider);
    return ERROR_SUCCESS;
}

static SECURITY_STATUS WINAPI ksp_FreeKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey) {
    (void)hProvider;
    GoFreeHandle((uintptr_t)hKey);
    return ERROR_SUCCESS;
}

static SECURITY_STATUS WINAPI ksp_FreeBuffer(PVOID pvInput) {
    (void)pvInput;
    return ERROR_SUCCESS;
}

// ---- Unsupported functions (return NTE_NOT_SUPPORTED) ----------------------

static SECURITY_STATUS WINAPI ksp_CreatePersistedKey(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE *p, LPCWSTR a, LPCWSTR n, DWORD k, DWORD f) { (void)h;(void)p;(void)a;(void)n;(void)k;(void)f; return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI ksp_GetProviderProperty(NCRYPT_PROV_HANDLE h, LPCWSTR pr, PBYTE o, DWORD c, DWORD *r, DWORD f) { (void)h;(void)pr;(void)o;(void)c;(void)r;(void)f; return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI ksp_SetProviderProperty(NCRYPT_PROV_HANDLE h, LPCWSTR pr, PBYTE i, DWORD c, DWORD f) { (void)h;(void)pr;(void)i;(void)c;(void)f; return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI ksp_SetKeyProperty(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE k, LPCWSTR pr, PBYTE i, DWORD c, DWORD f) { (void)h;(void)k;(void)pr;(void)i;(void)c;(void)f; return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI ksp_FinalizeKey(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE k, DWORD f) { (void)h;(void)k;(void)f; return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI ksp_DeleteKey(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE k, DWORD f) { (void)h;(void)k;(void)f; return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI ksp_Encrypt(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE k, PBYTE i, DWORD ci, VOID *pad, PBYTE o, DWORD co, DWORD *r, DWORD f) { (void)h;(void)k;(void)i;(void)ci;(void)pad;(void)o;(void)co;(void)r;(void)f; return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI ksp_Decrypt(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE k, PBYTE i, DWORD ci, VOID *pad, PBYTE o, DWORD co, DWORD *r, DWORD f) { (void)h;(void)k;(void)i;(void)ci;(void)pad;(void)o;(void)co;(void)r;(void)f; return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI ksp_IsAlgSupported(NCRYPT_PROV_HANDLE h, LPCWSTR a, DWORD f) { (void)h;(void)a;(void)f; return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI ksp_EnumAlgorithms(NCRYPT_PROV_HANDLE h, DWORD op, DWORD *c, NCryptAlgorithmName **l, DWORD f) { (void)h;(void)op;(void)c;(void)l;(void)f; return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI ksp_EnumKeys(NCRYPT_PROV_HANDLE h, LPCWSTR s, NCryptKeyName **n, PVOID *e, DWORD f) { (void)h;(void)s;(void)n;(void)e;(void)f; return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI ksp_ImportKey(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE ik, LPCWSTR bt, NCryptBufferDesc *pl, NCRYPT_KEY_HANDLE *pk, PBYTE d, DWORD cd, DWORD f) { (void)h;(void)ik;(void)bt;(void)pl;(void)pk;(void)d;(void)cd;(void)f; return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI ksp_VerifySignature(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE k, VOID *pad, PBYTE hv, DWORD chv, PBYTE s, DWORD cs, DWORD f) { (void)h;(void)k;(void)pad;(void)hv;(void)chv;(void)s;(void)cs;(void)f; return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI ksp_PromptUser(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE k, LPCWSTR o, DWORD f) { (void)h;(void)k;(void)o;(void)f; return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI ksp_NotifyChangeKey(NCRYPT_PROV_HANDLE h, HANDLE *e, DWORD f) { (void)h;(void)e;(void)f; return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI ksp_SecretAgreement(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE pr, NCRYPT_KEY_HANDLE pu, NCRYPT_SECRET_HANDLE *sec, DWORD f) { (void)h;(void)pr;(void)pu;(void)sec;(void)f; return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI ksp_DeriveKey(NCRYPT_PROV_HANDLE h, NCRYPT_SECRET_HANDLE s, LPCWSTR kdf, NCryptBufferDesc *pl, PBYTE d, DWORD cd, DWORD *r, DWORD f) { (void)h;(void)s;(void)kdf;(void)pl;(void)d;(void)cd;(void)r;(void)f; return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI ksp_FreeSecret(NCRYPT_PROV_HANDLE h, NCRYPT_SECRET_HANDLE s) { (void)h;(void)s; return NTE_NOT_SUPPORTED; }

// ---- Function table + entry point ------------------------------------------
// Field order must match NCRYPT_KEY_STORAGE_FUNCTION_TABLE in <ncrypt_provider.h>. Any trailing
// optional entries a newer header adds (e.g. KeyDerivation) are left NULL, i.e. unsupported.

static NCRYPT_KEY_STORAGE_FUNCTION_TABLE g_FunctionTable = {
    NCRYPT_KEY_STORAGE_INTERFACE_VERSION,
    ksp_OpenProvider,
    ksp_OpenKey,
    ksp_CreatePersistedKey,
    ksp_GetProviderProperty,
    ksp_GetKeyProperty,
    ksp_SetProviderProperty,
    ksp_SetKeyProperty,
    ksp_FinalizeKey,
    ksp_DeleteKey,
    ksp_FreeProvider,
    ksp_FreeKey,
    ksp_FreeBuffer,
    ksp_Encrypt,
    ksp_Decrypt,
    ksp_IsAlgSupported,
    ksp_EnumAlgorithms,
    ksp_EnumKeys,
    ksp_ImportKey,
    ksp_ExportKey,
    ksp_SignHash,
    ksp_VerifySignature,
    ksp_PromptUser,
    ksp_NotifyChangeKey,
    ksp_SecretAgreement,
    ksp_DeriveKey,
    ksp_FreeSecret,
};

// GetKeyStorageInterface is the DLL export CNG resolves by name; __declspec(dllexport) exports it
// undecorated on x64.
__declspec(dllexport)
SECURITY_STATUS WINAPI GetKeyStorageInterface(LPCWSTR pszProviderName, NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable, DWORD dwFlags) {
    (void)pszProviderName;
    (void)dwFlags;
    *ppFunctionTable = &g_FunctionTable;
    return ERROR_SUCCESS;
}
