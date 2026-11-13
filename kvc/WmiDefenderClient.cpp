// WmiDefenderClient.cpp
// COM/WMI direct implementation of Add-MpPreference / Remove-MpPreference
// Targets ROOT\Microsoft\Windows\Defender :: MSFT_MpPreference (Add / Remove static methods)

#include "WmiDefenderClient.h"
#include <comdef.h>

// ---------------------------------------------------------------------------
// Constructor — connects to ROOT\Microsoft\Windows\Defender
// ---------------------------------------------------------------------------

WmiDefenderClient::WmiDefenderClient()
{
    HRESULT initHr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (SUCCEEDED(initHr)) {
        m_comInitialized = true;
    } else if (initHr != RPC_E_CHANGED_MODE) {
        return;
    }

    ComPtr<IWbemLocator> pLoc;

    HRESULT hr = CoCreateInstance(
        CLSID_WbemLocator, nullptr,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        reinterpret_cast<void**>(&pLoc.p)
    );

    if (FAILED(hr)) {
        return;
    }

    IWbemServices* rawSvc = nullptr;
    hr = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\Microsoft\\Windows\\Defender"),
        nullptr, nullptr,          // user / password — use caller's token
        nullptr,                   // locale
        0,                         // flags
        nullptr,                   // authority
        nullptr,                   // context
        &rawSvc
    );

    if (FAILED(hr)) {
        return;
    }

    m_pSvc = ComPtr<IWbemServices>(rawSvc);

    // Set proxy blanket — use caller's identity, delegate impersonation
    hr = CoSetProxyBlanket(
        m_pSvc.p,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        nullptr,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE
    );

    if (FAILED(hr)) {
        // Non-fatal; WMI may still work under SYSTEM / TrustedInstaller.
    }
}

WmiDefenderClient::~WmiDefenderClient()
{
    // Release COM proxies before leaving COM apartment.
    m_pSvc = ComPtr<IWbemServices>();

    if (m_comInitialized) {
        CoUninitialize();
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

bool WmiDefenderClient::Add(ExclusionType type, std::wstring_view value) noexcept
{
    // Skip WMI round-trip if exclusion already present
    if (HasExclusion(type, value)) return true;
    return ExecMpMethod(L"Add", ParamNameFor(type), value);
}

bool WmiDefenderClient::Remove(ExclusionType type, std::wstring_view value) noexcept
{
    return ExecMpMethod(L"Remove", ParamNameFor(type), value);
}

// ---------------------------------------------------------------------------
// Core WMI method invocation
// ---------------------------------------------------------------------------

bool WmiDefenderClient::ExecMpMethod(const wchar_t* method,
                                     const wchar_t* paramName,
                                     std::wstring_view value) noexcept
{
    if (!m_pSvc) return false;

    // ------------------------------------------------------------------
    // 1. Retrieve MSFT_MpPreference class object to obtain in-params def
    // ------------------------------------------------------------------
    ComPtr<IWbemClassObject> pClass;
    HRESULT hr = m_pSvc->GetObject(
        _bstr_t(L"MSFT_MpPreference"),
        0, nullptr,
        &pClass.p, nullptr
    );
    if (FAILED(hr)) {
        return false;
    }

    // ------------------------------------------------------------------
    // 2. Get the method's in-parameter class definition
    // ------------------------------------------------------------------
    ComPtr<IWbemClassObject> pInParamsDef;
    hr = pClass->GetMethod(_bstr_t(method), 0, &pInParamsDef.p, nullptr);
    if (FAILED(hr) || !pInParamsDef) {
        return false;
    }

    // ------------------------------------------------------------------
    // 3. Spawn an instance of the in-params object
    // ------------------------------------------------------------------
    ComPtr<IWbemClassObject> pInParams;
    hr = pInParamsDef->SpawnInstance(0, &pInParams.p);
    if (FAILED(hr)) return false;

    // ------------------------------------------------------------------
    // 4. Build a SAFEARRAY<BSTR> with the single exclusion value
    //    MSFT_MpPreference::Add / Remove accept string arrays
    // ------------------------------------------------------------------
    {
        SAFEARRAY* sa = SafeArrayCreateVector(VT_BSTR, 0, 1);
        if (!sa) return false;
        SafeArrayGuard saGuard(sa);

        LONG idx = 0;
        BSTR bval = SysAllocStringLen(value.data(), static_cast<UINT>(value.size()));
        if (!bval) return false;

        hr = SafeArrayPutElement(sa, &idx, bval);
        SysFreeString(bval);
        if (FAILED(hr)) return false;

        VARIANT varParam;
        VariantInit(&varParam);
        varParam.vt     = VT_ARRAY | VT_BSTR;
        varParam.parray = sa;
        // Transfer ownership to variant before setting on IWbemClassObject
        // (VariantClear on the local var is handled below)

        hr = pInParams->Put(_bstr_t(paramName), 0, &varParam, 0);
        // Don't VariantClear here — parray still owned by saGuard.
        // Zero out the variant's parray so VariantClear doesn't double-free.
        varParam.parray = nullptr;
        VariantClear(&varParam);

        if (FAILED(hr)) {
            return false;
        }
        // saGuard destructs here, SafeArrayDestroy called
    }

    // ------------------------------------------------------------------
    // 5. Execute the static method on MSFT_MpPreference
    // ------------------------------------------------------------------
    ComPtr<IWbemClassObject> pOutParams;
    hr = m_pSvc->ExecMethod(
        _bstr_t(L"MSFT_MpPreference"),
        _bstr_t(method),
        0, nullptr,
        pInParams.p,
        &pOutParams.p,
        nullptr
    );

    if (FAILED(hr)) {
        return false;
    }

    // ------------------------------------------------------------------
    // 6. Check ReturnValue (0 = success)
    // ------------------------------------------------------------------
    if (pOutParams) {
        VariantGuard varRet;
        hr = pOutParams->Get(L"ReturnValue", 0, &varRet.v, nullptr, nullptr);
        if (SUCCEEDED(hr) && varRet.v.vt == VT_I4 && varRet.v.lVal != 0) {
            return false;
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// Query live MSFT_MpPreference instance for existing exclusions
// ---------------------------------------------------------------------------

std::vector<std::wstring> WmiDefenderClient::QueryExclusionArray(const wchar_t* paramName) noexcept
{
    std::vector<std::wstring> result;
    if (!m_pSvc) return result;

    // Singleton instance path: MSFT_MpPreference=@
    ComPtr<IWbemClassObject> pInst;
    HRESULT hr = m_pSvc->GetObject(
        _bstr_t(L"MSFT_MpPreference=@"),
        WBEM_FLAG_RETURN_WBEM_COMPLETE,
        nullptr,
        &pInst.p,
        nullptr);
    if (FAILED(hr) || !pInst) return result;

    VariantGuard var;
    hr = pInst->Get(paramName, 0, &var.v, nullptr, nullptr);
    if (FAILED(hr)) return result;

    // Property may be NULL when no exclusions are set
    if (var.v.vt == VT_NULL || var.v.vt == VT_EMPTY) return result;

    if ((var.v.vt & VT_ARRAY) == 0 || (var.v.vt & VT_BSTR) == 0) return result;

    SAFEARRAY* sa = var.v.parray;
    if (!sa) return result;

    LONG lBound = 0, uBound = -1;
    SafeArrayGetLBound(sa, 1, &lBound);
    SafeArrayGetUBound(sa, 1, &uBound);

    for (LONG i = lBound; i <= uBound; ++i) {
        BSTR bval = nullptr;
        if (SUCCEEDED(SafeArrayGetElement(sa, &i, &bval)) && bval) {
            result.emplace_back(bval);
            SysFreeString(bval);
        }
    }
    return result;
}

bool WmiDefenderClient::HasExclusion(ExclusionType type, std::wstring_view value) noexcept
{
    auto entries = QueryExclusionArray(ParamNameFor(type));
    if (entries.empty()) return false;

    // Case-insensitive comparison — Defender stores paths/names in original case
    std::wstring needle(value);
    const auto wideLower = [](wchar_t c) -> wchar_t {
        return static_cast<wchar_t>(::towlower(c));
    };
    std::transform(needle.begin(), needle.end(), needle.begin(), wideLower);

    for (auto& entry : entries) {
        std::wstring lower = entry;
        std::transform(lower.begin(), lower.end(), lower.begin(), wideLower);
        if (lower == needle) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

const wchar_t* WmiDefenderClient::ParamNameFor(ExclusionType type) noexcept
{
    switch (type) {
        case ExclusionType::Path:      return L"ExclusionPath";
        case ExclusionType::Process:   return L"ExclusionProcess";
        case ExclusionType::Extension: return L"ExclusionExtension";
        case ExclusionType::IpAddress: return L"ExclusionIpAddress";
    }
    return L"ExclusionPath"; // unreachable
}
