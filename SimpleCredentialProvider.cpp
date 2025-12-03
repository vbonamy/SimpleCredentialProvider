// SimpleCredentialProvider.cpp
// Credential Provider avec lancement d'agent Python NFC

#include <windows.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#include <shlguid.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <stdio.h>
#include <string>

#pragma comment(lib, "shlwapi.lib")

// Fonction de logging
void LogToFile(const wchar_t* message)
{
    FILE* file = nullptr;
    errno_t err = _wfopen_s(&file, L"C:\\SimpleCredentialProvider\\debug.log", L"a");
    if (file)
    {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fwprintf(file, L"[%02d:%02d:%02d] %s\n", st.wHour, st.wMinute, st.wSecond, message);
        fclose(file);
    }
}

// Fonction pour lancer l'agent Python et récupérer le login
bool LaunchNfcAgentAndGetUsername(std::wstring& username, std::wstring& errorMsg)
{
    LogToFile(L"LaunchNfcAgentAndGetUsername - Starting Python agent");

    // Chemin vers l'agent Python (à adapter)
    std::wstring pythonCmd = L"C:\\SimpleCredentialProvider\\nfc_agent.exe";

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    // Créer un pipe pour capturer stdout
    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
    {
        LogToFile(L"ERROR: Failed to create pipe");
        errorMsg = L"Erreur de création du pipe";
        return false;
    }

    // S'assurer que le handle de lecture n'est pas hérité
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = { 0 };

    // Lancer le processus Python
    wchar_t cmdLine[512];
    wcscpy_s(cmdLine, pythonCmd.c_str());

    BOOL success = CreateProcessW(
        NULL,
        cmdLine,
        NULL,
        NULL,
        TRUE,  // Hériter les handles
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    CloseHandle(hWritePipe);  // Fermer notre copie du pipe d'écriture

    if (!success)
    {
        DWORD errorCode = GetLastError();

        // Récupérer le message d'erreur Windows
        wchar_t* errorMessage = nullptr;
        FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPWSTR)&errorMessage,
            0,
            nullptr
        );

        // Obtenir le répertoire courant pour le contexte
        wchar_t currentDir[MAX_PATH] = { 0 };
        GetCurrentDirectoryW(MAX_PATH, currentDir);

        // Log détaillé avec toutes les informations
        wchar_t detailedLog[2048];
        swprintf_s(detailedLog,
            L"ERROR: Failed to launch Python process! "
            L"WinError=0x%08X (%s) | "
            L"Command='%s' | "
            L"CurrentDir='%s' | "
            L"hReadPipe=0x%p | "
            L"hWritePipe=0x%p",
            errorCode,
            errorMessage ? errorMessage : L"Unknown error",
            pythonCmd.c_str(),
            currentDir,
            hReadPipe,
            hWritePipe
        );

        LogToFile(detailedLog);

        // Libérer le buffer système
        if (errorMessage)
        {
            LocalFree(errorMessage);
        }

        CloseHandle(hReadPipe);
        errorMsg = L"Échec du lancement de l'agent Python (voir logs)";
        return false;
    }

    LogToFile(L"Python process launched, waiting for result...");

    // Attendre que le processus se termine (timeout 60 secondes)
    DWORD waitResult = WaitForSingleObject(pi.hProcess, 60000);

    if (waitResult == WAIT_TIMEOUT)
    {
        LogToFile(L"ERROR: Python agent timeout");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hReadPipe);
        errorMsg = L"Timeout - Badge non détecté";
        return false;
    }

    // Lire la sortie du processus
    char buffer[1024] = { 0 };
    DWORD bytesRead = 0;
    std::string output;

    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0)
    {
        buffer[bytesRead] = '\0';
        output += buffer;
    }

    CloseHandle(hReadPipe);

    // Vérifier le code de retour
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exitCode != 0)
    {
        wchar_t log[256];
        swprintf_s(log, L"ERROR: Python agent failed with exit code %d", exitCode);
        LogToFile(log);
        errorMsg = L"Échec de la lecture du badge";
        return false;
    }

    // Convertir la sortie en wstring et nettoyer
    int len = MultiByteToWideChar(CP_UTF8, 0, output.c_str(), -1, NULL, 0);
    if (len > 0)
    {
        wchar_t* wOutput = new wchar_t[len];
        MultiByteToWideChar(CP_UTF8, 0, output.c_str(), -1, wOutput, len);
        username = wOutput;
        delete[] wOutput;

        // Nettoyer (retirer espaces, retours chariot, etc.)
        size_t start = username.find_first_not_of(L" \t\r\n");
        size_t end = username.find_last_not_of(L" \t\r\n");
        if (start != std::wstring::npos && end != std::wstring::npos)
        {
            username = username.substr(start, end - start + 1);
        }

        wchar_t log[512];
        swprintf_s(log, L"Successfully retrieved username: %s", username.c_str());
        LogToFile(log);

        return !username.empty();
    }

    LogToFile(L"ERROR: Failed to convert output to wstring");
    errorMsg = L"Erreur de lecture du résultat";
    return false;
}

// GUID unique pour votre provider
static const GUID CLSID_SimpleCredentialProvider =
{ 0x12345678, 0x1234, 0x1234, { 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC } };

// Énumération des champs
enum SIMPLE_FIELD_ID
{
    SFI_LARGE_TEXT = 0,
    SFI_SUBMIT_BUTTON,
    SFI_NUM_FIELDS
};

wchar_t badgeMessage[] = L"En attente du badge NFC...";
wchar_t submitButton[] = L"Badger maintenant";

// Descriptions des champs
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgFieldDescriptors[] =
{
    { SFI_LARGE_TEXT, CPFT_LARGE_TEXT, badgeMessage, CPFG_CREDENTIAL_PROVIDER_LOGO },
    { SFI_SUBMIT_BUTTON, CPFT_SUBMIT_BUTTON, submitButton },
};


// Classe pour la tuile de connexion
class CSimpleCredential : public ICredentialProviderCredential
{
private:
    LONG m_cRef;
    std::wstring m_username;
    std::wstring m_password;
    ICredentialProviderCredentialEvents* m_pCredProvCredentialEvents;
    DWORD m_dwCredentialStatus;

public:
    CSimpleCredential() : m_cRef(1), m_pCredProvCredentialEvents(nullptr), m_dwCredentialStatus(0)
    {
        LogToFile(L"CSimpleCredential::Constructor");
    }

    ~CSimpleCredential()
    {
        LogToFile(L"CSimpleCredential::Destructor");
        if (m_pCredProvCredentialEvents)
        {
            m_pCredProvCredentialEvents->Release();
        }
    }

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv)
    {
        static const QITAB qit[] = {
            QITABENT(CSimpleCredential, ICredentialProviderCredential),
            { 0 },
        };
        return QISearch(this, qit, riid, ppv);
    }

    STDMETHODIMP_(ULONG) AddRef()
    {
        return InterlockedIncrement(&m_cRef);
    }

    STDMETHODIMP_(ULONG) Release()
    {
        LONG cRef = InterlockedDecrement(&m_cRef);
        if (!cRef) delete this;
        return cRef;
    }

    // ICredentialProviderCredential
    STDMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce)
    {
        LogToFile(L"CSimpleCredential::Advise");
        if (pcpce)
        {
            pcpce->AddRef();
            m_pCredProvCredentialEvents = pcpce;
        }
        return S_OK;
    }

    STDMETHODIMP UnAdvise()
    {
        LogToFile(L"CSimpleCredential::UnAdvise");
        if (m_pCredProvCredentialEvents)
        {
            m_pCredProvCredentialEvents->Release();
            m_pCredProvCredentialEvents = nullptr;
        }
        return S_OK;
    }

    STDMETHODIMP SetSelected(BOOL* pbAutoLogon)
    {
        LogToFile(L"CSimpleCredential::SetSelected");
        *pbAutoLogon = FALSE;
        return S_OK;
    }

    STDMETHODIMP SetDeselected()
    {
        LogToFile(L"CSimpleCredential::SetDeselected");
        return S_OK;
    }

    STDMETHODIMP GetFieldState(DWORD dwFieldID,
        CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
        CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
    {
        if (dwFieldID < SFI_NUM_FIELDS)
        {
            *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            *pcpfis = CPFIS_NONE;
            return S_OK;
        }
        return E_INVALIDARG;
    }

    STDMETHODIMP GetStringValue(DWORD dwFieldID, PWSTR* ppwsz)
    {
        HRESULT hr = E_INVALIDARG;

        if (dwFieldID == SFI_LARGE_TEXT && ppwsz)
        {
            hr = SHStrDupW(L"🔖 Authentification par Badge NFC", ppwsz);
        }
        else if (dwFieldID == SFI_SUBMIT_BUTTON && ppwsz)
        {
            hr = SHStrDupW(L"Badger maintenant", ppwsz);
        }

        return hr;
    }

    STDMETHODIMP GetBitmapValue(DWORD, HBITMAP*) { return E_NOTIMPL; }
    STDMETHODIMP GetCheckboxValue(DWORD, BOOL*, PWSTR*) { return E_NOTIMPL; }

    STDMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
    {
        if (dwFieldID == SFI_SUBMIT_BUTTON)
        {
            *pdwAdjacentTo = SFI_LARGE_TEXT;
            return S_OK;
        }
        return E_INVALIDARG;
    }

    STDMETHODIMP GetComboBoxValueCount(DWORD, DWORD*, DWORD*) { return E_NOTIMPL; }
    STDMETHODIMP GetComboBoxValueAt(DWORD, DWORD, PWSTR*) { return E_NOTIMPL; }
    STDMETHODIMP SetStringValue(DWORD, PCWSTR) { return E_NOTIMPL; }
    STDMETHODIMP SetCheckboxValue(DWORD, BOOL) { return E_NOTIMPL; }
    STDMETHODIMP SetComboBoxSelectedValue(DWORD, DWORD) { return E_NOTIMPL; }

    STDMETHODIMP CommandLinkClicked(DWORD dwFieldID)
    {
        LogToFile(L"CSimpleCredential::CommandLinkClicked - Not used with Submit Button");
        return E_NOTIMPL;
    }

    STDMETHODIMP GetSerialization(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        PWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
    {
        LogToFile(L"CSimpleCredential::GetSerialization - User clicked submit button");

        // Lancer l'agent Python maintenant !
        if (m_username.empty())
        {
            LogToFile(L"Username not set, launching NFC agent...");

            std::wstring errorMsg;
            if (!LaunchNfcAgentAndGetUsername(m_username, errorMsg))
            {
                LogToFile(L"ERROR: Failed to get username from NFC agent");
                *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                SHStrDupW(errorMsg.c_str(), ppwszOptionalStatusText);
                *pcpsiOptionalStatusIcon = CPSI_ERROR;
                return E_FAIL;
            }
        }

        if (m_username.empty())
        {
            LogToFile(L"ERROR: No username available after agent execution");
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            return E_FAIL;
        }

        wchar_t log[512];
        swprintf_s(log, L"Serializing credentials for user: %s", m_username.c_str());
        LogToFile(log);

        // Préparer la structure d'authentification
        KERB_INTERACTIVE_UNLOCK_LOGON kiul;
        ZeroMemory(&kiul, sizeof(kiul));

        kiul.Logon.MessageType = KerbInteractiveLogon;

        // Domaine (local par défaut)
        std::wstring domain = L".";

        // Allouer la mémoire pour les chaînes
        size_t cbDomain = (domain.length() + 1) * sizeof(wchar_t);
        size_t cbUsername = (m_username.length() + 1) * sizeof(wchar_t);
        size_t cbPassword = sizeof(wchar_t);  // Mot de passe vide pour l'instant

        size_t cbTotal = sizeof(kiul) + cbDomain + cbUsername + cbPassword;

        BYTE* rgbSerialization = (BYTE*)CoTaskMemAlloc(cbTotal);
        if (!rgbSerialization)
        {
            LogToFile(L"ERROR: Failed to allocate memory for serialization");
            return E_OUTOFMEMORY;
        }

        ZeroMemory(rgbSerialization, cbTotal);

        // Copier la structure
        KERB_INTERACTIVE_UNLOCK_LOGON* pkiul = (KERB_INTERACTIVE_UNLOCK_LOGON*)rgbSerialization;
        *pkiul = kiul;

        // Placer les chaînes après la structure
        BYTE* pbBuffer = rgbSerialization + sizeof(kiul);

        // Domaine
        pkiul->Logon.LogonDomainName.Length = (USHORT)(domain.length() * sizeof(wchar_t));
        pkiul->Logon.LogonDomainName.MaximumLength = (USHORT)cbDomain;
        pkiul->Logon.LogonDomainName.Buffer = (PWSTR)pbBuffer;
        memcpy(pbBuffer, domain.c_str(), cbDomain);
        pbBuffer += cbDomain;

        // Username
        pkiul->Logon.UserName.Length = (USHORT)(m_username.length() * sizeof(wchar_t));
        pkiul->Logon.UserName.MaximumLength = (USHORT)cbUsername;
        pkiul->Logon.UserName.Buffer = (PWSTR)pbBuffer;
        memcpy(pbBuffer, m_username.c_str(), cbUsername);
        pbBuffer += cbUsername;

        // Password (vide pour test - à remplir selon vos besoins)
        pkiul->Logon.Password.Length = 0;
        pkiul->Logon.Password.MaximumLength = (USHORT)cbPassword;
        pkiul->Logon.Password.Buffer = (PWSTR)pbBuffer;

        // Remplir la structure de sérialisation
        pcpcs->ulAuthenticationPackage = 0;  // Sera rempli par le système
        pcpcs->clsidCredentialProvider = CLSID_SimpleCredentialProvider;
        pcpcs->cbSerialization = (DWORD)cbTotal;
        pcpcs->rgbSerialization = rgbSerialization;

        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
        *pcpsiOptionalStatusIcon = CPSI_SUCCESS;
        SHStrDupW(L"Authentification...", ppwszOptionalStatusText);

        LogToFile(L"Serialization complete");
        return S_OK;
    }

    STDMETHODIMP ReportResult(
        NTSTATUS ntsStatus,
        NTSTATUS ntsSubstatus,
        PWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
    {
        wchar_t log[256];
        swprintf_s(log, L"CSimpleCredential::ReportResult - Status: 0x%08x", ntsStatus);
        LogToFile(log);
        return S_OK;
    }
};

// Classe principale du Credential Provider
class CSimpleProvider : public ICredentialProvider
{
private:
    LONG m_cRef;
    CSimpleCredential* m_pCredential;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_usageScenario;

public:
    CSimpleProvider() : m_cRef(1), m_pCredential(nullptr), m_usageScenario(CPUS_INVALID)
    {
        LogToFile(L"CSimpleProvider::Constructor");
    }

    ~CSimpleProvider()
    {
        LogToFile(L"CSimpleProvider::Destructor");
        if (m_pCredential)
        {
            m_pCredential->Release();
        }
    }

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv)
    {
        static const QITAB qit[] = {
            QITABENT(CSimpleProvider, ICredentialProvider),
            { 0 },
        };
        return QISearch(this, qit, riid, ppv);
    }

    STDMETHODIMP_(ULONG) AddRef()
    {
        return InterlockedIncrement(&m_cRef);
    }

    STDMETHODIMP_(ULONG) Release()
    {
        LONG cRef = InterlockedDecrement(&m_cRef);
        if (!cRef) delete this;
        return cRef;
    }

    // ICredentialProvider
    STDMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags)
    {
        wchar_t log[256];
        swprintf_s(log, L"CSimpleProvider::SetUsageScenario - Scenario=%d", cpus);
        LogToFile(log);

        m_usageScenario = cpus;

        return (cpus == CPUS_LOGON || cpus == CPUS_UNLOCK_WORKSTATION) ? S_OK : E_NOTIMPL;
    }

    STDMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*)
    {
        return E_NOTIMPL;
    }

    STDMETHODIMP Advise(ICredentialProviderEvents*, UINT_PTR)
    {
        return E_NOTIMPL;
    }

    STDMETHODIMP UnAdvise()
    {
        return E_NOTIMPL;
    }

    STDMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount)
    {
        *pdwCount = SFI_NUM_FIELDS;
        return S_OK;
    }

    STDMETHODIMP GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
    {
        if (dwIndex < SFI_NUM_FIELDS)
        {
            CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd =
                (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(*pcpfd));

            if (pcpfd)
            {
                *pcpfd = s_rgFieldDescriptors[dwIndex];
                SHStrDupW(s_rgFieldDescriptors[dwIndex].pszLabel, &pcpfd->pszLabel);
                *ppcpfd = pcpfd;
                return S_OK;
            }
            return E_OUTOFMEMORY;
        }
        return E_INVALIDARG;
    }

    STDMETHODIMP GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault)
    {
        *pdwCount = 1;
        *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
        *pbAutoLogonWithDefault = FALSE;
        return S_OK;
    }

    STDMETHODIMP GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc)
    {
        if (dwIndex == 0)
        {
            if (!m_pCredential)
            {
                m_pCredential = new CSimpleCredential();
            }
            m_pCredential->AddRef();
            *ppcpc = m_pCredential;
            return S_OK;
        }
        return E_INVALIDARG;
    }
};

// Factory class pour COM
class CSimpleProviderFactory : public IClassFactory
{
private:
    LONG m_cRef;

public:
    CSimpleProviderFactory() : m_cRef(1) {}

    STDMETHODIMP QueryInterface(REFIID riid, void** ppv)
    {
        if (riid == IID_IClassFactory || riid == IID_IUnknown)
        {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    STDMETHODIMP_(ULONG) AddRef()
    {
        return InterlockedIncrement(&m_cRef);
    }

    STDMETHODIMP_(ULONG) Release()
    {
        LONG cRef = InterlockedDecrement(&m_cRef);
        if (!cRef) delete this;
        return cRef;
    }

    STDMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv)
    {
        if (pUnkOuter) return CLASS_E_NOAGGREGATION;

        CSimpleProvider* pProvider = new CSimpleProvider();
        if (!pProvider) return E_OUTOFMEMORY;

        HRESULT hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
        return hr;
    }

    STDMETHODIMP LockServer(BOOL) { return S_OK; }
};

// Points d'entrée DLL
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
    if (rclsid == CLSID_SimpleCredentialProvider)
    {
        CSimpleProviderFactory* pFactory = new CSimpleProviderFactory();
        if (!pFactory) return E_OUTOFMEMORY;

        HRESULT hr = pFactory->QueryInterface(riid, ppv);
        pFactory->Release();
        return hr;
    }
    return CLASS_E_CLASSNOTAVAILABLE;
}

STDAPI DllCanUnloadNow()
{
    return S_OK;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        LogToFile(L"*** DLL_PROCESS_ATTACH - DLL loaded ***");
        DisableThreadLibraryCalls(hinstDLL);
        break;
    case DLL_PROCESS_DETACH:
        LogToFile(L"*** DLL_PROCESS_DETACH - DLL unloaded ***");
        break;
    }
    return TRUE;
}