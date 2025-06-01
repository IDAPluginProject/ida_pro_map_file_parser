#include "dllmain.h"

std::wstring CPluginMain::ConvertToWString(const std::string& s)
{
    if (s.empty())
        return std::wstring();

    int bufSize = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (bufSize <= 0)
        return std::wstring();

    std::wstring result(bufSize, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &result[0], bufSize);
    return result;
}

std::string CPluginMain::ConvertToUtf8(const std::wstring& wstr)
{
    if (wstr.empty()) return {};

    int bufsize = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (bufsize <= 0)
        return {};

    std::string result(bufsize - 1, 0); // exclude null terminator
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], bufsize, nullptr, nullptr);
    return result;
}

bool CPluginMain::PromptForFile()
{
    const char* filePath = ask_file(false, "*.map", "Select a .map file to parse");
    if (!filePath)
        return false;

    m_wFilePath = ConvertToWString(filePath);
    return !m_wFilePath.empty();
}

bool CPluginMain::OpenAndParseFile()
{
    std::wifstream file(m_wFilePath);
    if (!file.is_open())
    {
        msg("[MapFileParser] Unable to open file: %ls\n", m_wFilePath.c_str());
        return false;
    }

    m_symbolCount = 0;

    std::wstring line;
    while (std::getline(file, line))
    {
        if (ParseLine(line))
            ++m_symbolCount;
    }

    file.close();
    return true;
}

bool CPluginMain::ParseLine(const std::wstring& line)
{
    static const std::wregex pattern(L"\\s*(\\d+):([a-fA-F0-9]+)\\s+(\\S+)\\s+([a-fA-F0-9]{4,16})\\s+(.+)");
    std::wsmatch matches;

    if (!std::regex_search(line, matches, pattern) || matches.size() != 6)
        return false;

    std::wstring symbolName = matches[3].str();
    std::wstring hexAddr = matches[4].str();

    ea_t address;
    if (!ConvertAddress(hexAddr, address))
        return false;

    if (segment_t* seg = getseg(address); seg != nullptr)
    {
        set_name(address, ConvertToUtf8(symbolName).c_str(), SN_NOWARN);
        return true;
    }

    return false;
}

bool CPluginMain::ConvertAddress(const std::wstring& hexStr, ea_t& outAddress)
{
    try
    {
        if (hexStr.length() <= 8)
        {
            outAddress = static_cast<ea_t>(std::stoul(hexStr, nullptr, 16));
        }
        else
        {
            outAddress = static_cast<ea_t>(std::stoull(hexStr, nullptr, 16));
        }
        return true;
    }
    catch (const std::exception& ex)
    {
        msg("[MapFileParser] Address parse error: %s\n", ex.what());
    }
    catch (...)
    {
        msg("[MapFileParser] Unknown error while parsing address\n");
    }

    return false;
}

bool CPluginMain::Run()
{
    if (!PromptForFile())
    {
        msg("[MapFileParser] No file selected or invalid path.\n");
        return false;
    }

    if (!OpenAndParseFile())
    {
        msg("[MapFileParser] Failed during parsing.\n");
        return false;
    }

    msg("[MapFileParser] Symbols processed: %zu\n", m_symbolCount);
    return true;
}

static CPluginMain* g_CPluginMain = nullptr;
static plugmod_t* idaapi init() 
{
    g_CPluginMain = new CPluginMain();

    return PLUGIN_OK;
}

void idaapi term() 
{
    delete g_CPluginMain;
}


bool idaapi run(size_t arg) 
{
    bool isSuccessful = g_CPluginMain->Run();
    if (!isSuccessful)
    {
        msg("[MapFileParser] plugin did not ran\n");
    }

    return true;
}
// Plugin description
__declspec(dllexport) plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_PROC | PLUGIN_MOD,         // Plugin flags
    init,               // Initialization function
    term,               // Cleanup function
    run,                // Main function
    "loads map file",
    "",
    "IDA .map file parser ",
    "Ctrl-M"
};
