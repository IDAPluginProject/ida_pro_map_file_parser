#pragma once
#include <Windows.h>
#include <stringapiset.h>
#include <stdio.h>
#include <regex>
#include <fstream>
#include <string>

#include <idp.hpp>
#include <loader.hpp>
#include <name.hpp>

class CPluginMain
{
private:
    std::wstring m_wFilePath;
    size_t m_symbolCount = 0;

public:
    CPluginMain() = default;
    bool Run();
private:
    static std::wstring ConvertToWString(const std::string& s);
    static std::string ConvertToUtf8(const std::wstring& wstr);
    bool PromptForFile();
    bool OpenAndParseFile();
    bool ParseLine(const std::wstring& line);
    bool ConvertAddress(const std::wstring& hexStr, ea_t& outAddress);
};