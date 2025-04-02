#include <Windows.h>
#include <stringapiset.h>
#include <stdio.h>
#include <regex>
#include <fstream>
#include <string>
#include <idp.hpp>
#include <loader.hpp>
#include <name.hpp>


// the plugin class inheriting from plugmod_t
class MapFilePerser_t : public plugmod_t
{
private:
     static std::wstring ConvertToWString(const std::string& s) 
     {
         if (s.empty())
         {
             return std::wstring();
         }
        // Get the required buffer size (in wchar_t units)
        int buf = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
        if (buf <= 0)
        {
            return std::wstring();
        }

        std::wstring ret(buf, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &ret[0], buf);
        return ret;
    }
public:
    virtual bool idaapi run(size_t arg) override
    {
        // prompt the user to select a .map file
        const char* filePath = ask_file(false, "*.map", "select a .map file for paring");
        if (!filePath)
        {
            msg("[MapFilePerser]: no .map file selected.\n");
            return true;
        }

        auto wFilePath = ConvertToWString(filePath);
        if (wFilePath.empty())
        {
            msg("[MapFilePerser]: invalid .map file path.\n");
            return true;
        }

        // Open the selected .map file
        std::wifstream file(wFilePath);
        if (!file.is_open())
        {
            msg("[MapFilePerser]: failed to open the .map file.\n");
            return true;
        }

        // expression to match lines in the .map file
        std::wregex pattern(L"\\s*(\\d+):([a-fA-F0-9]+)\\s+(\\S+)\\s+([a-fA-F0-9]{4,16})\\s+(.+)");
        std::wstring buffer;
        size_t count = 0;

        // read the file line by line
        while (std::getline(file, buffer))
        {
            std::wsmatch matches;
            if (std::regex_search(buffer, matches, pattern) && matches.size() == 6)
            {
                // Extract symbol name and address
                std::wstring name = matches[3].str();
                std::wstring stringAddr = matches[4].str();

                // Convert addresses from hex string to uint
                ea_t address = 0;
                try
                {
                    uint32_t temp32 = std::stoul(stringAddr, nullptr, 16);
                    address = static_cast<ea_t>(temp32);
                }
                catch (const std::out_of_range&)
                {
                    uint64_t temp64 = std::stoull(stringAddr, nullptr, 16);
                    address = static_cast<ea_t>(temp64);
                }
                catch (const std::exception& ex)
                {
                    msg("[MapFilePerser]: exception: %s\n", ex.what());
                    continue;
                }
                catch (...)
                {
                    msg("[MapFilePerser]: caught C++ exceptions while parsing\n");
                    continue;
                }

                // verify the address is within a valid segment
                segment_t* seg = getseg(address);
                if (seg != nullptr)
                {
                    // Rename the symbol at the address
                    set_name(address, std::string(name.begin(), name.end()).c_str(), SN_NOWARN);
                    count++;
                }
            }
        }

        // clean up and report the result
        file.close();
        msg("[MapFilePerser]: number of symbols processed %d.\n", count);
        return true;
    }
};

// plugin initialization function
plugmod_t* idaapi init(void)
{
    return new MapFilePerser_t();
}

// Plugin description
__declspec(dllexport) plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MOD | PLUGIN_MULTI,         // Plugin flags
    init,               // Initialization function
    nullptr,               // Cleanup function
    nullptr,                // Main function
    "loads map file",
    "",
    "IDA .map file parser ",
    "Ctrl-M"
};
