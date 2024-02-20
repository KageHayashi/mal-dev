#include <iostream>
#include <windows.h>
#include <wlanapi.h>
#include <wtypes.h>
#include <stdexcept>
#include "pugixml.hpp"

#pragma comment(lib, "Wlanapi.lib")

int main()
{
    HANDLE handle;
    DWORD negotiatedVersion;
    DWORD clientVersion = 2;
    DWORD result = WlanOpenHandle(clientVersion, NULL, &negotiatedVersion, &handle);

    if (result != ERROR_SUCCESS) {
        throw std::runtime_error("Failed to open WLAN handle.");
    }

    WLAN_INTERFACE_INFO_LIST* interfaceList = NULL;
    result = WlanEnumInterfaces(handle, NULL, &interfaceList);
    if (result != ERROR_SUCCESS) {
        WlanCloseHandle(handle, NULL);
        throw std::runtime_error("Failed to enumerate WLAN interfaces.");
    }

    if (interfaceList->dwNumberOfItems == 0) {
        std::cout << "[-] No Interfaces Found. Exiting..." << std::endl;
        return 0;
    }

    std::cout << "[+] Found " << interfaceList->dwNumberOfItems << " Interfaces" << std::endl;

    for (DWORD i = 0; i < interfaceList->dwNumberOfItems; i++) {
        WLAN_INTERFACE_INFO interfaceInfo = interfaceList->InterfaceInfo[i];

        WLAN_PROFILE_INFO_LIST* profileList = NULL;
        result = WlanGetProfileList(handle, &interfaceInfo.InterfaceGuid, NULL, &profileList);
        if (result != ERROR_SUCCESS) {
            WlanFreeMemory(interfaceList);
            WlanCloseHandle(handle, NULL);
            throw std::runtime_error("Failed to get WLAN profile list.");
        }

        std::cout << "[+] Found " << profileList->dwNumberOfItems << " SSIDs" << std::endl;

        for (DWORD j = 0; j < profileList->dwNumberOfItems; j++) {
            WLAN_PROFILE_INFO profileInfo = profileList->ProfileInfo[j];

            WCHAR* wifiProfileXml = profileInfo.strProfileName;
            //std::cout << wifiProfileXml << "\n";
            DWORD flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
            DWORD out;
            result = WlanGetProfile(handle, &interfaceInfo.InterfaceGuid, wifiProfileXml, NULL, &wifiProfileXml, &flags, &out);
            if (result != ERROR_SUCCESS) {
                WlanFreeMemory(profileList);
                WlanFreeMemory(interfaceList);
                WlanCloseHandle(handle, NULL);
                throw std::runtime_error("Failed to get WLAN profile.");
            }

            std::string wifiProfileStr(wifiProfileXml, wifiProfileXml + wcslen(wifiProfileXml));

            pugi::xml_document doc;
            pugi::xml_parse_result result = doc.load_string(wifiProfileStr.c_str());
            if (!result)
                throw std::runtime_error("Failed to read Wifi XML String.");

            pugi::xml_node root = doc.document_element();
            pugi::xml_node nameNode = root.child("name");
            pugi::xml_node keyNode = root.child("MSM").child("security").child("sharedKey").child("keyMaterial");

            std::cout << std::endl;
            std::cout << "Name: " << nameNode.child_value() << std::endl;
            std::cout << "Pass: " << keyNode.child_value() << std::endl;
        }
    }

    return 0;
}
