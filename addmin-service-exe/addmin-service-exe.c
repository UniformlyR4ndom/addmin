#include <windows.h>
#include <stdio.h>

#include "../addmin-shared/addmin-shared.h"

#define SERVICE_NAME TEXT("TestService")

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE hStatus;


void serviceMain(int argc, char** argv);
void controlHandler(DWORD request);

int main() {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {(LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)serviceMain},
        {NULL, NULL}
    };

    addminMain(NULL);

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
    SetServiceStatus(hStatus, &serviceStatus);
    return;
}
