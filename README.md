# Why
Instead of hardcoding a password into an executable it may be preferable to read the password from a config file that can easily be deleted, even if a handle to the e.g. DLL remains (preventing deleting it).
All the executables read the username and password (and optionally SIDs for groups to add the new user to) from a config file.
This config file es encrypted (or obfuscated) using a hard-coded key.
As soon as the user was added successfully, the config file is deleted.

# Usage
+ build executables and DLL
+ place executable / DLL where it will be executed / lodaded
+ generate config: `python3 genconfig.py -u <username> -p <password> [-s <SID>] [-x]`
+ name config file (by default pwn.txt) to match the name of the EXE / DLL but change the extension to `.pwn`
+ place the renamed config file besides the EXE / DLL

## Fallback
In case reading the config file causes problems, a fallback configuration (encoded in a hex string) can be hardcoded.
To achieve this, simply define the macro `ADDMIN_FALLBACK_CONFIG` and then define `CONFIG_DEFAULT` to the hex string rrepresenting the config.

Example:
```
#define ADDMIN_FALLBACK_CONFIG
#define CONFIG_DEFAULT "576cb400ebd5a89499a955d22854ef155365e092ec9612f20c2673aa6ccc6213905b0869537bdbad3abe485fbb27595f773824e3cee952be04e16c4d221572ed1dbc49b8c4762ed0a792d4e31aee42646b24dbfb269c863de90f2e"
```

## Example config
### Plaintext
```
username=demouser
password=R34llySecur3P455w0rd
groupsid=S-1-5-32-544
groupsid=S-1-5-32-555
```

### Encrypted
```
xxd pwn.txt                                                        
00000000: 576c b400 ebd5 a894 99a9 55d2 2854 ef15  Wl........U.(T..
00000010: 5365 e092 ec96 12f2 0c26 73aa 6ccc 6213  Se.......&s.l.b.
00000020: 905b 0869 537b dbad 3abe 485f bb27 595f  .[.iS{..:.H_.'Y_
00000030: 7738 24e3 cee9 52be 04e1 6c4d 2215 72ed  w8$...R...lM".r.
00000040: 1dbc 49b8 c476 2ed0 a792 d4e3 1aee 4264  ..I..v........Bd
00000050: 6b24 dbfb 269c 863d e90f 2e              k$..&..=...
```