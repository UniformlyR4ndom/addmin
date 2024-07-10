# Why
Instead of hardcoding a password into an executable it may be preferable to read the password from a config file that can easily be deleted, even if a handle to the e.g. DLL remains (preventing deleting it).
All the executables read the username and password (and optionally SIDs for groups to add the new user to) from a config file.
This config file es encrypted (or obfuscated) using a hard-coded key.
As soon as the user was added successfully, the config file is deleted.

# Usage
+ build executables and DLL
+ place executable / DLL where it will be executed / lodaded
+ generate config: `python3 genconfig -u <username> -p <password> [-s <SID>]`
+ name config file (by default pwn.txt) to match the name of the EXE / DLL but change the extension to `.pwn`
+ place the renamed config file besides the EXE / DLL

## Example config
```
username=demouser
password=R34llySecur3P455w0rd
groupsid=S-1-5-32-544
groupsid=S-1-5-32-555
```