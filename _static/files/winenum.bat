@echo OFF
echo ----------------------------------------------
echo Windows Enumeration Script v1.1
echo ----------------------------------------------
echo By absolomb
echo ----------------------------------------------
echo creating temp folder to dump output at C:\temp
mkdir C:\temp
echo.
set OS=1
echo. 
echo 1: Vista/2003SP2 and newer(default)
echo 2: XP/2003
echo Choose 1 or 2
set /p OS="Choose OS: "

echo ----------------------------------------------
echo Basic System Info
echo ----------------------------------------------
systeminfo

echo.
echo ----------------------------------------------
echo Network Information
echo ----------------------------------------------
ipconfig /all

echo.
echo ---------------------------------------------- 
echo ARP table
echo ----------------------------------------------
arp -a

echo. 
echo ----------------------------------------------
echo Routing table
echo ----------------------------------------------
route print

echo.
echo ----------------------------------------------
echo Network Connections
echo ----------------------------------------------
netstat -ano

echo.
echo ----------------------------------------------
echo Mapped Drives
echo ----------------------------------------------
net use

echo.
echo ----------------------------------------------
echo Firewall State
echo ----------------------------------------------
netsh firewall show state

echo.
echo ----------------------------------------------
echo Firewall Config
echo ----------------------------------------------
netsh firewall show config

echo.
echo ----------------------------------------------
echo Local Users
echo ----------------------------------------------
net users

if "%OS%" == "1" (
    echo.
    echo ----------------------------------------------
    echo User Home Directories
    echo ----------------------------------------------
    dir /b /ad "C:\Users\"
)

if "%OS%" == "2" (
    echo.
    echo ----------------------------------------------
    echo User Home Directories
    echo ----------------------------------------------
    echo.
    dir /b /ad "C:\Documents and Settings\"
)

echo.
echo ----------------------------------------------
echo Local Groups
echo ----------------------------------------------
net localgroup

echo.
echo ----------------------------------------------
echo Users in Administrators Group
echo ----------------------------------------------
net localgroup Administrators

echo.
echo ----------------------------------------------
echo Environment Variables
echo ----------------------------------------------
set

echo.
echo ----------------------------------------------
echo Looking for backup SAM files
echo ----------------------------------------------
echo.
dir %SYSTEMROOT%\repair\SAM
dir %SYSTEMROOT%\system32\config\regback\SAM

echo. 
echo ----------------------------------------------
echo Installed Software Directories
echo ----------------------------------------------
echo.
dir  "C:\Program Files"
echo.
dir  "C:\Program Files (x86)"

if "%OS%" == "1" (
    echo.
    echo ----------------------------------------------
    echo Searching for Modify or Full Permissions in Program Files Directories
    echo ----------------------------------------------
    echo.
    echo Folders with Full Permissions for Everyone
    echo ----------------------------------------------
    echo.
    icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone" 
    icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone" 

    echo.
    echo Folders with Modify Permissions for Everyone
    echo ----------------------------------------------
    echo.
    icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone" 
    icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone" 

    echo.
    echo Folders with Full Permissions for BUILTIN\Users
    echo ----------------------------------------------
    echo.
    icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 
    icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 

    echo.
    echo Folders with Modify Permissions for BUILTIN\Users
    echo ----------------------------------------------
    echo.
    icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
    icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
)

if "%OS%" == "2" (
    echo.
    echo ----------------------------------------------
    echo Searching for Modify or Full Permissions in Program Files Directories 
    echo ----------------------------------------------
    echo.
    echo Folders with Full Permissions for Everyone
    echo ----------------------------------------------
    echo.
    cacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone" 
    cacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone" 

    echo.
    echo Folders with Modify Permissions for Everyone
    echo ----------------------------------------------
    echo.
    cacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone" 
    cacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone" 

    echo.
    echo Folders with Full Permissions for BUILTIN\Users
    echo ----------------------------------------------
    echo.
    cacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 
    cacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 

    echo.
    echo Folders with Modify Permissions for BUILTIN\Users
    echo ----------------------------------------------
    echo.
    cacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
    cacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
)

echo.
echo ----------------------------------------------
echo Software in registry
echo ----------------------------------------------
reg query HKEY_LOCAL_MACHINE\SOFTWARE

echo.
echo ----------------------------------------------
echo Scheduled Tasks
echo ----------------------------------------------
echo.
schtasks /query /fo LIST 2>nul | findstr TaskName
echo.
dir C:\windows\tasks
echo.
echo Check the log file at C:\Windows\schedlgu.txt 


echo.
echo ----------------------------------------------
echo Running Processes
echo ----------------------------------------------
tasklist /svc

echo.
echo ----------------------------------------------
echo Services
echo ----------------------------------------------
echo.
net start

echo.
echo ----------------------------------------------
echo Search for Unquoted Service Paths using WMI
echo ----------------------------------------------
echo.
wmic service get name,displayname,pathname,startmode 2>nul |findstr /i "Auto" 2>nul |findstr /i /v "C:\Windows\\" 2>nul |findstr /i /v """

echo.
echo ----------------------------------------------
echo Anything in Registry for User Autologon?
echo ----------------------------------------------
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"

echo.
echo ----------------------------------------------
echo Checking registry for AlwaysInstallElevated.. 
echo ----------------------------------------------
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

echo.
echo ----------------------------------------------
echo Interesting Files dumping to C:\temp\files.txt
echo ----------------------------------------------
echo.

cd C:\
echo Looking for sysprep and unattend files..
echo.
echo sysprep and unattend files > C:\temp\files.txt
echo. >> files.txt
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul >> C:\temp\files.txt 

echo.
echo Looking for any web.config files..
echo web.config files >> C:\temp\files.txt
echo. >> C:\temp\files.txt
dir /s web.config >> C:\temp\files.txt 2>nul

echo.
echo Looking for any other interesting files..
echo Other files >> C:\temp\files.txt
dir /s *pass* == *cred* == *vnc* == *.config* 2>nul >> C:\temp\files.txt 

echo.
echo ----------------------------------------------
echo Mentions of password in the registry dumping to C:\temp\reg.txt
echo ----------------------------------------------

echo HKCU Password Search > C:\temp\reg.txt
reg query HKCU /f password /t REG_SZ /s >> C:\temp\reg.txt
echo. >> C:\temp\reg.txt
echo. >> C:\temp\reg.txt
echo HKLM Password Search >> C:\temp\reg.txt
reg query HKLM /f password /t REG_SZ /s >> C:\temp\reg.txt

echo.
echo ----------------------------------------------
echo Files with password dumping to C:\temp\password.txt
echo ----------------------------------------------
echo.
findstr /si password *.xml *.ini *.txt *.config 2>nul > C:\temp\password.txt 

echo.
echo ----------------------------------------------
echo Script done!
echo Check your files at C:\temp\
