####################
Enumeration Overview
####################

* https://github.com/DigitalAftermath/EnumerationVisualized/wiki

Port Scanning
=============

reconnoitre
-----------

The following command will launch various nmap scans against the target host(s), create a helpful directory structure for tracking results, and offer suggestions for further enumeration.

.. code-block:: none

  reconnoitre -t <ip> -o <output-dir> --services

nmap
----

The following command will launch a full TCP port scan, with full version / OS detection and script scanning.

.. code-block:: none

   nmap -vv -Pn -sS -A -sC -p 0-65535 -T4 --osscan-guess --version-all --script-args=unsafe=1 -oA <output> <target>


The following command will launch a UDP port scan of the top 200 UDP ports, with full version detection and script scanning.

.. code-block:: none

    nmap -vv -Pn -sC -sV -sU -T4 --top-ports 200 --version-all --max-retries 1 -oA <output> <target>

For slow hosts, use limited version scanning:

.. code-block:: none

    nmap -vv -Pn -sC -sV -sU -T4 --top-ports 200 --version-light --max-retries 1 -oA <output> <target>


Useful Commands
---------------

Quickly extract port scan results + service names from nmap scans:

.. code-block:: none

    grep -Eh "^[0-9]+/(tcp|udp)" *.nmap | sort -un

Enumerate SMB/samba version and OS info:

.. code-block:: none

    nmap -Pn -sV -p 445,139 --script=smb-os-discovery <target>

Run commands against a Windows box that is running MSSQL (credentials + xp_cmdshell required):

.. code-block:: none

    nmap -Pn -sV -p <mssql-port> --script=ms-sql-xp-cmdshell --script-args=mssql.username=<username>,mssql.password=<password>,ms-sql-xp-cmdshell.cmd=<cmd> <target>
