#############
NetBIOS / SMB
#############

Usually ports 139 / 445.

**Lookup NetBIOS name for target**

.. code-block:: none

    nmblookup -A <target>

**List Shares**

Use the name identified by the previous command:

.. code-block:: none

    smbclient -L \\<name> -I <target>

**Connect to a share**

Use the share name identified by the previous command.

.. code-block:: none

    smbclient //<name>/<share> -I <target>

**Download files**

Once connected to a share:

.. code-block:: none

    dir
    get <filename>

Use ? for full list of commands.

**Download Files Recursively**

Once connected to a share:

.. code-block:: none

    mask ""
    recurse ON
    prompt OFF
    cd 'path\to\remote\dir'
    lcd '~/path/to/download/to/'
    mget *

One-liner:

.. code-block:: none

    smbclient //<name>/<share> -I <target> -c 'mark "";prompt OFF;recurse ON;cd "path\to\remote\dir";lcd "~/path/to/download/to/";mget *'

Alternative:

.. code-block:: none

    tarmode
    recurse
    prompt
    mget foldertocopy

**Mount SMB share using anonymous account**

.. code-block:: bash

    apt-get install cifsutil
    mount -t cifs -vvv -o username=guest,vers=1.0,uid=0 "//<ip>/<share>" <mount-point>
