###############
Cracking Hashes
###############

john
====

:download:`PDF Cheatsheet <../_static/files/jtr-cheat-sheet.pdf>`

List Formats
------------

.. code-block:: none

  john --list=formats

Brute Force (Incremental) Mode
------------------------------

This is the default cracking mode and will try all possible character combinations.

.. code-block:: none

  john --format=<format> hashes.txt

Dictionary / Wordlist Mode
--------------------------

.. code-block:: none

  john --format=<format> --wordlist=/path/to/wordlist hashes.txt


Combine /etc/passwd and /etc/shadow file for john
-------------------------------------------------

.. code-block:: none

    unshadow /path/to/passwd /path/to/shadow > <output-file>

Password Dictionaries
=====================

* https://hashes.org/
