#############################
Penetration Testing Checklist
#############################

This page serves as an overly simplified checklist for the entire penetration testing process, from initial enumeration to the final privilege escalation.

Enumeration
===========

* Run nmap scans with service/version detection.

    * From the result of those scans, perform further enumeration scans of identified services.
    * If there are any web servers, start running dirsearch with larger wordlists.

* Check version numbers of services against the Exploit Database and Google.
* Starting with less complex services, perform manual enumeration. Leave any web servers last.


Web Apps
========

* Ensure that dirsearch has been run with a huge wordlist, and various file extensions.
* Manually browse the app while proxying via Burp.

    * Use Burp Spider to crawl the site as you browse.

* Check for LFI if pages are being loaded dynamically.

    * If possible, can we get shell? I.e. apache log pollution, or using php filters to inject content.

* If there's some kind of login form prohibiting entry, try SQL injection, brute-force, etc.
