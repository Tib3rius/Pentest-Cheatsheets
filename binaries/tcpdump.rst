#######
tcpdump
#######

Save tcpdump as a pcap file
---------------------------

**Useful for when you want to view the capture in Wireshark**

.. code-block:: none

    tcpdump -s0 -i eth0 -w capture.pcap
    
**Disable name resolution (-n)**

.. code-block:: none

    tcpdump -n -s0 -i -eth0 -w capture.pcap
    
**Filter traffic to specific host (note: use BPF)**

.. code-block:: none

    tcpdump -n -s0 -i eth0 -w capture.pcap host 192.168.1.1
    
**Filter traffic to ports (note: use BPF)**

.. code-block:: none

    tcpdump -n -s0 -i eth0 -w capture.pcap tcp port 445

**BPF guide**
