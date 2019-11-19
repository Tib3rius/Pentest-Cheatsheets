######
Netcat
######

On Linux, netcat will send an LF character when enter/return is pressed. Several services (e.g. smtp, pop3) expect a CRLF instead. Force netcat to send a CRLF with the -C flag:

.. code-block:: none

    nc -C -nv 10.0.0.1 25
