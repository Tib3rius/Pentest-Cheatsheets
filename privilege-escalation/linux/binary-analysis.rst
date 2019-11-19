###############
Binary Analysis
###############

strings
=======

Search for printable strings of characters in binaries:

.. code-block:: none

    strings /path/to/binary

strace
======

Trace system calls and signals in a process:

.. code-block:: none

    strace ./path/to/binary --argument arg

ltrace
======

Trace library calls in a process:

.. code-block:: none

    ltrace ./path/to/binary --argument arg
