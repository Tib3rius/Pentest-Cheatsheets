#########
Man Pages
#########

Sometimes a program won't give you it's -\\-help text over a limited shell. Obviously we also can't use man pages, which load with the less program. However we can tell man to use cat to display these files:

.. code-block:: none

    man -P cat program
