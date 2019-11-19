###
SSH
###

Don't check the host key (disables prompt when connecting to a server for the first time):

.. code-block:: none

    ssh -o "StrictHostKeyChecking=no" <hostname>

Force key-based authentication (no password prompt):

.. code-block:: none

    ssh -o "IdentitiesOnly=yes" -i <private-key> <hostname>

Force password authentication:

.. code-block:: none

    ssh -o "PreferredAuthentications=password" -o "PubkeyAuthentication=no" <hostname>
