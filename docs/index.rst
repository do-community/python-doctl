.. python-doctl documentation master file, created by
   sphinx-quickstart on Mon May 28 15:31:17 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

python-doctl
============

This documentation exists to guide you through the usage of the `doctl <https://pypi.org/project/doctl/>`_ Python library — a Pythonic wrapper around the ``doctl`` command–line utility, for managing your `DigitalOcean <https://digitalocean.com/>`_ infrastructure.

Please enjoy!

Installation
------------

::

    $ pipenv install doctl

If `doctl` isn't found on your system, the latest version will be bootstrapped automatically at runtime.

Example Usage
-------------

    >>> import doctl

    >>> for droplet in doctl.compute.droplet.list():
    ...     print(droplet['name'])
    pypi.kennethreitz.org
    code.kennethreitz.org
    build.kennethreitz.org
    …

    >>> for key in doctl.compute.ssh_key.list():
    ...     print(key['name'])
    Blink (iPad)
    thoth
    macbook


API Documentation
=================

Main Interface
--------------

.. module:: doctl

The ``Compute`` class is the main interface to ``doctl``. A built in instance, ``doctl.compute`` is available at the module–level.


.. autoclass:: Compute
    :members:

This is also an `Account` class, for viewing your authentication information, as well as your rate–limiting. A built in instance, ``doctl.account`` is available at the module–level.

.. autoclass:: Account
    :members:


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
