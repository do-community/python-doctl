.. python-doctl documentation master file, created by
   sphinx-quickstart on Mon May 28 15:31:17 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

python-doctl
============

A Python wrapper for the excellent `doctl <https://github.com/digitalocean/doctl>`_ command-line utility, from
`Digital Ocean <https://digitalocean.com>`_.

-----------------------

This documentation exists to guide you through the usage of the `doctl <https://pypi.org/project/doctl/>`_ Python library — a Pythonic wrapper around the ``doctl`` command–line utility, for managing your `DigitalOcean <https://digitalocean.com/>`_ infrastructure.

Please enjoy!

Installation
------------

Fist, ensure you have ``doctl`` installed on your system, then you can add ``python-doctl`` to your project with `Pipenv <https://pipenv.org/>`_::

    $ pipenv install doctl

Introduction
------------

The ``DIGITALOCEAN_ACCESS_TOKEN`` environment variable will automatically be honored.

    $ export DIGITALOCEAN_ACCESS_TOKEN=xxxx

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

Alternatively, you can pass a token in explicitly:

    >>> from doctl import DigitalOcean
    >>> doctl = DigitalOcean(token="xxxxx")

Things to Know
++++++++++++++

- All reasonable ``doctl`` commands are available as methods on within the ``doctl`` module. Sub–commands are referenced with another method call (e.g. ``doctl.compute.ssh_key.list()``.
- All methods return Python data structures, includinging timezone–aware Datetime objects.

Notes
-----

Use of the ``DIGITALOCEAN_ACCESS_TOKEN`` environment variable is recommended.


API Documentation
=================

Main Interfaces
---------------

.. module:: doctl

The ``Compute`` class is the main interface to ``doctl``. A built in instance, ``doctl.compute`` is available at the module–level.


.. autoclass:: Compute
    :members:

This is also an `Account` class, for viewing your authentication information, as well as your rate–limiting. A built in instance, ``doctl.account`` is available at the module–level.

.. autoclass:: Account
    :members:

Low–Level Classes
-----------------

.. autoclass:: DigitalOcean
    :members:


Compute Classes
---------------

.. autoclass:: ComputeAction
    :members:

.. autoclass:: ComputeCertificate
    :members:

.. autoclass:: ComputeDroplet
    :members:

.. autoclass:: ComputeDomain
    :members:

.. autoclass:: ComputeDomainRecords
    :members:

.. autoclass:: ComputeFirewall
    :members:

.. autoclass:: ComputeFloatingIP
    :members:

.. autoclass:: ComputeFloatingIPAction
    :members:

.. autoclass:: ComputeImage
    :members:

.. autoclass:: ComputeImageAction
    :members:

.. autoclass:: ComputeLoadBalancer
    :members:

.. autoclass:: ComputePlugin
    :members:

.. autoclass:: ComputeSnapshot
    :members:

.. autoclass:: ComputeSSHKey
    :members:

.. autoclass:: ComputeTag
    :members:

.. autoclass:: ComputeVolume
    :members:

.. autoclass:: ComputeVolumeAction
    :members:

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
