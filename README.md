python-doctl
============

A Python wrapper for the excellent [doctl](https://github.com/slantview/doctl) command-line utility, from [Digital Ocean](https://digitalocean.com).

Usage
-----

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

Features
--------

- Automatically downloads `doctl`, if unavailable for your system (at runtime).

Available Namespaces
--------------------

The entire API surface of **doctl** is covered by this library, so the following
namespaces are available for your use and enjoyment:

- `compute.account`
- `compute.action`
- `compute.certificate`
- `compute.domain`
- `compute.domain_records`
- `compute.droplet`
- `compute.firewall`
- `compute.floating_ip`
- `compute.image`
- `compute.image_action`
- `compute.load_balancer`
- `compute.plugin`
- `compute.region_list`
- `compute.size_list`
- `compute.snapshot`
- `compute.ssh_key`
- `compute.tag`
- `compute.volume`
- `compute.volume_action`

✨🍰✨

Installation
------------

Coming soon!