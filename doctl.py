import io
import json
import logging
import os
import re
import sys
import tarfile
from tempfile import NamedTemporaryFile

import delegator
import maya


class DOCtlError(RuntimeError):
    def __init__(self, c):
        self.c = c
        self.output = c.out



def system_which(command, mult=False):
    """Emulates the system's which. Returns None if not found."""
    _which = "which -a" if not os.name == "nt" else "where"
    c = delegator.run("{0} {1}".format(_which, command))
    try:
        # Which Not found...
        assert c.return_code == 0
    except AssertionError:
        return None if not mult else []

    result = c.out.strip() or c.err.strip()
    if mult:
        return result.split("\n")

    else:
        return result.split("\n")[0]


def datetime_parser(dct):
    for k, v in dct.items():
        try:
            if "-" in v and ":" in v:
                dct[k] = maya.parse(v).datetime()
        except Exception:
            pass
    return dct


class DigitalOcean:
    """The DigitalOcean Client. Used to make all calls to doctcl.

    ``token`` is optional — if none is given, the system-configured
    authentication will be used, or the ``DIGITALOCEAN_ACCESS_TOKEN``
    environment variable will be honored.
    """

    def __init__(self, token=None):
        self.token = token
        self.compute = Compute(do=self)

    def doctl(self, *args, expect_json=True):
        """Runs doctl, with provided arguments.

        if ``expect_json`` is False, the ``delegator`` subprocess is returned.
        Otherwise, JSON output will be parsed and the results will be returned.

        Return–code is always asserted to be ``0``.
        """

        doctl_location = system_which("doctl")
        if not doctl_location:
            raise RuntimeError('doctl does not appear to be installed and on your PATH!')

        if expect_json:
            args = list(args)
            args.extend(["--output", "json"])

        if self.token:
            args = list(args)
            args.extend(["--access-token", self.token])

        args = " ".join(args)
        cmd = f"doctl {args}"

        logging.info(cmd)

        c = delegator.run(cmd)
        try:
            assert c.return_code == 0
        except AssertionError:
            print(c.out)
            raise DOCtlError(c)

        if not expect_json:
            return c
        else:
            return json.loads(c.out, object_hook=datetime_parser)


class ComputeAction:
    """action is used to access action commands."""

    def __init__(self, do):
        self.do = do

    def get(self, action_id):
        """get action."""
        return self.do.doctl("compute", "action", "get", action_id)

    def wait(self, action_id):
        """wait for action to complete."""
        return self.do.doctl("compute", "action", "wait", action_id)

    def list(self):
        """list actions."""
        return self.do.doctl("compute", "action", "list")


class ComputeCertificate:
    """certificate is used to access certificate commands."""

    def __init__(self, do):
        self.do = do

    def get(self, certificate_id):
        """get certificate."""
        return self.do.doctl("compute", "certificate", "get", certificate_id)

    def create(self):
        """create new certificate."""
        raise NotImplementedError()

    def list(self):
        """list certificates."""
        return self.do.doctl("compute", "certificate", "list")

    def delete(self, certificate_id):
        """delete certificates"""
        c = self.do.doctl(
            "compute",
            "certificate",
            "delete",
            certificate_id,
            "--force",
            expect_json=False,
        )
        return c.return_code == 0


class ComputeDroplet:
    """droplet is used to access droplet commands."""

    def __init__(self, do):
        self.do = do

    def list(self):
        """list droplets."""
        return self.do.doctl("compute", "droplet", "list")

    def get(self, droplet_id):
        """get droplet."""
        return self.do.doctl("compute", "droplet", "get", droplet_id)

    def delete(self, droplet_id):
        """Delete droplet by id or name."""
        c = self.do.doctl(
            "compute", "droplet", "delete", droplet_id, "--force", expect_json=False
        )
        return c.return_code == 0

    def create(
        self,
        name,
        image,
        region,
        size,
        volumes=None,
        user_data=None,
        user_data_file=None,
        tags=None,
        enable_private_networking=False,
        enable_monitoring=False,
        enable_ipv6=False,
        enble_backups=False,
        wait=False,
    ):
        """create droplet."""
        args = []
        args.extend([name])
        args.extend(["--image", image])
        args.extend(["--region", region])
        args.extend(["--size", size])
        if volumes:
            args.extend(["--volumes", volumes])
        if user_data:
            args.extend(["--user-data", user_data])
        if tags:
            args.extend(["--tags", tags])
        if enable_private_networking:
            args.extend(["--enable-private-networking"])
        if enable_monitoring:
            args.extend(["--enable-monitoring"])
        if enable_ipv6:
            args.extend(["--enable-ipv6"])
        if wait:
            args.extend(["--wait"])

        return doctl("compute", "droplet", "create", *args)

    def actions(self, droplet_id):
        """droplet actions."""
        return self.do.doctl("compute", "droplet", "actions", droplet_id)

    def backups(self, droplet_id):
        """droplet backups."""
        return self.do.doctl("compute", "droplet", "backups", droplet_id)

    def kernels(self, droplet_id):
        """droplet kernels."""
        return self.do.doctl("compute", "droplet", "kernels", droplet_id)

    def neighbors(self, droplet_id):
        """droplet neighbors."""
        return self.do.doctl("compute", "droplet", "neighbors", droplet_id)

    def snapshots(self, droplet_id):
        """snapshots."""
        return self.do.doctl("compute", "droplet", "snapshots", droplet_id)

    def tag(self, droplet_id, tag_name):
        """tag."""
        raise NotImplementedError

    def untag(self, droplet_id, tag_name):
        """untag."""
        raise NotImplementedError


class ComputeDomain:
    """domain is used to access domain commands."""

    def __init__(self, do):
        self.do = do

    def create(self, domain, ip_address):
        """Create domain."""
        return self.do.doctl(
            "compute", "domain", create, domain, "--ip-address", ip_address
        )

    def list(self):
        """List domain."""
        return self.do.doctl("compute", "domain", "list")

    def get(self, domain):
        """Get domain."""
        return self.do.doctl("compute", "domain", "get", domain)

    def delete(self, domain):
        """Delete domain."""
        return self.do.doctl("compute", "domain", "delete", domain, "--force")


class ComputeDomainRecords:
    """Commands for interacting with an individual domain."""

    def __init__(self, do):
        self.do = do

    def list(self, domain):
        """List records."""
        return self.do.doctl("compute", "domain", "records", "list", domain)

    def create(
        self,
        domain,
        *,
        record_data=None,
        record_flags=None,
        record_name=None,
        record_port=None,
        record_priority=None,
        record_tag=None,
        record_ttl=None,
        record_type=None,
        record_weight=None,
    ):
        """List records."""
        args = []
        if record_data:
            args.extend(["--record-data", record_data])
        if record_flags:
            args.extend(["--record-flags", record_flags])
        if record_name:
            args.extend(["--record-name", record_name])
        if record_port:
            args.extend(["--record-port", record_port])
        if record_priority:
            args.extend(["--record-priority", record_priority])
        if record_tag:
            args.extend(["--record-tag", record_tag])
        if record_ttl:
            args.extend(["--record-ttl", record_ttl])
        if record_type:
            args.extend(["--record-type", record_type])
        if record_weight:
            args.extend(["--record-weight", record_weight])

        return self.do.doctl("compute", "domain", "records", "create", domain, *args)

    def delete(self, domain, record_id):
        """Delete records."""
        return self.do.doctl(
            "compute", "domain", "records", "delete", domain, record_id
        )

    def update(
        self,
        domain,
        *,
        record_data=None,
        record_flags=None,
        record_name=None,
        record_port=None,
        record_priority=None,
        record_tag=None,
        record_ttl=None,
        record_type=None,
        record_weight=None,
    ):
        """Update records."""
        args = []
        if record_data:
            args.extend(["--record-data", record_data])
        if record_flags:
            args.extend(["--record-flags", record_flags])
        if record_name:
            args.extend(["--record-name", record_name])
        if record_port:
            args.extend(["--record-port", record_port])
        if record_priority:
            args.extend(["--record-priority", record_priority])
        if record_tag:
            args.extend(["--record-tag", record_tag])
        if record_ttl:
            args.extend(["--record-ttl", record_ttl])
        if record_type:
            args.extend(["--record-type", record_type])
        if record_weight:
            args.extend(["--record-weight", record_weight])
        return self.do.doctl("compute", "domain", "records", "update", domain, *args)


class ComputeFirewall:
    """Firewall is used to access firewall commands."""

    def __init__(self, do):
        self.do = do

    def get(self, firewall_id):
        """Get firewall."""
        return self.do.doctl("compute", "firewall", "get", firewall_id)

    def create(
        self,
        firewall_id,
        *,
        name,
        droplet_ids=None,
        inbound_rules=None,
        outbound_rules=None,
        tag_names=None,
    ):
        """Create firewall."""
        args = []
        args.extend(["--name", name])
        if droplet_ids:
            args.extend(["--droplet-ids", droplet_ids])
        if inbound_rules:
            args.extend(["--inbound-rules", inbound_rules])
        if outbound_rules:
            args.extend(["--outboud-rules", outbound_rules])
        if tag_names:
            args.extend(["--tag-names", tag_names])
        return self.do.doctl("compute", "firewall", "update", firewall_id, *args)

    def update(
        self,
        firewall_id,
        name,
        droplet_ids=None,
        inbound_rules=None,
        outbound_rules=None,
        tag_names=None,
    ):
        """Update firewall."""
        args = []
        args.extend(["--name", name])
        if droplet_ids:
            args.extend(["--droplet-ids", droplet_ids])
        if inbound_rules:
            args.extend(["--inbound-rules", inbound_rules])
        if outbound_rules:
            args.extend(["--outboud-rules", outbound_rules])
        if tag_names:
            args.extend(["--tag-names", tag_names])
        return self.do.doctl("compute", "firewall", "update", firewall_id, *args)

    def list(self):
        """List firewalls."""
        return self.do.doctl("compute", "firewall", "list")

    def list_by_droplet(self, droplet_id):
        """List firewalls by droplet ID."""
        return self.do.doctl("compute", "firewall", "list-by-droplet", droplet_id)

    def delete(self, firewall_id):
        """Delete firewall."""
        c = self.do.doctl(
            "compute", "firewall", "delete", firewall_id, "--force", expect_json=False
        )
        return c.return_code == 0

    def add_droplets(self, firewall_id, droplet_ids):
        """Add droplets to the firewall."""
        if not isinstance(str, droplet_ids):
            droplet_ids = ",".join(droplet_ids)
        return self.do.doctl(
            "compute",
            "firewall",
            "add-droplets",
            firewall_id,
            "--droplet-ids",
            droplet_ids,
        )

    def remove_droplets(self):
        """Remove droplets from the firewall."""
        if not isinstance(str, droplet_ids):
            droplet_ids = ",".join(droplet_ids)
        return self.do.doctl(
            "compute",
            "firewall",
            "remove-droplets",
            firewall_id,
            "--droplet-ids",
            droplet_ids,
        )

    def add_tags(self, firewall_id, tag_names):
        """Add tags from the firewall."""
        if not isinstance(str, tag_names):
            tag_names = ",".join(tag_names)

        return self.do.doctl(
            "compute", "firewall", "add-tags", firewall_id, "--tag-names", droplet_ids
        )

    def remove_tags(self, firewall_id, tag_names):
        """Remove tags from the firewall."""
        if not isinstance(str, tag_names):
            tag_names = ",".join(tag_names)

        return self.do.doctl(
            "compute",
            "firewall",
            "remove-tags",
            firewall_id,
            "--tag-names",
            droplet_ids,
        )

    def add_rules(self, firewall_id, inbound_rules=None, outbound_rules=None):
        """Add inbound/outbound rules to the firewall."""
        args = []
        if inbound_rules:
            args.extend(["--inbound-rules", inbound_rules])
        if outbound_rules:
            args.extend(["--outbound-rules", outbound_rules])

        return self.do.doctl("compute", "firewall", "add-rules", firewall_id, *args)

    def remove_rules(firewall_id, inbound_rules=None, outbound_rules=None):
        """Remove inbound/outbound rules to the firewall."""
        args = []
        if inbound_rules:
            args.extend(["--inbound-rules", inbound_rules])
        if outbound_rules:
            args.extend(["--outbound-rules", outbound_rules])

        return self.do.doctl("compute", "firewall", "remove-rules", firewall_id, *args)


class ComputeFloatingIP:
    """Floating-ip is used to access commands on floating IPs."""

    def __init__(self, do):
        self.do = do

    def create(self, droplet_id):
        """Create a floating IP."""
        return self.do.doctl("compute", "floating-ip", "create", droplet_id)

    def get(self, droplet_id):
        """Get the details of a floating IP."""
        return self.do.doctl("compute", "floating-ip", "get", droplet_id)

    def delete(self, droplet_id):
        """Delete a floating IP address."""
        c = self.do.doctl(
            "compute", "floating-ip", "delete", droplet_id, expect_json=False
        )
        return c.return_code == 0

    def list(self):
        """List all floating IP addresses."""
        return self.do.doctl("compute", "floating-ip", "list")


class ComputeFloatingIPAction:
    """Floating IP action commands."""

    def __init__(self, do):
        self.do = do

    def get(self, floating_ip, action_id):
        """Get the details"""
        return self.do.doctl(
            "compute", "floating-ip-action", "get", floating_ip, action_id
        )

    def assign(self, floating_ip, droplet_id):
        return self.do.doctl("compute", "floating-ip-action", floating_ip, droplet_id)

    def unassign(self, floating_ip):
        return self.do.doctl("compute", "floating-ip-action", "unassign", floating_ip)


class ComputeImage:
    """Image commands."""

    def __init__(self, do):
        self.do = do

    def list(self):
        return self.do.doctl("compute", "image", "list")

    def list_distribution(self):
        return self.do.doctl("compute", "image", "list-distribution")

    def list_application(self):
        return self.do.doctl("compute", "image", "list-application")

    def list_user(self):
        return self.do.doctl("compute", "image", "list-user")

    def get(self, image_id):
        return self.do.doctl("compute", "image", "get", image_id)

    def update(self, image_id, image_name):
        return self.do.doctl(
            "compute", "image", "update", image_id, "--image-name", image_name
        )

    def delete(self, image_id):
        c = self.do.doctl(
            "compute", "image", "update", image_id, "--force", expect_json=False
        )
        return c.return_code == 0


class ComputeImageAction:
    """Compute commands are for controlling and managing infrastructure."""

    def __init__(self, do):
        self.do = do

    def get(self, image_id):
        return self.do.doctl("compute", "image-action", "get", image_id)

    def transfer(self, image_id, region, wait=False):
        args = []
        if wait:
            args.extend(["--wait"])

        return self.do.doctl(
            "compute", "image-action", "transfer", image_id, "--region", region, *args
        )


class ComputeLoadBalancer:
    """Access load-balancer commands."""

    def __init__(self, do):
        self.do = do

    def get(self, load_balancer_id):
        return self.do.doctl("compute", "load-balancer", "get", load_balancer_id)

    def create(
        self,
        load_balancer_id,
        name,
        algorithm=None,
        droplet_ids=None,
        forwarding_rules=None,
        health_check=None,
        redirect_http_to_https=None,
        region=None,
        stricky_sessions=None,
        tag_name=None,
    ):

        if not isinstance(str, droplet_ids):
            tag_names = ",".join(droplet_ids)

        if hasattr(forwarding_rules, items):
            forwarding_rules = ",".join(
                [f"{k}:{v}" for (k, v) in forwarding_rules.items()]
            )
        if hasattr(health_check, items):
            health_check = ",".join([f"{k}:{v}" for (k, v) in health_check.items()])

        args = []
        args.extend(["--name", name])
        if algorithm:
            args.extend(["--algorithm", algorithm])
        if droplet_ids:
            args.extend(["--droplet-ids", droplet_ids])
        if fowarding_rules:
            args.extend(["--forwarding-rules", inbound_rules])
        if health_check:
            args.extend(["--health-check", outbound_rules])
        if tag_name:
            args.extend(["--tag-name", tag_name])

        return self.do.doctl(
            "compute", "load-balancer", "create", load_balancer_update, *args
        )

    def update(
        self,
        load_balancer_id,
        name,
        algorithm=None,
        droplet_ids=None,
        forwarding_rules=None,
        health_check=None,
        redirect_http_to_https=None,
        region=None,
        stricky_sessions=None,
        tag_name=None,
    ):
        """Create load balancer."""

        if not isinstance(str, droplet_ids):
            droplet_ids = ",".join(droplet_ids)

        if hasattr(forwarding_rules, items):
            forwarding_rules = ",".join(
                [f"{k}:{v}" for (k, v) in forwarding_rules.items()]
            )
        if hasattr(health_check, items):
            health_check = ",".join([f"{k}:{v}" for (k, v) in health_check.items()])

        args = []
        args.extend(["--name", name])
        if algorithm:
            args.extend(["--algorithm", algorithm])
        if droplet_ids:
            args.extend(["--droplet-ids", droplet_ids])
        if fowarding_rules:
            args.extend(["--forwarding-rules", inbound_rules])
        if health_check:
            args.extend(["--health-check", outbound_rules])
        if tag_name:
            args.extend(["--tag-name", tag_name])

        return self.do.doctl(
            "compute", "load-balancer", "update", load_balancer_update, *args
        )

    def list(self):
        """List load balancer."""
        return self.do.doctl("compute", "load-balancer", "list")

    def delete(self, load_balancer_id):
        """Delete load balancer."""
        c = self.do.doctl(
            "compute", "load-balancer", "delete", load_balancer_id, expect_json=False
        )
        return c.return_code == 0

    def add_droplets(self, load_balancer_id, droplet_ids):
        """Add droplets to the load balancer."""
        if not isinstance(str, droplet_ids):
            droplet_ids = ",".join(droplet_ids)

        args = []
        if droplet_ids:
            args.extend(["--droplet-ids", droplet_ids])

        return self.do.doctl(
            "compute", "load-balancer", "add-droplets", load_balancer_id, *args
        )

    def remove_droplets(self):
        """Remove droplets from the load balancer."""
        if not isinstance(str, droplet_ids):
            droplet_ids = ",".join(droplet_ids)

        args = []
        if droplet_ids:
            args.extend(["--droplet-ids", droplet_ids])

        return self.do.doctl(
            "compute", "load-balancer", "remove-droplets", load_balancer_id, *args
        )

    def add_forwarding_rules(self, load_balancer_id, forwarding_rules=None):
        """Add forwarding rules to the load balancer."""
        if hasattr(forwarding_rules, items):
            forwarding_rules = ",".join(
                [f"{k}:{v}" for (k, v) in forwarding_rules.items()]
            )

        args = []
        if forwarding_rules:
            args.extend(["--forwarding-rules", forwarding_rules])

        return self.do.doctl(
            "compute", "load-balancer", "add-forwarding-rules", load_balancer_id, *args
        )

    def remove_forwarding_rules(self, load_balancer_id, forwarding_rules=None):
        """Remove forwarding rules from the load balancer."""
        if hasattr(forwarding_rules, items):
            forwarding_rules = ",".join(
                [f"{k}:{v}" for (k, v) in forwarding_rules.items()]
            )

        args = []
        if forwarding_rules:
            args.extend(["--forwarding-rules", forwarding_rules])

        c = self.do.doctl(
            "compute",
            "load-balancer",
            "remove-forwarding-rules",
            load_balancer_id,
            *args,
            expect_json=False,
        )
        return c.return_code == 0


class ComputePlugin:
    """Access plugin commands."""
    def __init__(self, do):
        self.do = do

    def list(self):
        """List plugins."""
        return self.do.doctl("compute", "plugin", "list")

    def run(self, plugin_name):
        """Run plugin."""
        return self.do.doctl("compute", "plugin", "run", plugin_name)


class ComputeSnapshot:
    """Access snapshot commands."""
    def __init__(self, do):
        self.do = do

    def list(self):
        """List snapshots."""
        return self.do.doctl("compute", "snapshot", "list")

    def get(self, snapshot_id):
        """Get snapshots."""
        return self.do.doctl("compute", "snapshot", "get", snapshot_id)

    def delete(self, snapshot_id):
        """Delete snapshots."""
        c = self.do.doctl("compute", "size", "list", expect_json=False)
        return c.return_code == 0


class ComputeSSHKey:
    """Access ssh key commands"""
    def __init__(self, do):
        self.do = do

    def list(self):
        """List ssh keys."""
        return self.do.doctl("compute", "ssh-key", "list")

    def get(self, key_id):
        """Get ssh key."""
        return self.do.doctl("compute", "ssh-key", "get", key_id)

    def create(self, key_name, public_key):
        """Create ssh key."""
        return self.do.doctl(
            "compute", "ssh-key", "create", key_name, "--public-key", public_key
        )

    def _import(self, key_name, public_key_file):
        """Import ssh key."""
        return self.do.doctl(
            "compute",
            "ssh-key",
            "import",
            key_name,
            "--public-key-file",
            public_key_file,
        )

    def delete(self, key_id):
        """Delete ssh key."""
        c = self.do.doctl(
            "compute", "ssh-key", "delete", key_id, "--force", expect_json=False
        )
        return c.return_code == 0


class ComputeTag:
    """Access tag commands."""
    def __init__(self, do):
        self.do = do

    def create(self, tag_name):
        """Create tag."""
        return self.do.doctl("compute", "tag", "create", tag_name)

    def get(self, tag_name):
        """Get tag."""
        return self.do.doctl("compute", "tag", "get", tag_name)

    def list(self):
        """List tags."""
        return self.do.doctl("compute", "tag", "list")

    def delete(self, tag_name):
        """Delete tag."""
        c = self.do.doctl(
            "compute", "tag", "delete", tag_name, "--force", expect_json=False
        )
        return c.return_code == 0


class ComputeVolume:
    """Access volume commands."""
    def __init__(self, do):
        self.do = do

    def list(self):
        """List volume."""
        return self.do.doctl("compute", "volume", "list")

    def create(self, volume_name, region, size, description=None):
        """Create a volume."""
        args = []
        args.extend(["--region", region])
        args.extend(["--size", size])
        if description:
            args.extend(["--description", description])
        return self.do.doctl("compute", "volume", "create", volume_name, *args)

    def delete(self, volume_id):
        """Delete a volume."""
        c = self.do.doctl(
            "compute", "volume", "delete", volume_id, "--force", expect_json=False
        )
        return c.return_code == 0

    def get(self, volume_id):
        """Get a volume."""
        return self.do.doctl("compute", "volume", "get", volume_id)

    def snapshot(self, volume_id, name, description=None):
        """Create a volume snapshot."""
        args = []
        args.extend(["--snapshot-name", name])
        if description:
            args.extend(["--snapshot-desc", description])
        return self.do.doctl("compute", "volume", "snapshot", volume_id, *args)


class ComputeVolumeAction:
    """Access volume action commands."""

    def __init__(self, do):
        self.do = do

    def attach(self, volume_id, droplet_id):
        """Attaches a volume."""
        return self.do.doctl(
            "compute", "volume-action", "attach", volume_id, droplet_id
        )

    def detach(self, volume_id, droplet_id):
        """Detatches a volume."""
        return self.do.doctl(
            "compute",
            "volume-action",
            "detach",
            volume_id,
            "--region",
            region,
            "--size",
            size,
        )

    def resize(self, volume_id, region, size):
        """Resizes a volume."""
        return self.do.doctl(
            "compute",
            "volume-action",
            "resize",
            volume_id,
            "--region",
            region,
            "--size",
            size,
        )


# self.account = ComputeAccount(do=self.do)


class Compute:
    """compute commands are for controlling and managing infrastructure

    :ivar certificate: access certificate commands (:class:`ComputeCertificate`).
    :ivar action: access action commands (:class:`ComputeAction`).
    :ivar droplet: access droplet commands (:class:`ComputeDroplet`).
    :ivar domain: access domain commands (:class:`ComputeDomain`).
    :ivar domain_records: interacting with an individual domain (:class:`ComputeDomainRecords`).
    :ivar firewall: access firewall commands (:class:`ComputeFirewallAccess`).
    :ivar floating_ip: access commands on floating IPs (:class:`ComputeFloatingIP`).
    :ivar floating_ip_action: floating IP action commands (:class:`ComputeFloatingIPAction`).
    :ivar image: image commands (:class:`ComputeImage`).
    :ivar image_action: image-action commands (:class:`ComputeImageAction`).
    :ivar load_balancer: access load-balancer commands (:class:`ComputeLoadBalancer`).
    :ivar plugin: access plugin commands (:class:`ComputePlugin`).
    :ivar snapshot: access snapshot commands (:class:`ComputeSnapshot`).
    :ivar ssh_key: access ssh key commands (:class:`ComputeSSHKey`).
    :ivar tag: access tag commands (:class:`ComputeTag`).
    :ivar volume: access volume commands (:class:`ComputeVolume`).
    :ivar volume_action: access volume action commands (:class:`ComputeVolumeAction`).
    """

    def __init__(self, do=None):
        self.do = do or DigitalOcean()
        self.certificate = ComputeCertificate(do=self.do)
        self.action = ComputeAction(do=self.do)
        self.droplet = ComputeDroplet(do=self.do)
        self.domain = ComputeDomain(do=self.do)
        self.domain_records = ComputeDomainRecords(do=self.do)
        self.firewall = ComputeFirewall(do=self.do)
        self.floating_ip = ComputeFloatingIP(do=self.do)
        self.floating_ip_action = ComputeFloatingIPAction(do=self.do)
        self.image = ComputeImage(do=self.do)
        self.image_action = ComputeImageAction(do=self.do)
        self.load_balancer = ComputeLoadBalancer(do=self.do)
        self.plugin = ComputePlugin(do=self.do)
        self.snapshot = ComputeSnapshot(do=self.do)
        self.ssh_key = ComputeSSHKey(do=self.do)
        self.tag = ComputeTag(do=self.do)
        self.volume = ComputeVolume(do=self.do)
        self.volume_action = ComputeVolumeAction(do=self.do)

    def region_list(self):
        return self.do.doctl("compute", "region", "list")

    def size_list(self):
        return self.do.doctl("compute", "size", "list")


class Account:
    """account is used to access account commands."""

    def __init__(self, do=None):
        self.do = do or DigitalOcean()

    def get(self):
        """get account."""
        return self.do.doctl("account", "get")

    def rate_limit(self):
        """get API rate limits."""
        return self.do.doctl("account", "ratelimit")


compute = Compute()
account = Account()
