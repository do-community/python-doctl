
import sys
import os
import json
import re
import io
import tarfile

import delegator
import maya
import appdirs

import requests
import requests_html
from tempfile import NamedTemporaryFile

requests = requests.Session()
html_session = requests_html.HTMLSession()

BIN_CACHE = appdirs.user_cache_dir('python-doctl', 'Kenneth Reitz')
os.environ['PATH'] = f'{BIN_CACHE}:{os.environ["PATH"]}'


try:
    os.makedirs(BIN_CACHE)
except FileExistsError:
    pass

class DOCtlError(RuntimeError):
    def __init__(self, c):
        self.c = c
        self.output = c.out

def ensure_doctl():

    r = html_session.get('https://github.com/digitalocean/doctl/releases')
    candidates = r.html.find('#js-repo-pjax-container > div.container.new-discussion-timeline.experiment-repo-nav > div.repository-content > div.position-relative.border-top > div.release.clearfix.label-latest > div.release-body.commit.open.float-left > div.my-4 > ul', first=True).absolute_links

    asset = None
    for candidate in candidates:
        if sys.platform in candidate and 'sha256' not in candidate:
            asset = candidate

    if asset:
        r = requests.get(asset, stream=False)
        tarball = NamedTemporaryFile(delete=False)
        with open(tarball.name, 'wb') as f:
            f.write(r.content)

        tar = tarfile.open(tarball.name, "r|gz")
        tar.extractall(path=BIN_CACHE)
        tar.close()


def system_which(command, mult=False):
    """Emulates the system's which. Returns None if not found."""
    _which = 'which -a' if not os.name == 'nt' else 'where'
    c = delegator.run('{0} {1}'.format(_which, command))
    try:
        # Which Not found...
        assert c.return_code == 0
    except AssertionError:
        return None if not mult else []

    result = c.out.strip() or c.err.strip()
    if mult:
        return result.split('\n')

    else:
        return result.split('\n')[0]


def datetime_parser(dct):
    for k, v in dct.items():
        try:
            if "-" in v and ":" in v:
                dct[k] = maya.parse(v).datetime()
        except Exception:
            pass
    return dct


class DigitalOcean:

    def __init__(self, token=None):
        self.token = token
        self.compute = Compute(do=self)

    def doctl(self, *args, expect_json=True):
        """Runs doctl."""

        doctl_location = system_which('docutil')
        if not doctl_location:
            ensure_doctl()

        if expect_json:
            args = list(args)
            args.extend(["--output", "json"])

        if self.token:
            args = list(args)
            args.extend(["--access-token", self.token])

        args = " ".join(args)
        c = delegator.run(f"doctl {args}")
        try:
            assert c.return_code == 0
        except AssertionError:
            print(c.out)
            raise DOCtlError(c)

        if not expect_json:
            return c
        else:
            return json.loads(c.out, object_hook=datetime_parser)


class ComputeAccount:

    def __init__(self, do):
        self.do = do

    def get(self):
        return self.do.doctl("account", "get")

    def rate_limit(self):
        return self.do.doctl("account", "ratelimit")


class ComputeAction:

    def __init__(self, do):
        self.do = do

    def get(self, action_id):
        return self.do.doctl("compute", "action", "get", action_id)

    def wait(self, action_id):
        return self.do.doctl("compute", "action", "wait", action_id)

    def list(self):
        return self.do.doctl("compute", "action", "list")


class ComputeCertificate:

    def __init__(self, do):
        self.do = do

    def get(self, certificate_id):
        return self.do.doctl("compute", "certificate", "get", certificate_id)

    def create(self):
        raise NotImplementedError()

    def list(self):
        return self.do.doctl("compute", "certificate", "list")

    def delete(self, certificate_id):
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

    def __init__(self, do):
        self.do = do

    def list(self):
        return self.do.doctl("compute", "droplet", "list")

    def get(self, droplet_id):
        return self.do.doctl("compute", "droplet", "get", droplet_id)

    def delete(self, droplet_id):
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
        return self.do.doctl("compute", "droplet", "actions", droplet_id)

    def backups(self, droplet_id):
        return self.do.doctl("compute", "droplet", "backups", droplet_id)

    def kernels(self, droplet_id):
        return self.do.doctl("compute", "droplet", "kernels", droplet_id)

    def neighbors(self, droplet_id):
        return self.do.doctl("compute", "droplet", "neighbors", droplet_id)

    def snapshots(self, droplet_id):
        return self.do.doctl("compute", "droplet", "snapshots", droplet_id)

    def tag(self, droplet_id, tag_name):
        raise NotImplementedError

    def untag(self, droplet_id, tag_name):
        raise NotImplementedError


class ComputeDomain:

    def __init__(self, do):
        self.do = do

    def create(self, domain, ip_address):
        return self.do.doctl(
            "compute", "domain", create, domain, "--ip-address", ip_address
        )

    def list(self):
        return self.do.doctl("compute", "domain", "list")

    def get(self, domain):
        return self.do.doctl("compute", "domain", "get", domain)

    def delete(self, domain):
        return self.do.doctl("compute", "domain", "delete", domain, "--force")


class ComputeDomainRecords:

    def __init__(self, do):
        self.do = do

    def list(self, domain):
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

    def __init__(self, do):
        self.do = do

    def get(self, firewall_id):
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
        return self.do.doctl("compute", "firewall", "list")

    def list_by_droplet(self, droplet_id):
        return self.do.doctl("compute", "firewall", "list-by-droplet", droplet_id)

    def delete(self, firewall_id):
        c = self.do.doctl(
            "compute", "firewall", "delete", firewall_id, "--force", expect_json=False
        )
        return c.return_code == 0

    def add_droplets(self, firewall_id, droplet_ids):
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
        if not isinstance(str, tag_names):
            tag_names = ",".join(tag_names)

        return self.do.doctl(
            "compute", "firewall", "add-tags", firewall_id, "--tag-names", droplet_ids
        )

    def remove_tags(self, firewall_id, tag_names):
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
        args = []
        if inbound_rules:
            args.extend(["--inbound-rules", inbound_rules])
        if outbound_rules:
            args.extend(["--outbound-rules", outbound_rules])

        return self.do.doctl("compute", "firewall", "add-rules", firewall_id, *args)

    def remove_rules(firewall_id, inbound_rules=None, outbound_rules=None):
        args = []
        if inbound_rules:
            args.extend(["--inbound-rules", inbound_rules])
        if outbound_rules:
            args.extend(["--outbound-rules", outbound_rules])

        return self.do.doctl("compute", "firewall", "remove-rules", firewall_id, *args)


class ComputeFloatingIP:

    def __init__(self, do):
        self.do = do

    def create(self, droplet_id):
        return self.do.doctl("compute", "floating-ip", "create", droplet_id)

    def get(self, droplet_id):
        return self.do.doctl("compute", "floating-ip", "get", droplet_id)

    def delete(self, droplet_id):
        c = self.do.doctl(
            "compute", "floating-ip", "delete", droplet_id, expect_json=False
        )
        return c.return_code == 0

    def list(self):
        return self.do.doctl("compute", "floating-ip", "list")

    def get(self, floating_ip, action_id):
        return self.do.doctl("compute", "floating-ip", "get", floating_ip, action_id)

    def assign(self, floating_ip, droplet_id):
        return self.do.doctl("compute", "floating-ip", floating_ip, droplet_id)

    def unassign(self, floating_ip):
        return self.do.doctl("compute", "floating-ip", "unassign", floating_ip)


class ComputeImage:

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
        return self.do.doctl("compute", "load-balancer", "list")

    def delete(self, load_balancer_id):
        c = self.do.doctl(
            "compute", "load-balancer", "delete", load_balancer_id, expect_json=False
        )
        return c.return_code == 0

    def add_droplets(self, load_balancer_id, droplet_ids):
        if not isinstance(str, droplet_ids):
            droplet_ids = ",".join(droplet_ids)

        args = []
        if droplet_ids:
            args.extend(["--droplet-ids", droplet_ids])

        return self.do.doctl(
            "compute", "load-balancer", "add-droplets", load_balancer_id, *args
        )

    def remove_droplets(self):
        if not isinstance(str, droplet_ids):
            droplet_ids = ",".join(droplet_ids)

        args = []
        if droplet_ids:
            args.extend(["--droplet-ids", droplet_ids])

        return self.do.doctl(
            "compute", "load-balancer", "remove-droplets", load_balancer_id, *args
        )

    def add_forwarding_rules(self, load_balancer_id, forwarding_rules=None):
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

    def __init__(self, do):
        self.do = do

    def list(self):
        return self.do.doctl("compute", "plugin", "list")

    def run(self, plugin_name):
        return self.do.doctl("compute", "plugin", "run", plugin_name)


class ComputeSnapshot:

    def __init__(self, do):
        self.do = do

    def list(self):
        return self.do.doctl("compute", "snapshot", "list")

    def get(self, snapshot_id):
        return self.do.doctl("compute", "snapshot", "get", snapshot_id)

    def delete(self, snapshot_id):
        c = self.do.doctl("compute", "size", "list", expect_json=False)
        return c.return_code == 0


class ComputeSSHKey:

    def __init__(self, do):
        self.do = do

    def list(self):
        return self.do.doctl("compute", "ssh-key", "list")

    def get(self, key_id):
        return self.do.doctl("compute", "ssh-key", "get", key_id)

    def create(self, key_name, public_key):
        return self.do.doctl(
            "compute", "ssh-key", "create", key_name, "--public-key", public_key
        )

    def _import(self, key_name, public_key_file):
        return self.do.doctl(
            "compute",
            "ssh-key",
            "import",
            key_name,
            "--public-key-file",
            public_key_file,
        )

    def delete(self, key_id):
        c = self.do.doctl(
            "compute", "ssh-key", "delete", key_id, "--force", expect_json=False
        )
        return c.return_code == 0


class ComputeTag:

    def __init__(self, do):
        self.do = do

    def create(self, tag_name):
        return self.do.doctl("compute", "tag", "create", tag_name)

    def get(self, tag_name):
        return self.do.doctl("compute", "tag", "get", tag_name)

    def list(self):
        return self.do.doctl("compute", "tag", "list")

    def delete(self, tag_name):
        c = self.do.doctl(
            "compute", "tag", "delete", tag_name, "--force", expect_json=False
        )
        return c.return_code == 0


class ComputeVolume:

    def __init__(self, do):
        self.do = do

    def list(self):
        return self.do.doctl("compute", "volume", "list")

    def create(self, volume_name, region, size, description=None):
        args = []
        args.extend(["--region", region])
        args.extend(["--size", size])
        if description:
            args.extend(["--description", description])
        return self.do.doctl("compute", "volume", "create", volume_name, *args)

    def delete(self, volume_id):
        c = self.do.doctl(
            "compute", "volume", "delete", volume_id, "--force", expect_json=False
        )
        return c.return_code == 0

    def get(self, volume_id):
        return self.do.doctl("compute", "volume", "get", volume_id)

    def snapshot(self, volume_id, name, description=None):
        args = []
        args.extend(["--snapshot-name", name])
        if description:
            args.extend(["--snapshot-desc", description])
        return self.do.doctl("compute", "volume", "snapshot", volume_id, *args)


class ComputeVolumeAction:

    def __init__(self, do):
        self.do = do

    def attach(self, volume_id, droplet_id):
        return self.do.doctl(
            "compute", "volume-action", "attach", volume_id, droplet_id
        )

    def detach(self, volume_id, droplet_id):
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


class Compute:

    def __init__(self, do=None):
        self.do = do or DigitalOcean()
        self.certificate = ComputeCertificate(do=self.do)
        self.action = ComputeAction(do=self.do)
        self.account = ComputeAccount(do=self.do)
        self.droplet = ComputeDroplet(do=self.do)
        self.domain = ComputeDomain(do=self.do)
        self.domain_records = ComputeDomainRecords(do=self.do)
        self.firewall = ComputeFirewall(do=self.do)
        self.floating_ip = ComputeFloatingIP(do=self.do)
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


compute = Compute()