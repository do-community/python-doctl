import re

import simplejson
import delegator
import maya


PROPER_WHITESPACE = r"\s{2,}"


class TableImporter:
    """docstring for TableImporter"""

    def __init__(self, asciitable, ints=None, bools=None, timestamps=None, splits=None):
        self.asciitable = asciitable
        self.ints = ints if ints else []
        self.bools = bools if bools else []
        self.timestamps = timestamps if timestamps else []
        self.splits = splits if splits else []

    @property
    def split(self):

        def gen():
            for line in self.asciitable.split("\n"):
                if line:
                    yield line

        return [g for g in gen()]

    @staticmethod
    def pythonize_header(header):
        header = header.lower()
        header = header.replace(" ", "_")
        return header

    @property
    def headers(self):
        # Only split headers if they are seperated by more than one space.
        return re.split(PROPER_WHITESPACE, self.split[0])

    @property
    def iter_data(self):
        for row in self.split[1:]:
            yield re.split(PROPER_WHITESPACE, row)

    def get_values(self, header):
        i = self.headers.index(header)
        data = [d for d in self.iter_data]
        values = []

        for row in data:
            values.append(row[i])

        for value in values:
            print(header, value)
            if header in self.ints:
                # Convert ints into ints.
                v = int(value)
            elif header in self.bools:
                # Turn 'true' into valid boolean.
                v = value == "true"
            elif header in self.timestamps:
                # chop off unneccessary duplicate timezone data.
                v = maya.parse(value[:-4]).datetime()
            elif header in self.splits:
                v = value.split(",")
            else:
                v = None

            values[values.index(value)] = v or value

        return values

    def as_dict(self):
        d = {}

        for header in self.headers:
            d[self.pythonize_header(header)] = self.get_values(header)

        # Clean up values, if there is only one instance.
        d2 = d.copy()
        for k in d:
            if len(d[k]) == 1:
                d2[k] = d[k][0]

        return d2

    def as_list(self):

        data = [d for d in self.iter_data]

        data2 = data.copy()
        for (i, datum) in enumerate(data):
            d = {}
            for j in range(len(datum)):
                d[self.pythonize_header(self.headers[j])] = datum[j]

            data2[i] = d

        return data2


def datetime_parser(dct):
    for k, v in dct.items():
        try:
            if "-" in v and ":" in v:
                dct[k] = maya.parse(v).datetime()
        except Exception:
            pass
    return dct


def doctl(*args, expect_json=True):
    """Runs doctl."""
    if expect_json:
        args = list(args)
        args.extend(["--output", "json"])
    args = " ".join(args)
    c = delegator.run(f"doctl {args}")
    try:
        assert c.return_code == 0
    except AssertionError:
        print(c.out)
        raise RuntimeWarning("Something went wrong!")

    if not expect_json:
        return c
    else:
        return simplejson.loads(c.out, object_hook=datetime_parser)


def account_get():
    return doctl("account", "get")


def account_ratelimit():
    return doctl("account", "ratelimit")


def compute_action_get(action_id):
    return doctl("compute", "action", "get", action_id)


def compute_action_wait(action_id):
    return doctl("compute", "action", "wait", action_id)


def compute_action_list():
    return doctl("compute", "action", "list")


def compute_certificate_get(certificate_id):
    results = doctl("compute", "certificate", "get", certificate_id).out
    t = TableImporter(results, timestamps=["Created At", "Expiration Date"])
    return t.as_dict()


def compute_certificate_create():
    raise NotImplementedError


def compute_certificate_list():
    results = doctl("compute", "certificate", "list").out
    t = TableImporter(results, timestamps=["Created At", "Expiration Date"])
    return t.as_list()


def compute_certificate_delete(certificate_id):
    doctl("compute", "certificate", "delete", certificate_id, "--force").out
    return True


def compute_droplet_list():
    return doctl("compute", "droplet", "list")


def compute_droplet_get(droplet_id):
    return doctl("compute", "droplet", "get", droplet_id)


def compute_droplet_delete(droplet_id):
    c = doctl("compute", "droplet", "delete", droplet_id, "--force", expect_json=False)
    assert c.return_code == 0
    return True


def compute_droplet_create(
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


def compute_droplet_actions(droplet_id):
    return doctl("compute", "droplet", "actions", droplet_id)


def compute_droplet_backups(droplet_id):
    return doctl("compute", "droplet", "backups", droplet_id)


def compute_droplet_kernels(droplet_id):
    return doctl("compute", "droplet", "kernels", droplet_id)


def compute_droplet_neighbors(droplet_id):
    return doctl("compute", "droplet", "neighbors", droplet_id)


def compute_droplet_snapshots(droplet_id):
    return doctl("compute", "droplet", "snapshots", droplet_id)


def compute_droplet_tag(droplet_id, tag_name):
    raise NotImplementedError


def compute_droplet_untag(droplet_id, tag_name):
    raise NotImplementedError


def compute_domain_create(domain, ip_address):
    return doctl("compute", "domain", create, domain, "--ip-address", ip_address)


def compute_domain_list():
    return doctl("compute", "domain", "list")


def compute_domain_get(domain):
    return doctl("compute", "domain", "get", domain)


def compute_domain_delete(domain):
    return doctl("compute", "domain", "delete", domain, "--force")


def compute_domain_records_list(domain):
    return doctl("compute", "domain", "records", "list", domain)


def compute_domain_records_create(
    domain,
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

    return doctl("compute", "domain", "records", "create", domain, *args)


def compute_domain_records_delete(domain, record_id):
    return doctl("compute", "domain", "records", "delete", domain, record_id)


def compute_domain_records_update(
    domain,
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
    return doctl("compute", "domain", "records", "update", domain, *args)


def compute_firewall_get(firewall_id):
    return doctl("compute", "firewall", "get", firewall_id)


def compute_firewall_create(
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
    return doctl("compute", "firewall", "update", firewall_id, *args)


def compute_firewall_update(
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
    return doctl("compute", "firewall", "update", firewall_id, *args)


def compute_firewall_list():
    return doctl("compute", "firewall", "list")


def compute_firewall_list_by_droplet(droplet_id):
    return doctl("compute", "firewall", "list-by-droplet", droplet_id)


def compute_firewall_delete(firewall_id):
    return doctl("compute", "firewall", "delete", firewall_id, "--force")


def compute_firewall_add_droplets(firewall_id, droplet_ids):
    if not isinstance(str, droplet_ids):
        droplet_ids = ",".join(droplet_ids)
    return doctl(
        "compute", "firewall", "add-droplets", firewall_id, "--droplet-ids", droplet_ids
    )


def compute_firewall_remove_droplets():
    if not isinstance(str, droplet_ids):
        droplet_ids = ",".join(droplet_ids)
    return doctl(
        "compute",
        "firewall",
        "remove-droplets",
        firewall_id,
        "--droplet-ids",
        droplet_ids,
    )


def compute_firewall_add_tags(firewall_id, tag_names):
    if not isinstance(str, tag_names):
        tag_names = ",".join(tag_names)

    return doctl(
        "compute", "firewall", "add-tags", firewall_id, "--tag-names", droplet_ids
    )


def compute_firewall_remove_tags(firewall_id, tag_names):
    if not isinstance(str, tag_names):
        tag_names = ",".join(tag_names)

    return doctl(
        "compute", "firewall", "remove-tags", firewall_id, "--tag-names", droplet_ids
    )


def compute_firewall_add_rules(firewall_id, inbound_rules=None, outbound_rules=None):
    args = []
    if inbound_rules:
        args.extend(["--inbound-rules", inbound_rules])
    if outbound_rules:
        args.extend(["--outbound-rules", outbound_rules])

    return doctl("compute", "firewall", "add-rules", firewall_id, *args)


def compute_firewall_remove_rules(firewall_id, inbound_rules=None, outbound_rules=None):
    args = []
    if inbound_rules:
        args.extend(["--inbound-rules", inbound_rules])
    if outbound_rules:
        args.extend(["--outbound-rules", outbound_rules])

    return doctl("compute", "firewall", "remove-rules", firewall_id, *args)


def compute_floating_ip_create(droplet_id):
    return doctl("compute", "floating-ip", "create", droplet_id)


def compute_floating_ip_get(droplet_id):
    return doctl("compute", "floating-ip", "get", droplet_id)


def compute_floating_ip_delete(droplet_id):
    c = doctl("compute", "floating-ip", "delete", droplet_id, expect_json=False)
    return c.return_code == 0


def compute_floating_ip_list():
    return doctl("compute", "floating-ip", "list")


def compute_floating_ip_get(floating_ip, action_id):
    return doctl("compute", "floating-ip", "get", floating_ip, action_id)


def compute_floating_ip_assign(floating_ip, droplet_id):
    return doctl("compute", "floating-ip", floating_ip, droplet_id)


def compute_floating_ip_unassign(floating_ip):
    return doctl("compute", "floating-ip", "unassign", floating_ip)


def compute_image_list():
    return doctl("compute", "image", "list")


def compute_image_list_distribution():
    return doctl("compute", "image", "list-distribution")


def compute_image_list_application():
    return doctl("compute", "image", "list-application")


def compute_image_list_user():
    return doctl("compute", "image", "list-user")


def compute_image_get(image_id):
    return doctl("compute", "image", "get", image_id)


def compute_image_update(image_id, image_name):
    return doctl("compute", "image", "update", image_id, "--image-name", image_name)


def compute_image_delete(image_id):
    c = doctl("compute", "image", "update", image_id, "--force", expect_json=False)
    return c.return_code == 0


def compute_image_compute_image_action_get(image_id):
    return doctl("compute", "image-action", "get", image_id)


def compute_image_compute_image_action_transfer(image_id, region, wait=False):
    args = []
    if wait:
        args.extend(["--wait"])

    return doctl(
        "compute", "image-action", "transfer", image_id, "--region", region, *args
    )


def compute_load_balancer_get():
    pass


def compute_load_balancer_create(
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
        forwarding_rules = ",".join([f"{k}:{v}" for (k, v) in forwarding_rules.items()])
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

    return doctl("compute", "load-balancer", "create", load_balancer_update, *args)


def compute_load_balancer_update(
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
        forwarding_rules = ",".join([f"{k}:{v}" for (k, v) in forwarding_rules.items()])
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

    return doctl("compute", "load-balancer", "update", load_balancer_update, *args)


def compute_load_balancer_list():
    return doctl("compute", "load-balancer", "list")


def compute_load_balancer_delete(load_balancer_id):
    c = doctl("compute", "load-balancer", "delete", load_balancer_id, expect_json=False)
    return c.return_code == 0


def compute_load_balancer_add_droplets(load_balancer_id, droplet_ids):
    if not isinstance(str, droplet_ids):
        droplet_ids = ",".join(droplet_ids)

    args = []
    if droplet_ids:
        args.extend(["--droplet-ids", droplet_ids])

    return doctl("compute", "load-balancer", "add-droplets", load_balancer_id, *args)


def compute_load_balancer_remove_droplets():
    if not isinstance(str, droplet_ids):
        droplet_ids = ",".join(droplet_ids)

    args = []
    if droplet_ids:
        args.extend(["--droplet-ids", droplet_ids])

    return doctl("compute", "load-balancer", "remove-droplets", load_balancer_id, *args)


def compute_load_balancer_add_forwarding_rules(load_balancer_id, forwarding_rules=None):
    if hasattr(forwarding_rules, items):
        forwarding_rules = ",".join([f"{k}:{v}" for (k, v) in forwarding_rules.items()])

    args = []
    if forwarding_rules:
        args.extend(["--forwarding-rules", forwarding_rules])

    return doctl(
        "compute", "load-balancer", "add-forwarding-rules", load_balancer_id, *args
    )


def compute_load_balancer_remove_forwarding_rules(
    load_balancer_id, forwarding_rules=None
):
    if hasattr(forwarding_rules, items):
        forwarding_rules = ",".join([f"{k}:{v}" for (k, v) in forwarding_rules.items()])

    args = []
    if forwarding_rules:
        args.extend(["--forwarding-rules", forwarding_rules])

    c = doctl(
        "compute",
        "load-balancer",
        "remove-forwarding-rules",
        load_balancer_id,
        *args,
        expect_json=False,
    )
    return c.return_code == 0

def compute_plugin_list():
    return doctl("compute", "plugin", "list")

def compute_plugin_run(plugin_name):
    return doctl("compute", "plugin", "run", plugin_name)

def compute_region_list():
    return doctl("compute", "region", "list")

def compute_size_list():
    return doctl("compute", "size", "list")

def compute_snapshot_list():
    return doctl("compute", "snapshot", "list")

def compute_snapshot_get(snapshot_id):
    return doctl("compute", "snapshot", "get", snapshot_id)

def compute_snapshot_delete(snapshot_id):
    c = doctl("compute", "size", "list", expect_json=False)
    return c.return_code == 0

def compute_ssh_key_list():
    return doctl("compute", "ssh-key", "list")

def compute_ssh_key_get(key_id):
    return doctl("compute", "ssh-key", "get", key_id)

def compute_ssh_key_create(key_name, public_key):
    return doctl("compute", "ssh-key", "create", key_name, "--public-key", public_key)

def compute_ssh_key_import(key_name, public_key_file):
    return doctl("compute", "ssh-key", "import", key_name, "--public-key-file", public_key_file)

def compute_ssh_key_delete(key_id):
    c = doctl("compute", "ssh-key", "delete", key_id, '--force', expect_json=False)
    return c.return_code == 0

def compute_tag_create(tag_name):
    return doctl("compute", "tag", "create", tag_name)

def compute_tag_get(tag_name):
    return doctl("compute", "tag", "get", tag_name)

def compute_tag_list():
    return doctl("compute", "tag", "list")

def compute_tag_delete(tag_name):
    c = doctl("compute", "tag", "delete", tag_name, "--force", expect_json=False)
    return c.return_code == 0

def compute_volume_list():
    return doctl("compute", "volume", "list")

def compute_volume_create(volume_name, region, size, description=None):
    args = []
    args.extend(['--region', region])
    args.extend(['--size', size])
    if description:
        args.extend(['--description', description])
    return doctl("compute", "volume", "create", volume_name, *args)

def compute_volume_delete(volume_id):
    c = doctl("compute", "volume", "delete", volume_id, "--force", expect_json=False)
    return c.return_code == 0

def compute_volume_get(volume_id):
    return doctl("compute", "volume", "get", volume_id)

def compute_volume_snapshot(volume_id, name, description=None):
    args = []
    args.extend(["--snapshot-name", name])
    if description:
        args.extend(["--snapshot-desc", description])
    return doctl("compute", "volume", "snapshot", volume_id, *args)

def compute_volume_action_attach(volume_id, droplet_id):
    return doctl("compute", "volume-action", "attach", volume_id, droplet_id)

def compute_volume_action_detach(volume_id, droplet_id):
    return doctl("compute", "volume-action", "detach", volume_id, "--region", region, "--size", size)

def compute_volume_action_resize(volume_id, region, size):
    return doctl("compute", "volume-action", "resize", volume_id, "--region", region, "--size", size)

print(compute_volume_get('a397a0a3-5f9b-11e8-9b5e-0242ac110508'))
