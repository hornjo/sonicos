#!/usr/bin/python
# Copyright: (c) 2023, Horn Johannes (@hornjo)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module code for interfaces"""

from __future__ import absolute_import, division, print_function
import requests
import urllib3
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hornjo.sonicos.plugins.module_utils.sonicos_core_functions import (
    authentication,
    commit,
    execute_api,
    compare_json,
    session,
    raise_for_error,
)

__metaclass__ = type

DOCUMENTATION = r"""
---
module: sonicos_address_objects

short_description: Manages all available features for address objects on SonicWALL
version_added: "1.0.0"
description:
- This brings the capability to authenticate, manage all kinds of address objects and commits the changes
- This module is only supported on sonicos 7 or newer
options:
    hostname:
        description: Defines the endpoint of the sonicos.
        required: true
        type: str
    username:
        description: The username for the login and authentication.
        required: true
        type: str
    password:
        description: The password for the authentication and login.
        required: true
        type: str
    ssl_verify:
        description: Defines whether you want to use trusted ssl certification verfication or not. Default value is true.
        required: false
        type: bool
        default: True

    state:
        description: Defines whether a object should be present or absent. Default is present.
        type: str
        choices: "present", "absent"
        default: "present"


author:
    - Johannes Horn (@hornjo)
"""

EXAMPLES = r"""
- name:
  hornjo.sonicos.sonicos_address_object:
    hostname: 192.168.178.254
    username: admin
    password: password
    ssl_verify: false
    state: present

- name:
  hornjo.sonicos.sonicos_address_object:
    hostname: 192.168.178.254
    username: admin
    password: password
    state: absent

- name:
  hornjo.sonicos.sonicos_address_object:
    hostname: 192.168.178.254
    username: admin
    password: password
    state: present


"""

RETURN = r"""
result:
    description: information about performed operation
    returned: always
    type: str
    sample: {
        "changed": false,
        "failed": false,
        "output": {}
"""


# Defining module arguments
module_args = dict(
    hostname=dict(type="str", required=True),
    username=dict(type="str", required=True),
    password=dict(type="str", required=True, no_log=True),
    ssl_verify=dict(type="bool", default=True),
    interface_name=dict(type="str", required=True),
    shutdown_port=dict(type="bool", required=True),
    ip_assignment=dict(type="str", choices=["dhcp", "static"], default="static"),
    gateway=dict(type="str", required=False, default="0.0.0.0"),
    ip_address=dict(type="str", required=False),
    subnetmask=dict(type="str", required=False),
    dns=dict(
        type="dict",
        options=dict(
            primary=dict(type="str", default="0.0.0.0"),
            secondary=dict(type="str", default="0.0.0.0"),
            tertiary=dict(type="str", default="0.0.0.0"),
        ),
        default=dict(
            primary="0.0.0.0",
            secondary="0.0.0.0",
            tertiary="0.0.0.0",
        ),
    ),
    dhcp_hostname=dict(type="str", default=""),
    dhcp_renew_on_link_up=dict(type="bool", default=False),
    dhcp_renew_on_startup=dict(type="bool", default=False),
    zone=dict(type="str", required=False),
    vlan=dict(type="int", required=False),
    tunnel=dict(type="int", required=False),
    mtu=dict(type="int", default=1500),
    comment=dict(type="str", default=""),
    management=dict(
        type="dict",
        options=dict(
            domain_fqdn=dict(type="str", default=""),
            https=dict(type="bool", default=False),
            ping=dict(type="bool", default=False),
            snmp=dict(type="bool", default=False),
            ssh=dict(type="bool", default=False),
        ),
        default=dict(
            domain_fqdn="",
            https=False,
            ping=False,
            snmp=False,
            ssh=False,
        ),
    ),
    user_login=dict(
        type="dict",
        options=dict(
            http=dict(type="bool", default=False),
            https=dict(type="bool", default=False),
        ),
        default=dict(
            http=False,
            https=False,
        ),
    ),
    https_redirect=dict(type="bool", default=False),
    auto_link_speed=dict(type="bool", default=True),
    mac=dict(type="bool", default=True),
    send_icmp_fragmentation=dict(type="bool", default=False),
    fragment_packets=dict(type="bool", default=True),
    ignore_df_bit=dict(type="bool", default=False),
    auto_discovery=dict(type="bool", default=False),
    multicast=dict(type="bool", default=False),
    cos_8021p=dict(type="bool", default=False),
    exclude_route=dict(type="bool", default=False),
    asymmetric_route=dict(type="bool", default=False),
    management_traffic_only=dict(type="bool", default=False),
    flow_reporting=dict(type="bool", default=True),
    bandwidth_egress=dict(type="int", required=False),
    bandwidth_ingress=dict(type="int", required=False),
    redundant_aggregation=dict(type="str", choices=["aggregation", "redundancy"]),
    redundant_aggregation_port=dict(type="list", elements="str"),
    state=dict(type="str", choices=["present", "absent"], default="present"),
)

# Defining registerable values
result = dict(
    changed=False,
    output=None,
)

# Defining ansible settings
module = AnsibleModule(
    argument_spec=module_args,
    supports_check_mode=True,
    required_if=[
        ["ip_assignment", "static", ["ip_address", "subnetmask"]],
        ["zone", "wan", ["send_icmp_fragmentation", "fragment_packets", "ignore_df_bit"]],
    ],
)

# Defining global variables
url_base = "https://" + module.params["hostname"] + "/api/sonicos/"
auth_params = requests.auth.HTTPDigestAuth(module.params["username"], module.params["password"])


# Defining actual module functions
def get_json_params():
    """Function builds json parameters"""
    json_params = {"interfaces": []}

    json_helper = {
        "ipv4": {
            "name": module.params["interface_name"],
            "mtu": module.params["mtu"],
            "link_speed": {"auto_negotiate": module.params["auto_link_speed"]},
            "mac": {"default": module.params["mac"]},
            "ip_assignment": {},
            "shutdown_port": module.params["shutdown_port"],
            "flow_reporting": module.params["flow_reporting"],
            "exclude_route": module.params["exclude_route"],
            "cos_8021p": module.params["cos_8021p"],
            "bandwidth_management": {
                "egress": {},
                "ingress": {},
            },
            "asymmetric_route": module.params["asymmetric_route"],
            "multicast": module.params["multicast"],
        }
    }

    if module.params["shutdown_port"] is False:
        optional_json_params = {
            "vlan": module.params["vlan"],
            "tunnel": module.params["tunnel"],
            "comment": module.params["comment"],
            "management": {
                "fqdn_assignment": module.params["management"]["domain_fqdn"],
                "https": module.params["management"]["https"],
                "ping": module.params["management"]["ping"],
                "snmp": module.params["management"]["snmp"],
                "ssh": module.params["management"]["ssh"],
            },
            "user_login": {
                "http": module.params["user_login"]["http"],
                "https": module.params["user_login"]["http"],
            },
            "management_traffic_only": module.params["management_traffic_only"],
            "port": {},
        }

        for key, value in optional_json_params.items():
            if value is not None:
                json_helper["ipv4"].update({key: value})

        ip_assigment_params = {
            "ip_assignment": {
                "mode": {
                    "dhcp": {
                        "force_discover_interval": 0,
                        "hostname": module.params["dhcp_hostname"],
                        "initiate_renewals_with_discover": False,
                        "renew_on_link_up": module.params["dhcp_renew_on_link_up"],
                        "renew_on_startup": module.params["dhcp_renew_on_startup"],
                    }
                },
                "zone": module.params["zone"],
            }
        }

        if module.params["ip_assignment"] == "static":
            ip_assigment_params = {
                "ip_assignment": {
                    "mode": {
                        "static": {
                            "gateway": module.params["gateway"],
                            "ip": module.params["ip_address"],
                            "netmask": module.params["subnetmask"],
                        },
                    },
                    "zone": module.params["zone"],
                }
            }

            if module.params["zone"] == "WAN":
                dns_params = {
                    "dns": {
                        "primary": module.params["dns"]["primary"],
                        "secondary": module.params["dns"]["secondary"],
                        "tertiary": module.params["dns"]["tertiary"],
                    },
                }

                ip_assigment_params["ip_assignment"]["mode"]["static"].update(dns_params)

        json_helper["ipv4"].update(ip_assigment_params)

        if module.params["zone"] == "WAN":
            wan_params = {
                "fragment_packets": module.params["fragment_packets"],
                "send_icmp_fragmentation": module.params["send_icmp_fragmentation"],
            }
            if module.params["fragment_packets"] is True:
                df_bit_params = {
                    "ignore_df_bit": module.params["ignore_df_bit"],
                }
                wan_params.update(df_bit_params)

            json_helper["ipv4"].update(wan_params)

        if module.params["management"]["https"] is True:
            https_params = {
                "https_redirect": module.params["https_redirect"],
            }

            json_helper["ipv4"].update(https_params)

        if module.params["bandwidth_egress"] is not None:
            egress_params = {"amount": module.params["bandwidth_egress"]}
            json_helper["ipv4"]["bandwidth_management"]["egress"].update(egress_params)

        if module.params["bandwidth_ingress"] is not None:
            ingress_params = {"amount": module.params["bandwidth_ingress"]}
            json_helper["ipv4"]["bandwidth_management"]["ingress"].update(ingress_params)

        port_params = {"redundancy_aggregation": False}

        if module.params["redundant_aggregation"] == "aggregation":
            port_params = {"aggregation": {"aggregate": []}}

            for index, value in enumerate(sorted(module.params["redundant_aggregation_port"])):
                port_params_helper = {
                    "aggno": index + 1,
                    "interface": value,
                }
                port_params["aggregation"]["aggregate"].append(port_params_helper)

        if module.params["redundant_aggregation"] == "redundancy":
            port_params = {
                module.params["redundant_aggregation"]: {
                    "interface": module.params["redundant_aggregation_port"][0]
                }
            }

        json_helper["ipv4"]["port"].update(port_params)

    json_params["interfaces"].append(json_helper)

    return json_params


def interfaces():
    """Creates idempotency of the module and defines action for the api"""
    api_action = None
    url = url_base + "interfaces/ipv4"
    json_params = get_json_params()

    if module.params["state"] == "present":
        api_action = "post"

    req = session.get(url, auth=auth_params, verify=module.params["ssl_verify"], timeout=10)
    raise_for_error(url, req, module, result)

    if "interfaces" in req.json():
        for item in req.json()["interfaces"]:
            if item["ipv4"]["name"] != module.params["interface_name"]:
                continue

            if module.params["state"] == "present":
                api_action = "put"

            keys = [
                "uuid",
                "one_arm_mode",
                "one_arm_peer",
                "routed_mode",
            ]

            for key in keys:
                try:
                    del item["ipv4"][key]
                except KeyError:
                    continue

            # Debug
            # module.fail_json(msg=json_params["interfaces"][0], **result)
            # module.fail_json(msg=item, **result)

            if compare_json(item, json_params["interfaces"][0]) is True:
                if module.params["state"] == "absent":
                    api_action = "delete"
                    break
                api_action = None

            if (
                module.params["redundant_aggregation"] not in item["ipv4"]["port"]
                and module.params["redundant_aggregation"] is not None
            ):
                tmp_port_params = {
                    "port": {"redundancy_aggregation": False},
                }
                tmp_json_params = {"interfaces": [item]}
                tmp_json_params["interfaces"][0]["ipv4"].update(tmp_port_params)

                # module.fail_json(msg=tmp_json_params, **result)

                req = session.patch(
                    url,
                    auth=auth_params,
                    json=tmp_json_params,
                    verify=module.params["ssl_verify"],
                    timeout=10,
                )
                raise_for_error(url, req, module, result)
                commit(url_base, auth_params, module, result)

    # Debug
    # module.fail_json(msg=api_action, **result)

    if api_action is not None:
        execute_api(url, json_params, api_action, auth_params, module, result)


# Defining the actual module actions
def main():
    """Main function which calls the functions"""

    if module.params["ssl_verify"] is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    authentication(url_base, auth_params, module, result)

    interfaces()

    commit(url_base, auth_params, module, result)

    module.exit_json(**result)


# Executing the module
if __name__ == "__main__":
    main()
