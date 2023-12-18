#!/usr/bin/python
# Copyright: (c) 2023, Horn Johannes (@hornjo)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module code for access rules"""

from __future__ import absolute_import, division, print_function
import requests
import urllib3
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hornjo.sonicos.plugins.module_utils.sonicos_core_functions import (
    authentication,
    commit,
    execute_api,
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
        required: True
        type: str
    username:
        description: The username for the login and authentication.
        required: True
        type: str
    password:
        description: The password for the authentication and login.
        required: True
        type: str
    ssl_verify:
        description: Defines whether you want to use thrusted ssl certification verfication or not. Default value is True.
        required: false
        type: bool

    state:
        description: Defines whether a object should be present or absent. Default is present.
        type: str
        choices: "present", "absent"
        default: "present"


author:
    - Johannes Horn (@hornjo)
    - Marco Fuchs (@FuxMak)
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
        "output": {
    }
"""


# Defining module arguments
module_args = dict(
    hostname=dict(type="str", required=True),
    username=dict(type="str", required=True),
    password=dict(type="str", required=True, no_log=True),
    ssl_verify=dict(type="bool", default=True),
    rule_name=dict(type="str", required=False),
    action=dict(type="str", choices=["allow", "deny", "discard"], default="allow"),
    source_zone=dict(type="str", required=True),
    source_address=dict(type="str", required=True),
    source_service=dict(type="str", required=True),
    destination_zone=dict(type="str", required=True),
    destination_address=dict(type="str", required=True),
    destination_service=dict(type="str", required=True),
    enable=dict(type="bool", default=True),
    auto_rule=dict(type="bool", default=False),
    users_include=dict(
        type="str",
        choices=[
            "All",
            "Everyone",
            "Trusted Users",
            "Content Filtering Bypass",
            "Limited Administrators",
            "SonicWall Administrators",
            "SonicWALL Read-Only Admins",
            "Guest Services",
            "Guest Administrators",
            "SSLVPN Services",
        ],
        default="All",
    ),
    users_exclude=dict(
        type="str",
        choices=[
            "None",
            "Everyone",
            "Trusted Users",
            "Content Filtering Bypass",
            "Limited Administrators",
            "SonicWall Administrators",
            "SonicWALL Read-Only Admins",
            "Guest Services",
            "Guest Administrators",
            "SSLVPN Services",
        ],
        default="None",
    ),
    comment=dict(type="str", required=False),
    max_connections=dict(type="int", required=False, default=100),
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
    required_if=[],
)

# Defining global variables
url_base = "https://" + module.params["hostname"] + "/api/sonicos/"
auth_params = (module.params["username"], module.params["password"])


# Defining actual module functions
def get_json_params():
    """Function builds json parameters"""
    json_params = {"access_rules": []}

    json_helper = {
        "ipv4": {
            "from": module.params["source_zone"],
            "to": module.params["destination_zone"],
            "action": module.params["action"],
            "schedule": {"always_on": True},
            "name": module.params["rule_name"],
            "comment": module.params["comment"],
            "enable": module.params["enable"],
            "auto_rule": module.params["auto_rule"],
            "max_connections": module.params["max_connections"],
            "logging": True,
            "sip": True,
            "h323": True,
            "management": True,
            "packet_monitoring": True,
            "packet_dissection_filter": {},
            "priority": {},
            "tcp": {"urgent": True, "timeout": 0},
            "udp": {"timeout": 0},
            "fragments": True,
            "botnet_filter": True,
            "connection_limit": {
                "destination": {"threshold": {"value": 0}},
                "source": {"threshold": {"value": 0}},
            },
            "dpi": True,
            "dpi_ssl": {"client": True, "server": True},
            "flow_reporting": True,
            "geo_ip_filter": {"enable": True, "global": True, "custom": True},
            "block": {"countries": {"unknown": True}, "country": [{"name": "string"}]},
            "quality_of_service": {"class_of_service": {}, "dscp": {}},
            "cos_override": True,
            "bandwidth_management": {"egress": {}, "ingress": {}, "usage_tracking": True},
            "ticket": {"tag1": "string", "tag2": "string", "tag3": "string"},
            "single_sign_on": True,
            "redirect_unauthenticated_users_to_log_in": True,
            "block_traffic_for_single_sign_on": True,
        }
    }

    source_address_params = {
        "source": {
            "address": {"any": True},
        }
    }
    if module.params["source_address"] != "any":
        source_address_params = {
            "source": {
                "address": {
                    get_address_type(module.params["source_address"]): module.params[
                        "source_address"
                    ]
                },
            },
        }

    source_service_params = {
        "port": {"any": True},
    }
    if module.params["source_service"] != "any":
        source_service_params = {
            "port": {
                get_service_type(module.params["source_service"]): module.params["source_service"]
            }
        }

    source_address_params["source"].update(source_service_params)
    json_helper["ipv4"].update(source_address_params)

    destination_params = {
        "destination": {
            "address": {"any": True},
        }
    }
    if module.params["destination_address"] != "any":
        destination_params = {
            "destination": {
                "address": {
                    get_address_type(module.params["destination_address"]): module.params[
                        "destination_address"
                    ]
                },
            },
        }

    json_helper["ipv4"].update(destination_params)

    service_params = {"service": {"any": True}}
    if module.params["destination_service"] != "any":
        service_params = {
            "service": {
                get_service_type(module.params["destination_service"]): module.params[
                    "destination_service"
                ]
            },
        }

    json_helper["ipv4"].update(service_params)

    user_params = {
        "users": {"included": {"all": True}, "excluded": {"none": True}},
    }
    if module.params["users_include"] != "All":
        include_user_params = {"included": {"group": module.params["users_include"]}}
        user_params["users"].update(include_user_params)

    if module.params["users_exclude"] != "None":
        exclude_user_params = {"excluded": {"group": module.params["users_exclude"]}}
        user_params["users"].update(exclude_user_params)

    json_helper["ipv4"].update(user_params)
    json_params["access_rules"].append(json_helper)

    return json_params


def get_address_type(address_name):
    """Determinig the type for source and destination address"""
    address_type = "name"

    for ip_version in "ipv4", "ipv6":
        url = url_base + "address-groups/" + ip_version
        req = requests.get(url, auth=auth_params, verify=module.params["ssl_verify"], timeout=10)

        if "address_groups" in req.json():
            for item in req.json()["address_groups"]:
                if item[ip_version]["name"] == address_name:
                    address_type = "group"
                    return address_type

    return address_type


def get_service_type(service_name):
    """Determinig the type for source and detination service"""
    service_type = "name"
    url = url_base + "service-groups"
    req = requests.get(url, auth=auth_params, verify=module.params["ssl_verify"], timeout=10)

    if "service_groups" in req.json():
        for item in req.json()["service_groups"]:
            if item["name"] == service_name:
                service_type = "group"
                break

    return service_type


def access_rules():
    """Creates idempotency of the module and defines action for the api"""
    api_action = None
    url = url_base + "access-rules/ipv4"
    json_params = get_json_params()

    if module.params["state"] == "present":
        api_action = "post"

    req = requests.get(url, auth=auth_params, verify=module.params["ssl_verify"], timeout=10)

    # Debug
    # module.fail_json(msg=json_params, **result)
    module.fail_json(msg=req.json(), **result)

    if "interfaces" in req.json():
        for item in req.json()["interfaces"]:
            if item["ipv4"]["name"] != module.params["interface_name"]:
                continue

            if module.params["state"] == "present":
                api_action = "patch"

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

    # Debug
    # module.fail_json(msg=api_action, **result)

    if api_action is not None:
        execute_api(url, json_params, api_action, auth_params, module, result)


# Defining the actual module actions
def main():
    """Main fuction which calls the functions"""

    if module.params["ssl_verify"] is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    authentication(url_base, auth_params, module, result)

    access_rules()

    commit(url_base, auth_params, module, result)

    module.exit_json(**result)


# Executing the module
if __name__ == "__main__":
    main()
