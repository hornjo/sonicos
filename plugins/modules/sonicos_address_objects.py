#!/usr/bin/python
# Copyright: (c) 2023, Horn Johannes (@hornjo)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module code for address objects"""

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
        description: Defines whether you want to use thrusted ssl certification verfication or not. Default value is true.
        required: false
        type: bool
    object_name:
        description: Name of the address object.
        required: true
        type: str
    object_type:
        description: Kind of the address object, like host, range, network, mac or fqdn.
        required: true
        type: str
    zone:
        description: Zone of the address object.
        required: true
        type: str
    ip:
        description: Ip of the address object when host is used.
        required: false
        type: str
    ip_range:
        description: Ip range of the address object when range is used.
        required: false
        type: dict
        begin:
            description: Begin of the ip range.
            required: false
            type: str
        end:
            description: End of the ip range.
            required: false
            type: str
    network:
        description: Ip range of the address object when network is used.
        required: false
        type: dict
        subnet:
            description: Net address of the network.
            required: false
            type: str
        mask:
            description: Subnet mask of the network.
            required: false
            type: str
    fqdn:
        description: Fqdn of the address object when fqdn is used.
        required: false
        type: str
    mac:
        description: Mac address of the address object when mac is used. Supported types are with/without colons and lowercase/uppercase.
        required: false
        type: str
    multi_homed:
        description: Defines whether a mac addres can be multi homed or not. Default is true.
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
- name: Create ipv4 host object
  hornjo.sonicos.sonicos_address_object:
    hostname: 192.168.178.254
    username: admin
    password: password
    ssl_verify: false
    object_name: my_object
    object_type: host
    zone: LAN
    ip: 10.5.5.9
    state: present

- name: Delete ipv6 host object
  hornjo.sonicos.sonicos_address_object:
    hostname: 192.168.178.254
    username: admin
    password: password
    object_name: my_object
    object_type: host
    ip_version: ipv6
    zone: VPN
    ip: 2a00:10:7557:4202:1c2c:b459:96df:e1b9
    state: absent

- name: Create range object
  hornjo.sonicos.sonicos_address_object:
    hostname: 192.168.178.254
    username: admin
    password: password
    object_name: my_object
    object_type: range
    zone: WLAN
    ip_range:
      begin: 10.5.5.5
      end: 10.5.5.7
    state: present

- name: Create network object
  hornjo.sonicos.sonicos_address_object:
    hostname: 192.168.178.254
    username: admin
    password: password
    object_name: my_object
    object_type: network
    zone: VPN
    network:
      subnet: 10.5.5.0
      mask: 255.255.255.0
    state: present

- name: Create mac object
  hornjo.sonicos.sonicos_address_object:
    hostname: 192.168.178.254
    username: admin
    password: password
    object_name: my_object
    object_type: mac
    zone: WAN
    mac: 00:e0:4c:67:11:9c
    state: present

- name: Create fqdn object
  hornjo.sonicos.sonicos_address_object:
    hostname: 192.168.178.254
    username: admin
    password: password
    object_name: my_object
    object_type: fqdn
    zone: WAN
    fqdn: github.com/hornjo
    state: absent

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
            "fqdn": {
                "domain": "github.com/hornjo",
                "name": "my_objcet",
                "zone": "WAN"
            }
    }
"""


# Defining module arguments
module_args = dict(
    hostname=dict(type="str", required=True),
    username=dict(type="str", required=True),
    password=dict(type="str", required=True, no_log=True),
    ssl_verify=dict(type="bool", default=True),
    object_name=dict(type="str", required=True),
    object_type=dict(
        type="str", choices=["host", "range", "network", "mac", "fqdn"], required=True
    ),
    zone=dict(type="str", required=True),
    ip_version=dict(type="str", choices=["ipv4", "ipv6"], default="ipv4"),
    ip=dict(type="str"),
    ip_range=dict(
        type="dict",
        begin=dict(type="str"),
        end=dict(type="str"),
    ),
    network=dict(
        type="dict",
        subnet=dict(type="str"),
        mask=dict(type="str"),
    ),
    fqdn=dict(type="str"),
    mac=dict(type="str"),
    multi_homed=dict(type="bool", default=True),
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
        ["object_type", "host", ["ip"]],
        ["object_type", "range", ["ip_range"]],
        ["object_type", "network", ["network"]],
        ["object_type", "mac", ["mac"]],
        ["object_type", "fqdn", ["fqdn"]],
    ],
)

# Defining global variables
url_base = "https://" + module.params["hostname"] + "/api/sonicos/"
url_address_objects = url_base + "address-objects/"
auth_params = (module.params["username"], module.params["password"])


# Defining actual module functions
def get_json_params(ip_type):
    """Function builds json parameters"""
    json_params = {
        "address_objects": [
            {
                ip_type: {
                    "name": module.params["object_name"],
                    "zone": module.params["zone"],
                }
            }
        ]
    }
    dict_object_type = json_params["address_objects"][0][ip_type]

    match module.params["object_type"]:
        case "host":
            dict_object_type["host"] = {"ip": module.params["ip"]}
        case "range":
            dict_object_type["range"] = {
                "begin": module.params["ip_range"]["begin"],
                "end": module.params["ip_range"]["end"],
            }
        case "network":
            dict_object_type["network"] = {
                "subnet": module.params["network"]["subnet"],
                "mask": module.params["network"]["mask"],
            }
        case "mac":
            dict_object_type["address"] = module.params["mac"].replace(":", "").upper()
            dict_object_type["multi_homed"] = module.params["multi_homed"]
        case "fqdn":
            dict_object_type["domain"] = module.params["fqdn"]

    return json_params


def address_object():
    """Creates idempotency of the module and defines action for the api"""
    ip_type = module.params["ip_version"]

    if module.params["object_type"] == "mac" or module.params["object_type"] == "fqdn":
        ip_type = module.params["object_type"]

    url = url_address_objects + ip_type
    api_action = None

    json_params = get_json_params(ip_type)
    req = requests.get(
        url, auth=auth_params, verify=module.params["ssl_verify"], timeout=10
    )

    if module.params["state"] == "present":
        api_action = "post"

    if "address_objects" in req.json():
        for item in req.json()["address_objects"]:
            if item[ip_type]["name"] != module.params["object_name"]:
                continue

            if module.params["state"] == "present":
                api_action = "patch"

            del item[ip_type]["uuid"]

            if item == json_params["address_objects"][0]:
                if module.params["state"] == "absent":
                    api_action = "delete"
                    break
                api_action = None

    if api_action == "put" or api_action == "delete":
        url = (
            url_base
            + "address-objects/"
            + ip_type
            + "/name/"
            + module.params["object_name"]
        )

    if api_action is not None:
        execute_api(url, json_params, api_action, auth_params, module, result)


# Defining the actual module actions
def main():
    """Main fuction which calls the functions"""

    if module.params["ssl_verify"] is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    authentication(url_base, auth_params, module, result)

    address_object()

    commit(url_base, auth_params, module, result)

    module.exit_json(**result)


# Executing the module
if __name__ == "__main__":
    main()
