#!/usr/bin/python

# Copyright: (c) 2023, Horn Johannes (@hornjo)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: sonicos_address_groups

short_description: Manages all available features for address groups on SonicWALL
version_added: "1.0.0"
description: 
- This brings the capability to authenticate, absolutly manage address groups and commits the changes
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
    group_name:
        description: The name for the group which will be worked with.
        required: true
        type: str
    group_member:
        description: The dictionary with the details of the group members.
        required: true
        type: list
        member_name:
            description: The name of member.
            required: true
            type: str
        member_type:
            description: The type of member.
            required: true
            type: str
            choices: "host", "range", "network", "mac", "fqdn", "address_group"
    state:
        description: Defines whether the group should be present or absent. Default is present.
        type: str
        choices: "present", "absent"
        default: "present"

author:
    - Johannes Horn (@hornjo)
    - Marco Fuchs (@FuxMak)
"""

EXAMPLES = r"""
- name: Creating an address group with mixed members. 
  hornjo.sonicos.sonicos_address_groups:
    hostname: 192.168.178.254
    username: admin
    password: password
    ssl_verify: false
    group_name: Test_Group1
    group_member: 
      - {member_name: Test_Object, member_type: fqdn}
      - {member_name: Test_Object2, member_type: host}
      - {member_name: ipv6, member_type: range}
      - {member_name: Test_Group2, member_type: address_group}
    state: present

- name: Deleting an address group with exact details of group and members.
  hornjo.sonicos.sonicos_address_groups:
    hostname: 192.168.178.254
    username: admin
    password: password
    ssl_verify: false
    group_name: Test_Group2
    group_member: 
      - {member_name: Test_Object, member_type: fqdn}
      - {member_name: Test_Object2, member_type: host}
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
            "address_groups": [
                {
                    "ipv6": {
                        "address_group": {
                            "ipv6": [
                                {
                                    "name": "Test_Group2"
                                }
                            ]
                        },
                        "address_object": {
                            "fqdn": [
                                {
                                    "name": "Test_Object"
                                }
                            ],
                            "ipv4": [
                                {
                                    "name": "Test_Object2"
                                }
                            ],
                            "ipv6": [
                                {
                                    "name": "ipv6"
                                }
                            ]
                        },
                        "name": "Test_Group2"
                    }
                }
            ]
        }
    }
"""


# Importing needed libraries
import requests
import urllib3
from flatten_json import flatten
from ansible.module_utils.basic import AnsibleModule
from ..module_utils.sonicos_core_functions import authentication, commit, execute_api, compare_json


# Defining module arguments
module_args = dict(
    hostname=dict(type="str", required=True),
    username=dict(type="str", required=True),
    password=dict(type="str", required=True, no_log=True),
    ssl_verify=dict(type="bool", default=True),
    group_name=dict(type="str", required=True),
    group_member=dict(
        type="list",
        required=True,
        member_name=dict(type="str", required=True),
        member_type=dict(type="str", choices=["host", "range", "network", "mac", "fqdn", "address_group"], required=True),
    ),
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
)

# Defining global variables
url_base = "https://" + module.params["hostname"] + "/api/sonicos/"
url_address_groups = url_base + "address-groups/"
auth_params = (module.params["username"], module.params["password"])


# Defining actual module functions
def get_address_member_type(address_member_name, address_object_kind):
    type = "ipv4"
    url = url_address_groups + "ipv6"

    if address_object_kind != "address_group":
        url = url_base + "address-objects/ipv6"

    req = requests.get(url, auth=auth_params, verify=module.params["ssl_verify"])

    flat_req = flatten(req.json())

    for value in flat_req.values():
        if address_member_name == value:
            type = "ipv6"
            break

    return type


def get_json_params():
    json_params = {"address_groups": []}
    json_member_group = {"address_group": {}}
    json_member_object = {"address_object": {}}
    group_type = "ipv4"

    for item in module.params["group_member"]:
        if item["member_type"] == "mac" or item["member_type"] == "fqdn":
            type = item["member_type"]

        if item["member_type"] != "mac" and item["member_type"] != "fqdn":
            type = get_address_member_type(item["member_name"], item["member_type"])

        json_member_type = json_member_object["address_object"]

        if item["member_type"] == "address_group":
            json_member_type = json_member_group["address_group"]

        try:
            json_member_type[type].append({"name": item["member_name"]})
        except:
            json_member_type.update(
                {
                    type: [
                        {"name": item["member_name"]},
                    ]
                },
            )

    if (
        "ipv6" in json_member_object["address_object"]
        or "mac" in json_member_object["address_object"]
        or "fqdn" in json_member_object["address_object"]
        or "ipv6" in json_member_group["address_group"]
    ):
        group_type = "ipv6"

    json_params_helper = {
        group_type: {"name": module.params["group_name"]},
    }

    if json_member_group != {"address_group": {}}:
        json_params_helper[group_type].update(json_member_group)

    if json_member_object != {"address_object": {}}:
        json_params_helper[group_type].update(json_member_object)

    json_params["address_groups"].append(json_params_helper)

    return json_params


def address_group():
    api_action = None
    json_params = get_json_params()

    ip_versions = ["ipv4", "ipv6"]

    if module.params["state"] == "present":
        api_action = "post"

    for ip_version in ip_versions:
        url = url_address_groups + ip_version
        req = requests.get(url, auth=auth_params, verify=module.params["ssl_verify"])

        if "address_groups" in req.json():
            for item in req.json()["address_groups"]:
                if api_action == "put":
                    break

                if item[ip_version]["name"] != module.params["group_name"]:
                    continue

                if module.params["state"] == "present":
                    api_action = "put"
                    exist_group_type = ip_version

                del item[ip_version]["uuid"]

                if compare_json(item, json_params["address_groups"][0]) == True:
                    if module.params["state"] == "absent":
                        api_action = "delete"
                        exist_group_type = ip_version
                        break
                    api_action = None
                    break

    if api_action == "post":
        json_helper = json_params["address_groups"][0]
        group_type = next(iter(json_helper))
        url = url_address_groups + group_type

    if api_action == "put":
        json_helper = json_params["address_groups"][0]
        group_type = next(iter(json_helper))
        json_params["address_groups"][0][exist_group_type] = json_params["address_groups"][0].pop(group_type)
        url = url_address_groups + exist_group_type + "/name/" + module.params["group_name"]

    if api_action == "delete":
        url = url_address_groups + exist_group_type + "/name/" + module.params["group_name"]

    if api_action != None:
        execute_api(url, json_params, api_action, auth_params, module, result)


# Defining the actual module actions
def main():
    if module.params["ssl_verify"] == False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    authentication(url_base, auth_params, module, result)

    address_group()

    commit(url_base, auth_params, module, result)

    module.exit_json(**result)


# Executing the module
if __name__ == "__main__":
    main()
