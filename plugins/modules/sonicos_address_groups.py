#!/usr/bin/python

# Copyright: (c) 2023, Horn Johannes (@hornjo)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: sonicos_address_groups

short_description: Manages all available featrues for address objects on SonicWALL
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
    # Enter missing parameters
    state:
        description: Defines whether a object should be present or absent. Default is present.
        required: true
        type: str 

extends_documentation_fragment:
    - hornjo.sonicos.sonicos_documentation

author:
    - Johannes Horn (@hornjo)
    - Marco Fuchs (@FuxMak)
"""

EXAMPLES = r"""
- name: # Enter sample playboos
  hornjo.sonicos.sonicos_address_groups:
    hostname: 192.168.178.254
    username: admin
    password: password
    ssl_verify: false



"""

RETURN = r"""
result:
    description: information about performed operation
    returned: always
    type: str
    sample: {
        "changed": false,
        "failed": false,
    }
"""


# Importing needed libraries
import requests
import urllib3
from ansible.module_utils.basic import AnsibleModule


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
        object_name=dict(type="str", choices=["host", "range", "network", "mac", "fqdn", "address_group"]),
        object_type=dict(type="str", choices=["host", "range", "network", "mac", "fqdn", "address_group"]),
    ),
    ip_version=dict(type="str", choices=["ipv4", "ipv6"], default="ipv4"),
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
        #   ["object_type", "host", ["ip"]],
    ],
)

# Defining global variables
url_base = "https://" + module.params["hostname"] + "/api/sonicos/"
url_address_groups = url_base + "address-groups/"
auth_params = (module.params["username"], module.params["password"])


# Defining actual module functions
def authentication():
    url = url_base + "auth"
    res = requests.post(url, auth=auth_params, verify=module.params["ssl_verify"])
    msg = res.json()["status"]["info"][0]["message"]
    if res.status_code != 200:
        module.fail_json(msg=msg, **result)
    if res.json()["status"]["info"][0]["config_mode"] == "No":
        configmode()


def configmode():
    url = url_base + "config-mode"
    res = requests.post(url, auth=auth_params, verify=module.params["ssl_verify"])
    msg = res.json()["status"]["info"][0]["message"]
    if res.status_code != 200:
        module.fail_json(msg=msg, **result)


def commit():
    url = url_base + "config/pending"
    res = requests.post(url, auth=auth_params, verify=module.params["ssl_verify"])
    msg = res.json()["status"]["info"][0]["message"]
    if res.status_code != 200:
        module.fail_json(msg=msg, **result)


def get_json_params(group_kind):
    group_type = module.params["ip_version"]

    json_params = {
        group_kind: [
            {
                group_type: {
                    "name": module.params["group_name"],
                }
            }
        ]
    }

    for item in module.params["group_member"]:
        group_member_kind = "address_object"
        type = module.params["ip_version"]

        if item["object_type"] == "address_group":
            group_member_kind = "address_group"

        if item["object_type"] == "mac" or item["object_type"] == "fqdn":
            type = item["object_type"]

        json_params[group_kind][0].update(
            {
                group_member_kind: {type: [{"name": item["object_name"]}]},
            }
        )
    return json_params


def execute_api_call(url, json_params, address_group_action):
    match address_group_action:
        case "patch":
            res = requests.patch(url, auth=auth_params, json=json_params, verify=module.params["ssl_verify"])
        case "post":
            res = requests.post(url, auth=auth_params, json=json_params, verify=module.params["ssl_verify"])
        case "delete":
            res = requests.delete(url, auth=auth_params, json=json_params, verify=module.params["ssl_verify"])
    if res.status_code == 200:
        result["changed"] = True
        return
    msg = res.json()["status"]["info"][0]["message"]
    module.fail_json(msg=msg, **result)


def address_group():
    url = url_address_groups + module.params["ip_version"]
    address_group_action = None
    group_kind = "address_groups"

    if len(module.params["group_member"]) == 1:
        group_kind = "address_group"

    json_params = get_json_params(group_kind)
    req = requests.get(url, auth=auth_params, verify=module.params["ssl_verify"])

    if module.params["state"] == "present":
        address_group_action = "post"

    if "address_groups" in req.json():
        for item in req.json()["address_groups"]:
            # Debug
            # module.fail_json(msg=item, **result)
            module.fail_json(msg=json_params[group_kind][0], **result)
            if item[module.params["ip_version"]]["name"] != module.params["group_name"]:
                continue

            if module.params["state"] == "present":
                address_group_action = "patch"

            del item[module.params["ip_version"]]["uuid"]

            # Debug
            # module.fail_json(msg=item, **result)

            if item == json_params["address_group"][0]:
                if module.params["state"] == "absent":
                    address_group_action = "delete"
                    break
                address_group_action = None

    if address_group_action != None:
        execute_api_call(url, json_params, address_group_action)


# Defining the actual module actions
def main():
    if module.params["ssl_verify"] == False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    authentication()

    address_group()

    commit()

    module.exit_json(**result)


# Executing the module
if __name__ == "__main__":
    main()
