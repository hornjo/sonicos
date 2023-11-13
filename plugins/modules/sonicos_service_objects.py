#!/usr/bin/python
# Copyright: (c) 2023, Horn Johannes (@hornjo)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module code for service objects"""

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
module: sonicos_service_objects

short_description: Manages all available features for service objects on SonicWALL
version_added: "1.0.0"
description:
- This brings the capability to authenticate, absolutly manage service objects and commits the changes
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
        description: Name of the service object.
        required: true
        type: str
    protocol:
        description: Protocol which should be used in the service object.
        required: true
        type: str
    begin:
        description: Defining the begin of a port range, only requiered with tcp and udp.
        required: false
        type: int
    end:
        description: Defining the end of a port range, only requiered with tcp and udp.
        required: false
        type: int
    sub_type:
        description: Defining the sub type for certain protocols. They Either are none by default or exactly accroding to the predefined ones by sonicwall.
        required: false
        default: "none"
        type: str
    custom_protocol:
        description: Defining the number of the custom protocol. Can be only between 1-255.
        required: false
        type: int
    state:
        description: Defines whether the service object should be present or absent. Default is present.
        type: str
        choices: "present", "absent"
        default: "present"


author:
    - Johannes Horn (@hornjo)
"""

EXAMPLES = r"""
- name: Creating IGMP service object.
  hornjo.sonicos.sonicos_service_objects:
    hostname: 192.168.178.254
    username: admin
    password: password
    object_name: Test2
    protocol: igmp
    sub_type: v2-member-report
    state: present

- name: Deleting UDP service object.
  hornjo.sonicos.sonicos_service_objects:
    hostname: 192.168.178.254
    username: admin
    password: password
    ssl_verify: false
    object_name: TestObject1
    protocol: udp
    begin: 8080
    end: 8081
    state: absent

- name: Creating custom service object.
  hornjo.sonicos.sonicos_service_objects:
    hostname: 192.168.178.254
    username: admin
    password: password
    ssl_verify: false
    object_name: CustomTest
    protocol: custom
    custom_protocol: 255
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
            "service_objects": [
                {
                    "name": "Test3",
                    "ospf": "link-state-update"
                }
            ]
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
    protocol=dict(
        type="str",
        choices=[
            "custom",
            "icmp",
            "igmp",
            "tcp",
            "udp",
            "gre",
            "esp",
            "6over4",
            "ah",
            "icmpv6",
            "eigrp",
            "ospf",
            "pim",
            "l2tp",
        ],
        required=True,
    ),
    begin=dict(type="int", required=False),
    end=dict(type="int", required=False),
    sub_type=dict(type="str", default="none", required=False),
    custom_protocol=dict(type="int", required=False),
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
        ["protocol", "custom", ["custom_protocol"]],
        ["protocol", "icmp", ["sub_type"]],
        ["protocol", "igmp", ["sub_type"]],
        ["protocol", "tcp", ["begin"] + ["end"]],
        ["protocol", "udp", ["begin"] + ["end"]],
        ["protocol", "icmpv6", ["sub_type"]],
        ["protocol", "ospf", ["sub_type"]],
        ["protocol", "pim", ["sub_type"]],
    ],
)

# Defining global variables
url_base = "https://" + module.params["hostname"] + "/api/sonicos/"
auth_params = (module.params["username"], module.params["password"])


# Defining actual module functions
def get_json_params():
    """Function builds json parameters"""
    json_params = {"service_objects": []}
    json_helper = {"name": module.params["object_name"], module.params["protocol"]: True}

    if module.params["protocol"] == "tcp" or module.params["protocol"] == "udp":
        json_helper = {
            "name": module.params["object_name"],
            module.params["protocol"]: {
                "begin": module.params["begin"],
                "end": module.params["end"],
            },
        }

    if (
        module.params["protocol"] == "icmp"
        or module.params["protocol"] == "igmp"
        or module.params["protocol"] == "icmpv6"
        or module.params["protocol"] == "ospf"
        or module.params["protocol"] == "pim"
    ):
        json_helper = {
            "name": module.params["object_name"],
            module.params["protocol"]: module.params["sub_type"].lower(),
        }

    if module.params["custom_protocol"] is not None:
        json_helper = {
            "name": module.params["object_name"],
            module.params["protocol"]: module.params["custom_protocol"],
        }

    json_params["service_objects"].append(json_helper)

    return json_params


def service_objects():
    """Creates idempotency of the module and defines action for the api"""
    api_action = None
    url = url_base + "service-objects"
    json_params = get_json_params()

    if module.params["state"] == "present":
        api_action = "post"

    req = requests.get(url, auth=auth_params, verify=module.params["ssl_verify"], timeout=10)

    if "service_objects" in req.json():
        for item in req.json()["service_objects"]:
            if item["name"] != module.params["object_name"]:
                continue

            if module.params["state"] == "present":
                api_action = "patch"

            del item["uuid"]

            if item == json_params["service_objects"][0]:
                if module.params["state"] == "absent":
                    api_action = "delete"
                    break
                api_action = None

    if api_action is not None:
        execute_api(url, json_params, api_action, auth_params, module, result)


# Defining the actual module actions
def main():
    """Main fuction which calls the functions"""
    if module.params["ssl_verify"] is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    authentication(url_base, auth_params, module, result)

    service_objects()

    commit(url_base, auth_params, module, result)

    module.exit_json(**result)


# Executing the module
if __name__ == "__main__":
    main()
