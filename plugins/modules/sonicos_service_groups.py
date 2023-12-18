#!/usr/bin/python
# Copyright: (c) 2023, Horn Johannes (@hornjo)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module code for service groups"""

from __future__ import absolute_import, division, print_function
import requests
import urllib3
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hornjo.sonicos.plugins.module_utils.sonicos_core_functions import (
    authentication,
    commit,
    execute_api,
    compare_json,
)

__metaclass__ = type

DOCUMENTATION = r"""
---
module: sonicos_service_groups

short_description: Manages all available features for service groups on SonicWALL
version_added: "1.0.0"
description:
- This brings the capability to authenticate, absolutly manage service groups and commits the changes
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
            - member_name:
                description: The name of member.
                required: true
                type: str
            - member_type:
                description: The type of member.
                required: true
                type: str
                choices: "service_object", "service_group"
    state:
        description: Defines whether the service object should be present or absent. Default is present.
        type: str
        choices: "present", "absent"
        default: "present"


author:
    - Johannes Horn (@hornjo)
"""

EXAMPLES = r"""
- name: Creating service group.
  hornjo.sonicos.sonicos_service_groups:
    hostname: 192.168.178.254
    username: admin
    password: password
    group_name: ServiceGroup1
    group_member:
      - {member_name: HTTP, member_type: service_object}
      - {member_name: HTTPS, member_type: service_object}
      - {member_name: AD Directory Services, member_type: service_group}
    state: present


- name: Deleting service group.
  hornjo.sonicos.sonicos_service_groups:
    hostname: 192.168.178.254
    username: admin
    password: password
    group_name: ServiceGroup2
    group_member:
      - {member_name: MS SQL, member_type: service_object}
      - {member_name: ServiceGroup1, member_type: service_group}
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
            "service_groups": [
                {
                    "name": "ServiceGroup1",
                    "service_group": [
                        {
                            "name": "AD Directory Services"
                        }
                    ],
                    "service_object": [
                        {
                            "name": "HTTP"
                        },
                        {
                            "name": "HTTPS"
                        }
                    ]
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
    group_name=dict(type="str", required=True),
    group_member=dict(
        type="list",
        required=True,
        member_name=dict(type="str", required=True),
        member_type=dict(type="str", choices=["service_object", "service_group"], required=True),
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
auth_params = (module.params["username"], module.params["password"])


# Defining actual module functions
def get_json_params():
    """Function builds json parameters"""
    json_params = {"service_groups": [{"name": module.params["group_name"]}]}
    json_member_group = {"service_group": []}
    json_member_object = {"service_object": []}

    for item in module.params["group_member"]:
        json_member_type = json_member_object["service_object"]

        if item["member_type"] == "service_group":
            json_member_type = json_member_group["service_group"]

        json_member_type.append({"name": item["member_name"]})

    if json_member_group != {"service_group": []}:
        json_params["service_groups"][0].update(json_member_group)

    if json_member_object != {"service_object": []}:
        json_params["service_groups"][0].update(json_member_object)

    return json_params


def service_groups():
    """Creates idempotency of the module and defines action for the api"""
    api_action = None
    url = url_base + "service-groups"
    json_params = get_json_params()

    if module.params["state"] == "present":
        api_action = "post"

    req = requests.get(url, auth=auth_params, verify=module.params["ssl_verify"], timeout=10)

    if "service_groups" in req.json():
        for item in req.json()["service_groups"]:
            if item["name"] != module.params["group_name"]:
                continue

            if module.params["state"] == "present":
                api_action = "put"

            del item["uuid"]

            if compare_json(item, json_params["service_groups"][0]) is True:
                if module.params["state"] == "absent":
                    api_action = "delete"
                    break
                api_action = None

    if api_action == "put" or api_action == "delete":
        url = url_base + "service-groups" + "/name/" + module.params["group_name"]

    if api_action is not None:
        execute_api(url, json_params, api_action, auth_params, module, result)


# Defining the actual module actions
def main():
    """Main fuction which calls the functions"""

    if module.params["ssl_verify"] is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    authentication(url_base, auth_params, module, result)

    service_groups()

    commit(url_base, auth_params, module, result)

    module.exit_json(**result)


# Executing the module
if __name__ == "__main__":
    main()
