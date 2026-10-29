#!/usr/bin/python
# Copyright: (c) 2026, Dennison Williams (@DennisonWilliams) <dennison@dennisonwilliams.com>
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
    session,
    raise_for_error,
    logout,
)

__metaclass__ = type

DOCUMENTATION = r"""
---
module: sonicos_bandwidth_objects

short_description: Manages all available features for bandwidth objects on SonicWALL
version_added: "1.0.1"
description:
- This brings the capability to authenticate, absolutely manage bandwidth objects and commits the changes
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
        description: Defines whether you want to use trusted ssl certification verification or not. Default value is true.
        required: false
        type: bool
        default: true
    object_name:
        description: Name of the bandwidth object.
        required: true
        type: str
    guaranteed:
        description: The guaranteed bandwidth for the bandwidth object (kbps).
        required: true
        type: int
    maximum:
        description: Defining the maximum bandwidth for the bandwidth object (kbps).
        required: true
        type: int
    priority:
        description: Defining the traffic priority for the bandwidth object. "realtime" (0), "highest" (1), "high" (2), "medium_high" (3), "medium" (4), "medium_low" (5), "low" (6), "lowest" (7).
        required: false
        type: str
    violation_action:
        description: Determines what action to trigger when the threshold passes maximum capacity ("delay" or "drop").
        required: false
        default: "delay"
        type: str
    comment:
        description: Defining the comment for the bandwidth object.
        required: false
        type: str
    state:
        type: str
        choices: "present", "absent"
        default: "present"


author:
    - Dennison Williams (@DennisonWilliams)
"""

EXAMPLES = r"""
- name: Creating IGMP service object.
  hornjo.sonicos.sonicos_bandwidth_objects:
    hostname: 192.168.178.254
    username: admin
    password: password
    name: Limit-Backup-Speed
    guaranteed: 1000
    maximum: 1024
    priority: realtime
    violation_action: delay
    state: present

- name: Voip bandwidth object.
  hornjo.sonicos.sonicos_bandwidth_objects:
    hostname: 192.168.178.254
    username: admin
    password: password
    ssl_verify: false
    name: VoIP-Bandwidth
    guaranteed: 2048
    maximum: 10240
    priority: realtime
    violation_action: delay
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
            "bandwidth_objects": [
                {
                    "name": "Name of the bandwidth object",
                    "guaranteed": "The guaranteed bandwidth for this object: dict",
                    "maximum": "The maximum bandwidth for this object: dict",
                    "priority": "From realtime to lowest: str",
                    "action": "Delay or Drop",
                    "comment": "Object comment",
                    "per_ip_management": "Empty: dict",
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
    guaranteed=dict( type="int", default=0),
    maximum=dict( type="int", default=0),
    priority=dict(type="str", required=False),
    violation_action=dict(type="str", choices=["delay", "drop"], default="delay"),
    comment=dict(type="str", required=False),
    state=dict(type="str", choices=["present", "absent"], default="present")
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
auth_params = requests.auth.HTTPDigestAuth(module.params["username"], module.params["password"])


# Defining actual module functions
def get_json_params():
    """Function builds json parameters"""
    print("get_json_params() begin")
    json_params = {"bandwidth_objects": []}
    json_helper = {
        "name": module.params["object_name"],
        "priority": module.params["priority"],
        "action": module.params["violation_action"],
        "per_ip_management": {}
    }

    if module.params["guaranteed"] is not None and module.params["guaranteed"] != 0:
        json_helper["guaranteed"] = {
          "kbps": module.params["guaranteed"]
        }

    if module.params["maximum"] is not None and module.params["maximum"] != 0:
        json_helper["maximum"] = {
            "kbps": module.params["maximum"],
        }

    if module.params["comment"] is not None and module.params["comment"] != '':
        json_helper["comment"] = module.params["comment"]

    # TODO: handle per_ip_management / elemental
    json_params["bandwidth_objects"].append(json_helper)

    return json_params


def bandwidth_objects():
    """Creates idempotency of the module and defines action for the api"""

    api_action = None
    url = url_base + "bandwidth-objects"

    json_params = get_json_params()

    if module.params["state"] == "present":
        api_action = "post"

    req = session.get(url, auth=auth_params, verify=module.params["ssl_verify"], timeout=10)
    raise_for_error(url, req, module, result)

    if "bandwidth_objects" in req.json():
        for item in req.json()["bandwidth_objects"]:
            if item["name"] != module.params["object_name"]:
                continue

            if module.params["state"] == "present":
                api_action = "patch"

            if item == json_params["bandwidth_objects"][0]:
                if module.params["state"] == "absent":
                    api_action = "delete"
                    break
                api_action = None

    if api_action is not None:
        execute_api(url, json_params, api_action, auth_params, module, result)

# Defining the actual module actions
def main():
    """Main function which calls the functions"""
    if module.params["ssl_verify"] is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    authentication(url_base, auth_params, module, result)

    bandwidth_objects()

    commit(url_base, auth_params, module, result)

    logout(url_base, auth_params, module)

    module.exit_json(**result)


# Executing the module
if __name__ == "__main__":
    main()
