#!/usr/bin/python

# Copyright: (c) 2023, Horn Johannes (@hornjo)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: sonicos_service_objects

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
    # Enter documentation
    state:
        description: Defines whether the group should be present or absent. Default is present.
        type: str
        choices: "present", "absent"
        default: "present"

extends_documentation_fragment:
    - hornjo.sonicos.sonicos_documentation

author:
    - Johannes Horn (@hornjo)
    - Marco Fuchs (@FuxMak)
"""

EXAMPLES = r""" # Enter examples
- name: 
  hornjo.sonicos.sonicos_service_objects:
    hostname: 192.168.178.254
    username: admin
    password: password
    ssl_verify: false

    state: present

- name: 
  hornjo.sonicos.sonicos_service_objects:
    hostname: 192.168.178.254
    username: admin
    password: password
    ssl_verify: false

    state: absent



"""

RETURN = r""" # Enter return values
result:
    description: information about performed operation
    returned: always
    type: str
    sample: {
        "changed": false,
        "failed": false,
        "output": None
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
    object_name=dict(type="str", required=True),
    protocol=dict(type="str", choices=["custom", "icmp", "igmp", "tcp", "udp", "gre", "esp", "6over4", "ah", "icmpv6", "eigrp", "ospf", "pim", "l2tp"], required=True),
    begin=dict(type="str", required=False),
    end=dict(type="str", required=False),
    sub_type=dict(type="str", required=False),
    custom_protocol=dict(type="str", required=False),
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
    if res.status_code != 200 or res.json()["status"]["success"] != True:
        module.fail_json(msg=msg, **result)


def get_json_params():
    return json_params


def service_objects():
    api_action = None
    url = url_base + "service-objects"


def execute_api_call(url, json_params, api_action):
    match api_action:
        case "put":
            res = requests.put(url, auth=auth_params, json=json_params, verify=module.params["ssl_verify"])
        case "post":
            res = requests.post(url, auth=auth_params, json=json_params, verify=module.params["ssl_verify"])
        case "delete":
            res = requests.delete(url, auth=auth_params, verify=module.params["ssl_verify"])

    if res.status_code == 200:
        result["changed"] = True
        result["output"] = json_params
        return
    msg = res.json()["status"]["info"][0]["message"]
    module.fail_json(msg=msg, **result)


# Defining the actual module actions
def main():
    if module.params["ssl_verify"] == False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    authentication()

    commit()

    module.exit_json(**result)


# Executing the module
if __name__ == "__main__":
    main()
