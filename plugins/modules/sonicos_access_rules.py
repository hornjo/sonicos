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
url_address_objects = url_base + "address-objects/"
auth_params = (module.params["username"], module.params["password"])


# Defining actual module functions
def get_json_params():
    """Function builds json parameters"""

    return json_params


def access_rules():
    """Creates idempotency of the module and defines action for the api"""

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
