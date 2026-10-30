#!/usr/bin/python
# Copyright: (c) 2026, Dennison Williams (@dennisonwilliams)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module code for SonicOS DHCP server configuration"""

from __future__ import absolute_import, division, print_function
import os
import requests
import urllib3
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hornjo.sonicos.plugins.module_utils.sonicos_core_functions import (
    authentication,
    raise_for_error,
    execute_api,
    logout,
)
from plugins.module_utils.sonicos_core_functions import raise_for_error  # NOQA

__metaclass__ = type

DOCUMENTATION = r"""
---
module: sonicos_dhcp_server

short_description: Configure the DHCP server on the SonicWALL device for IPv4.
TODO: Implement IPv6 DHCP server configuration.
version_added: "1.0.2"
description:
- This brings the capability to configure the DHCP server on the SonicWALL device.
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
        default: True
    conflict_detection:
        description: Enable or disable conflict detection for the DHCP server.
        required: False
        type: bool
        default: True
    enable:
        description: Enable or disable the DHCP server.
        required: True
        type: bool
        default: False
    persistence:
        description: Enable or disable persistence for the DHCP server.
        required: False
        type: bool
        default: True
    persistence_monitoring_interval:
        description: Define the monitoring interval for persistence of the DHCP server.
        required: False
        type: int
        default: 5
    recycle_expired_lease:
        description: Enable or disable recycling of expired leases for the DHCP server.
        required: False
        type: int
        default: 0
    trusted_relay_agents:
        description: Define the trusted relay agents for the DHCP server.
        required: False
        type: str
        default: ""


author:
    - Dennison Williams (@DennisonWilliams)
"""

EXAMPLES = r"""
- name:  Enable the DHCP server on the SonicWALL device.
  hornjo.sonicos.sonicos_dhcp_server:
    hostname: 192.168.178.254
    username: admin
    password: password
    ssl_verify: false
    enable: true
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
    conflict_detection=dict(type="bool", required=False, default=True),
    enable=dict(type="bool", required=True, default=False),
    persistence=dict(type="bool", required=False, default=True),
    persistence_monitoring_interval=dict(type="int", required=False, default=5),
    recycle_expired_lease=dict(type="int", required=False, default=0),
    trusted_relay_agents=dict(type="str", required=False, default=""),
)

# Defining registerable values
result = dict(changed=False)

# Defining ansible settings
module = AnsibleModule(argument_spec=module_args, supports_check_mode=False)

# Defining global variables
url_base = "https://" + module.params["hostname"] + "/api/sonicos/"
auth_params = requests.auth.HTTPDigestAuth(module.params["username"], module.params["password"])

# Defining actual module functions
def get_json_params():
    """Function builds json parameters"""
    json_params = {"dhcp_server": []}
    json_helper = {}

    if module.params["enable"] is not None:
        json_helper["enable"] = module.params["enable"]

    if module.params["conflict_detection"] is not None:
        json_helper["conflict_detection"] = module.params["conflict_detection"]

    if module.params["persistence"] is not None:
        json_helper["persistence"] = module.params["persistence"]

    if module.params["persistence_monitoring_interval"] is not None:
        json_helper["persistence_monitoring_interval"] = module.params["persistence_monitoring_interval"]

    if module.params["recycle_expired_lease"] is not None:
        json_helper["recycle_expired_lease"] = module.params["recycle_expired_lease"]

    if module.params["trusted_relay_agents"] is not None:
        json_helper["trusted_relay_agents"] = module.params["trusted_relay_agents"]

    json_params["dhcp_server"].append(json_helper)
    return json_params

def dhcp_server():
    """Creates idempotency of the module and defines action for the api"""
    api_action = "put"
    url = url_base + "dhcp-server/ipv4/base"
    json_params = get_json_params()
    req = session.get(url, auth=auth_params, verify=module.params["ssl_verify"], timeout=10)
    raise_for_error(url, req, module, result)
 
    execute_api(url, json_params, api_action, auth_params, module, result)
    
     

# Defining the actual module actions
def main():
    """Main function which calls the functions"""

    if not module.params["ssl_verify"]:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    authentication(url_base, auth_params, module, result)

    dhcp_server()
    
    commit(url_base, auth_params, module, result)
    
    logout(url_base, auth_params, module)
    
    module.exit_json(**result)


# Executing the module
if __name__ == "__main__":
    main()
