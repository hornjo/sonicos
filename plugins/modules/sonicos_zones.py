#!/usr/bin/python
# Copyright: (c) 2023, Horn Johannes (@hornjo)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module code for zones"""

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
module: sonicos_zones

short_description: Manages all available features for zones on SonicWALL
version_added: "1.0.0"
description:
- This brings the capability to authenticate, absolutly manage zones and commits the changes
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
        default: true
    zone_name:
        description: Name of the zone.
        required: true
        type: str
    security_type:
        description: Security type which can be chosen.
        required: true
        choices: "trusted", "public", "wireless", "sslvpn"
        type: str
    interface_trust:
        description: Selection of interface trust.
        required: false
        default: false
        type: bool
    auto_generate_access_rules:
        description: Rule for auto generation.
        required: false
        type: dict
        default:
            allow_from_to_equal=True,
            allow_from_higher=True,
            allow_to_lower=True,
            deny_from_lower=True
    ssl_settings:
        description: Related ssl settings for zones.
        required: false
        type: dict
        default:
            sslvpn_access=False,
            ssl_control=False,
            dpi_ssl_client=False,
            dpi_ssl_server=False
    advanced_services:
        description: All advanced settings.
        required: false
        type: dict
        default:
            create_group_vpn=False,
            gateway_anti_virus=False,
            intrusion_prevention=False,
            anti_spyware=False,
            app_control=False
    state:
        description: Defines whether the service object should be present or absent. Default is present.
        type: str
        choices: "present", "absent"
        default: "present"


author:
    - Johannes Horn (@hornjo)
"""

EXAMPLES = r"""
- name: Remove zone
  hornjo.sonicos.sonicos_zones:
    hostname: 192.168.178.254
    username: admin
    password: password
    zone_name: TestZone1
    security_type: public
    auto_generate_access_rules:
      allow_from_to_equal: false
      allow_from_higher: false
      allow_to_lower: false
    state: absent

- name: Create zone
  hornjo.sonicos.sonicos_zones:
    hostname: 192.168.178.254
    username: admin
    password: password
    ssl_verify: false
    zone_name: TestZone2
    security_type: trusted
    interface_trust: true
    ssl_settings:
            dpi_ssl_client=true
            dpi_ssl_server=true



"""

RETURN = r"""
result:
    description: information about performed operation
    returned: always
    type: str
    sample: {
        "changed": false,
        "failed": false,
        "output":
    }
"""


# Defining module arguments
module_args = dict(
    hostname=dict(type="str", required=True),
    username=dict(type="str", required=True),
    password=dict(type="str", required=True, no_log=True),
    ssl_verify=dict(type="bool", default=True),
    zone_name=dict(type="str", required=True),
    security_type=dict(
        type="str", choices=["trusted", "public", "wireless", "sslvpn"], required=True
    ),
    interface_trust=dict(type="bool", default=False),
    auto_generate_access_rules=dict(
        type="dict",
        options=dict(
            allow_from_to_equal=dict(type="bool", default=True),
            allow_from_higher=dict(type="bool", default=True),
            allow_to_lower=dict(type="bool", default=True),
            deny_from_lower=dict(type="bool", default=True),
        ),
        default=dict(
            allow_from_to_equal=True,
            allow_from_higher=True,
            allow_to_lower=True,
            deny_from_lower=True,
        ),
    ),
    ssl_settings=dict(
        type="dict",
        options=dict(
            sslvpn_access=dict(type="bool", default=False),
            ssl_control=dict(type="bool", default=False),
            dpi_ssl_client=dict(type="bool", default=False),
            dpi_ssl_server=dict(type="bool", default=False),
        ),
        default=dict(
            sslvpn_access=False,
            ssl_control=False,
            dpi_ssl_client=False,
            dpi_ssl_server=False,
        ),
    ),
    advanced_services=dict(
        type="dict",
        options=dict(
            create_group_vpn=dict(type="bool", default=False),
            gateway_anti_virus=dict(type="bool", default=False),
            intrusion_prevention=dict(type="bool", default=False),
            anti_spyware=dict(type="bool", default=False),
            app_control=dict(type="bool", default=False),
        ),
        default=dict(
            create_group_vpn=False,
            gateway_anti_virus=False,
            intrusion_prevention=False,
            anti_spyware=False,
            app_control=False,
        ),
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


def get_json_params():
    """Function builds json parameters"""

    json_params = {
        "zones": [
            {
                "name": module.params["zone_name"],
                "security_type": module.params["security_type"],
                "interface_trust": module.params["interface_trust"],
                "auto_generate_access_rules": {
                    "allow_from_to_equal": module.params["auto_generate_access_rules"][
                        "allow_from_to_equal"
                    ],
                    "allow_from_higher": module.params["auto_generate_access_rules"][
                        "allow_from_higher"
                    ],
                    "allow_to_lower": module.params["auto_generate_access_rules"]["allow_to_lower"],
                    "deny_from_lower": module.params["auto_generate_access_rules"][
                        "deny_from_lower"
                    ],
                },
                "gateway_anti_virus": module.params["advanced_services"]["gateway_anti_virus"],
                "intrusion_prevention": module.params["advanced_services"]["intrusion_prevention"],
                "app_control": module.params["advanced_services"]["app_control"],
                "anti_spyware": module.params["advanced_services"]["anti_spyware"],
                "create_group_vpn": module.params["advanced_services"]["create_group_vpn"],
                "ssl_control": module.params["ssl_settings"]["ssl_control"],
                "sslvpn_access": module.params["ssl_settings"]["sslvpn_access"],
                "dpi_ssl_client": module.params["ssl_settings"]["dpi_ssl_client"],
                "dpi_ssl_server": module.params["ssl_settings"]["dpi_ssl_server"],
            }
        ]
    }

    return json_params


def zones():
    """Creates idempotency of the module and defines action for the api"""
    api_action = None
    url = url_base + "zones"
    json_params = get_json_params()

    if module.params["state"] == "present":
        api_action = "post"

    req = requests.get(url, auth=auth_params, verify=module.params["ssl_verify"], timeout=10)

    if "zones" in req.json():
        for item in req.json()["zones"]:
            if item["name"] != module.params["zone_name"]:
                continue

            if module.params["state"] == "present":
                api_action = "patch"

            keys = [
                "uuid",
                "guest_services",
                "wireless",
                "websense_content_filtering",
                "local_radius_server",
            ]

            for key in keys:
                try:
                    del item[key]
                except KeyError:
                    continue

            if item == json_params["zones"][0]:
                if module.params["state"] == "absent":
                    api_action = "delete"
                    break
                api_action = None

    if api_action == "put" or api_action == "delete":
        url = url_base + "zones" + "/name/" + module.params["zone_name"]

    if api_action is not None:
        execute_api(url, json_params, api_action, auth_params, module, result)


# Defining the actual module actions
def main():
    """Main function which calls the functions"""

    if module.params["ssl_verify"] is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    authentication(url_base, auth_params, module, result)

    zones()

    commit(url_base, auth_params, module, result)

    module.exit_json(**result)


# Executing the module
if __name__ == "__main__":
    main()
