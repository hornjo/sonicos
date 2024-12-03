#!/usr/bin/python
# Copyright: (c) 2023, Horn Johannes (@hornjo)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module code for interfaces"""

from __future__ import absolute_import, division, print_function
import os
import requests
import urllib3
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hornjo.sonicos.plugins.module_utils.sonicos_core_functions import authentication, execute_api  # NOQA

__metaclass__ = type

DOCUMENTATION = r"""
---
module: sonicos_config_bkup

short_description: Export the configuration from SonicWALL
version_added: "1.0.0"
description:
- This brings the capability to authenticate and backup the device configuration, in either EXP or CLI format.
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
        description: Defines whether you want to use trusted ssl certification verfication or not. Default value is true.
        required: false
        type: bool
        default: True
    exp_format:
        description: Backup in EXP format, instead of CLI format.
        required: False
        type: bool
        default: False
    filename:
        description:
            - Name of file in which the running-config will be saved.
              If not specified, the filename will default to "backup" of .txt or .exp, for CLI or EXP type backups respectively.
        required: False
        type: str
    dir_path:
        description:
            - Path to directory in which the backup file should reside.
              If not specified, the backup file is written to the "backup" folder in the playbook root directory.
              If the directory does not exist, it is created.
        required: False
        type: str


author:
    - Kelly Shutt (@CompPhy)
"""

EXAMPLES = r"""
- name:  Create a backup of the device configuration into /tmp/config-backup/backup.txt on the Ansible controller, contents of the file will be in CLI export format.
  hornjo.sonicos.sonicos_config_bkup:
    hostname: 192.168.178.254
    username: admin
    password: password
    ssl_verify: false
    dir_path: /tmp/config-backup/
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
    exp_format=dict(type="bool", required=False, default=False),
    filename=dict(type="str", required=False, default=''),
    dir_path=dict(type="path", required=False, default='')
)

# Defining registerable values
result = dict(
    changed=False
)

# Defining ansible settings
module = AnsibleModule(
    argument_spec=module_args,
    supports_check_mode=False
)

# Defining global variables
url_base = "https://" + module.params["hostname"] + "/api/sonicos/"
auth_params = requests.auth.HTTPDigestAuth(module.params["username"], module.params["password"])


# Defining the actual module actions
def main():
    """Main function which calls the functions"""

    if not module.params["ssl_verify"]:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    authentication(url_base, auth_params, module, result)

    json_params = None
    api_action = 'get'
    url = url_base + 'export/current-config/cli'
    if module.params["exp_format"]:
        url = url_base + 'export/current-config/exp'

    dir_path = './backup'
    if module.params['dir_path']:
        dir_path = module.params['dir_path']

    filename = 'backup.txt'
    if module.params['exp_format']:
        filename = 'backup.exp'
    if module.params['filename']:
        filename = module.params['filename']
    
    output_file = os.path.join(dir_path, filename)

    execute_api(url, json_params, api_action, auth_params, module, result)

    with open(output_file, 'wb') as output:
        output.write(result['response'])

    module.exit_json(**result)


# Executing the module
if __name__ == "__main__":
    main()
