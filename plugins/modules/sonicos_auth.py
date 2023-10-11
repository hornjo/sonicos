#!/usr/bin/python

# Copyright: (c) 2018, Terry Jones <terry.jones@example.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: sonicos_get_address_objects

short_description: Out puts all address objects based on a selection
version_added: "1.0.0"
description: 
- Within this module you can list address objects based on filters like: custom, zones, types, ip types, etc.
- This module is only supported on sonicos 7 or newer
options:
    name:
        description: This is the message to send to the test module.
        required: true
        type: str
    new:
        description:
            - Control to demo if the result of this module is changed or not.
            - Parameter description can be a list as well.
        required: false
        type: bool
# Specify this value according to your collection
# in format of namespace.collection.doc_fragment_name
# extends_documentation_fragment:
#     - my_namespace.my_collection.my_doc_fragment_name

author:
    - Johannes Horn (@hornjo)
'''

EXAMPLES = r'''
# Pass in a message
- name: Test with a message
  my_namespace.my_collection.my_test:
    name: hello world

# pass in a message and have changed true
- name: Test with a message and changed output
  my_namespace.my_collection.my_test:
    name: hello world
    new: true

# fail the module
- name: Test failure of the module
  my_namespace.my_collection.my_test:
    name: fail me
'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.
original_message:
    description: The original name param that was passed in.
    type: str
    returned: always
    sample: 'hello world'
message:
    description: The output message that the test module generates.
    type: str
    returned: always
    sample: 'goodbye'
'''

# Importing needed libraries
import requests
from ansible.module_utils.basic import AnsibleModule
import urllib3

# Disabeling HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Defining module arguments
module_args = dict(
    hostname=dict(type='str', required=True),
    username=dict(type='str', required=True),
    password=dict(type='str', required=True),
    ssl_verify=dict(type='bool', default=True)
)

# Defining registerable values
result = dict(
        changed=False,
    )

# Defining ansible settings
module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

# Defining global variables
baseurl="https://" + module.params['hostname'] + "/api/sonicos/"
auth_params=(module.params['username'], module.params['password'])

# Defining actual module functions
def authentication():
    endpoint="auth"
    url=baseurl + endpoint
    authentication=requests.post(url, auth=auth_params, verify=module.params['ssl_verify'])
    return authentication.status_code

def configmode():
    endpoint="config-mode"
    url=baseurl + endpoint
    configmode=requests.post(url, auth=auth_params, verify=module.params['ssl_verify'])
    return configmode

# Defining the actual module actions
def main():
    authStatus=authentication()
    if authStatus == 200:
        result['changed']=True
    else:
        print(authStatus)
        module.fail_json(msg='Not able to authenticate', **result)

    configStatus=configmode()
    if configStatus.status_code == 200:
        result['changed']=True
        module.exit_json(**result)
    elif configStatus.json()['status']['info'][0]['message'] == "Already in config mode.":
        result['changed']=False
        module.exit_json(**result)
    else:
        module.fail_json(msg='Not able to enter config mode', **result)

# Executing the module
if __name__ == '__main__':
    main()
