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

import json
import requests

from ansible.module_utils.basic import AnsibleModule


def run_module():
    module_args = dict(
        hostname=dict(type='str', required=True),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True),
        object_type=dict(type='str', choices=['ipv4', 'ipv6', 'range', 'network', 'MAC', 'FQDN'], default='objects'),
        zone=dict(type='str', required=False, default='all'),
        name=dict(type='str', required=True),
        ip=dict(type='str', required=True),
        ip_range=dict(type='str', required=True),
        fqdn=dict(type='str', required=True),
        state=dict(type='str', choices=['present', 'absent'], required=True)
    )

    result = dict(
        changed=False,
        original_message='',
        message=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=[
            ['object_type', 'ipv4', ['ip']],
            ['object_type', 'ipv6', ['ip']],
            ['object_type', 'range', ['ip_range']],
            ['object_type', 'range', ['fqdn']],
        ]
    )

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    auth_url="https://" + module.params['hostname'] + "/api/sonicos/auth"
    requests.post(auth_url, auth=(module.params['username'], module.params['password']), verify=False)

    if module.params['state'].lower == "present":
        match module.params['object_type']:
            case "ipv4":
                url="https://" + module.params['hostname'] + "/api/sonicos/address-objects/ipv4"
                status=requests.get(url)
                status_dict=status.response.json()
                if status_dict['address_object']['ipv4']['ip']['name'] != module.params['name']:
                    json_dict={"address_object": {"ipv4": {"name": module.params['name'],"host": {"ip": module.params['ip'] },"zone": module.params['zone'] }}}
                    requests.post(url, json=json_dict)
                elif status_dict['address_object']['ipv4']['ip']['name'] == module.params['name']:
                    json_dict={"address_object": {"ipv4": {"name": module.params['name'],"host": {"ip": module.params['ip'] }}}}
                    requests.patch(url, json=json_dict)
            
    elif module.params['state'].lower == "absent":
        result['changed'] = True
    
    else:
        module.fail_json(msg='Bad state input, use either present or absent', **result)

    # during the execution of the module, if there is an exception or a
    # conditional state that effectively causes a failure, run
    # AnsibleModule.fail_json() to pass in the message and the result
    if module.params['name'] == 'fail me':
        module.fail_json(msg='You requested this to fail', **result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()