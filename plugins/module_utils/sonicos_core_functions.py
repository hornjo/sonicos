# Copyright: (c) 2023, Horn Johannes (@hornjo)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Module util for providing core functionalites"""

from __future__ import absolute_import, division, print_function
import json
import requests
from collections import OrderedDict

__metaclass__ = type
# SonicOS 6.5 releases have an issue with order of the headers, so we need to force requests to use the right order.
# For more details:  https://github.com/hornjo/sonicos/pull/5#issuecomment-2523443898
# Also, in the requests library we can only do this with Session objects:  https://requests.readthedocs.io/en/latest/user/advanced/#header-ordering
session = requests.Session()
# This is the same default headers provided by requests, just in a different order.
session.headers = OrderedDict([
    ('Accept', '*/*'),
    ('Accept-Encoding', requests.utils.DEFAULT_ACCEPT_ENCODING),
    ('User-Agent', requests.utils.default_user_agent()),
    ('Connection', 'keep-alive')
])

def raise_for_error(url, res, module, result, check_success=False):
    if res.status_code != 200 or (check_success and res.json()["status"]["success"] is not True):
        code = res.json()["status"]["info"][0]["code"]
        msg = res.json()["status"]["info"][0]["message"]
        text = 'API FAILURE:  URL: %s, FAILURE_CODE: %s, MESSAGE: %s' % (url, code, msg)
        module.fail_json(msg=text, **result)


def authentication(url_base, auth_params, module, result):
    """Basic authentication on the API"""
    url = url_base + "auth"
    res = session.post(url, auth=auth_params, verify=module.params["ssl_verify"], timeout=10)
    raise_for_error(url, res, module, result)
    # SonicOS 6.5 API is automatically in config mode and doesn't return this field.
    if 'config_mode' in res.json()["status"]["info"][0] and res.json()["status"]["info"][0]["config_mode"] == "No":
        configmode(url_base, auth_params, module, result)


def logout(url_base, auth_params, module):
    """Logout from the API"""
    url = url_base + "auth"
    session.delete(url, auth=auth_params, verify=module.params["ssl_verify"], timeout=10)
    # Ignore any failure response here, as the session is ending anyway.


def configmode(url_base, auth_params, module, result):
    """Enter config mode"""
    url = url_base + "config-mode"
    res = session.post(url, auth=auth_params, verify=module.params["ssl_verify"], timeout=10)
    raise_for_error(url, res, module, result)


def commit(url_base, auth_params, module, result):
    """Commits the changes to the API"""
    url = url_base + "config/pending"
    res = session.post(url, auth=auth_params, verify=module.params["ssl_verify"], timeout=10)
    raise_for_error(url, res, module, result, check_success=True)


def execute_api(url, json_params, api_action, auth_params, module, result):
    """Takes the needed action to the API from the module"""
    if api_action == "get":
        res = session.get(
            url,
            auth=auth_params,
            json=json_params,
            verify=module.params["ssl_verify"],
            timeout=10,
        )
    if api_action == "put":
        res = session.put(
            url,
            auth=auth_params,
            json=json_params,
            verify=module.params["ssl_verify"],
            timeout=10,
        )
    if api_action == "patch":
        res = session.patch(
            url,
            auth=auth_params,
            json=json_params,
            verify=module.params["ssl_verify"],
            timeout=10,
        )
    if api_action == "post":
        res = session.post(
            url,
            auth=auth_params,
            json=json_params,
            verify=module.params["ssl_verify"],
            timeout=10,
        )
    if api_action == "delete":
        res = session.delete(
            url,
            auth=auth_params,
            verify=module.params["ssl_verify"],
            timeout=10,
        )
    raise_for_error(url, res, module, result)
    result["changed"] = True
    result["output"] = json_params
    result["response"] = res.content


def sort_json(json_data):
    """Sorts nested json dicts and lists"""
    if isinstance(json_data, dict):
        return {key: sort_json(value) for key, value in json_data.items()}
    elif isinstance(json_data, list):
        if all(isinstance(item, dict) for item in json_data):
            return sorted(json_data, key=lambda x: json.dumps(sort_json(x), sort_keys=True))
        else:
            return sorted(json_data)
    return json_data


def compare_json(json1, json2):
    """Compares two nested json for idempotency"""
    sorted_json1 = sort_json(json1)
    sorted_json2 = sort_json(json2)
    return sorted_json1 == sorted_json2
