#!/usr/bin/python


# Copyright: (c) 2023, Horn Johannes (@hornjo)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import requests
import json


def authentication(url_base, auth_params, module, result):
    url = url_base + "auth"
    res = requests.post(url, auth=auth_params, verify=module.params["ssl_verify"])
    msg = res.json()["status"]["info"][0]["message"]
    if res.status_code != 200:
        module.fail_json(msg=msg, **result)
    if res.json()["status"]["info"][0]["config_mode"] == "No":
        configmode(url_base, auth_params, module, result)


def configmode(url_base, auth_params, module, result):
    url = url_base + "config-mode"
    res = requests.post(url, auth=auth_params, verify=module.params["ssl_verify"])
    msg = res.json()["status"]["info"][0]["message"]
    if res.status_code != 200:
        module.fail_json(msg=msg, **result)


def commit(url_base, auth_params, module, result):
    url = url_base + "config/pending"
    res = requests.post(url, auth=auth_params, verify=module.params["ssl_verify"])
    msg = res.json()["status"]["info"][0]["message"]
    if res.status_code != 200 or res.json()["status"]["success"] != True:
        module.fail_json(msg=msg, **result)


def execute_api(url, json_params, api_action, auth_params, module, result):
    match api_action:
        case "put":
            res = requests.put(url, auth=auth_params, json=json_params, verify=module.params["ssl_verify"])
        case "patch":
            res = requests.patch(url, auth=auth_params, json=json_params, verify=module.params["ssl_verify"])
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


def sort_json(json_data):
    if isinstance(json_data, dict):
        return {key: sort_json(value) for key, value in json_data.items()}
    elif isinstance(json_data, list):
        if all(isinstance(item, dict) for item in json_data):
            return sorted(json_data, key=lambda x: json.dumps(sort_json(x), sort_keys=True))
        else:
            return sorted(json_data)
    else:
        return json_data


def compare_json(json1, json2):
    sorted_json1 = sort_json(json1)
    sorted_json2 = sort_json(json2)
    return sorted_json1 == sorted_json2
