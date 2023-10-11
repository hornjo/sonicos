from collections import OrderedDict
import requests

# VARIABLES
username="admin"
hostname="192.168.178.144"
# hostname="172.27.72.39"
password="walli4CHINA"
# password="Letmein123!"
baseurl="https://" + hostname + "/api/sonicos/"
auth=(username, password)

# AUTHENTICATION
endpoint="auth"
url=baseurl + endpoint
debug=requests.post(url, auth=auth, verify=False)

# START CONFIG MODE
endpoint="config-mode"
url=baseurl + endpoint
debug_config=requests.post(url, auth=auth, verify=False)
debug_config_message=debug_config.json()

# POST ADDRESS OBJECT
name="Test_Object01"
ip="10.0.0.1"
zone="WAN"
json_dict={
                "address_objects": [
                    {
                        "ipv4": {
                            "name": name,
                            "zone": zone,
                            "host": {
                                "ip": ip
                            }
                        }
                    }
                ]
            }
endpoint="address-objects/ipv4"
url=baseurl + endpoint
debug_ipv4=requests.post(url, auth=auth, json=json_dict, verify=False)

# COMMIT
endpoint="config/pending"
url=baseurl + endpoint
debug_commit=requests.post(url, auth=auth, verify=False)

# RUNNING
print(debug.json())
print(debug_config.json()['status']['info'][0]['message'])
# print(debug_ipv4.json())
# print(debug_commit.json())