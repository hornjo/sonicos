# Ansible Collection - hornjo.sonicos

## Disclaimer!

This collection is stil in development. But most of the modules are already working. This collection will be pushed on ansible galaxy once most common modules are exisiting. After this point modules will be maintained for the new releases of the sonicos and new modules might be added over time.

## Releases and Maintenance

| Release | Status                      | End of life  |
| ------: | --------------------------: | -----------: |
|       1 | Development                 | Not Released |

## Ansible version compability

This collection has been tested against following Ansible versions: **>=2.15.0**.
The compabile OS version of Sonicwall is **>=7.0.1-5145-R5175**.

## Installation and Usage

### Installing the Collection from Ansible Galaxy

Before using the VMware community collection, you need to install the collection with the `ansible-galaxy` CLI:

```shell
ansible-galaxy collection install hornjo.sonicos
```

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml` using the format:

```yaml
collections:
- name: hornjo.sonicos
```

### Installing Collection locally from GitHub

Since the collection is not on ansible galaxy yet, you have to install the ansible collection locally. For this do follwing steps:

Clone the git repo
```shell
git clone https://github.com/hornjo/sonicos.git
```

Create the namespace folder and move the collection in the generic ansible collection path.
```shell
mkdir ~/.ansible/collections/ansible_collections/hornjo

mv hornjo ~/.ansible/collections/ansible_collections/hornjo
```

### Required Pythion libraries

In order to use the modules of the collection, in total following python libraries are required:

- requests
- urllib3
- flatten_json

### Installing required libraries

Installing collection does not install any required third party Python libraries. You need to install the required Python libraries using following command:

```sell
pip install -r ~/.ansible/collections/ansible_collections/hornjo/sonicos/requirements.txt
``````

## Testing and Development

### Ansible-Test

### Contributing to collection
