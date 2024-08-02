import pynetbox
from pprint import pprint
import configparser
import yaml
import ipaddress
import sys

# Установите параметры подключения к NetBox
NETBOX_URL = "http://netbox.example.com"
NETBOX_TOKEN = "f1801f2f519ed714f24fd89b5cc63c598da711f6"

# Создайте объект API
nb = pynetbox.api(NETBOX_URL, token=NETBOX_TOKEN)

def convert_to_cidr(prefix):
    ip, netmask = prefix.split()
    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    ntwrk, msk = str(network).split('/')
    net = f'{ip}/{msk}'
    return net

def create_or_update_device(data, device_info):
    device_name = data['hostname']
    device_type = device_info['host.dev.type']
    device_role = device_info['host.role']
    site_name = device_info['host.site']

    device = nb.dcim.devices.get(name=device_name)
    if not device:
        device = nb.dcim.devices.create({
            "name": device_name,
            "device_type": device_info['host.dev.type.id'],
            "role": device_info['host.role.id'],
            "site": device_info['host.site.id'],
            "serial": "ABC123",
        })
    else:
        device.update({
            "device_type": device_info['host.dev.type.id'],
            "role": device_info['host.role.id'],
            "site": device_info['host.site.id'],
            "serial": "ABC123",
        })

    return device

def create_or_update_interfaces(device, interfaces):
    for intf in interfaces:
        interface_name = intf['name']
        interface_type = "virtual" if "Loopback" in interface_name else "1000base-t"
        description = intf.get('description', '')
        enabled = not intf.get('shutdown', False)

        interface = nb.dcim.interfaces.get(name=interface_name, device_id=device.id)
        if not interface:
            interface = nb.dcim.interfaces.create({
                "device": device.id,
                "name": interface_name,
                "type": interface_type,
                "description": description,
                "enabled": enabled,
            })
        else:
            interface.update({
                "type": interface_type,
                "description": description,
                "enabled": enabled,
            })

        if "ipv4_address" in intf:
            ip_address = intf["ipv4_address"]
            ip_adr = convert_to_cidr(ip_address)
            ip = nb.ipam.ip_addresses.get(address=ip_adr)
            if not ip:
                nb.ipam.ip_addresses.create({
                    "address": ip_adr,
                    "assigned_object_type": "dcim.interface",
                    "assigned_object_id": interface.id,
                })
            else:
                ip.update({
                    "assigned_object_type": "dcim.interface",
                    "assigned_object_id": interface.id,
                })

            if intf['name'] == 'Loopback0':
                int_ip = list(nb.ipam.ip_addresses.get(address=ip_adr))
                ip_id = int_ip[0]
                ipid = ip_id[1]
                device.update({'device': device.id,
                               'primary_ip4': ipid})

            elif 'MgmtEth' in intf['name']:
                int_ip = list(nb.ipam.ip_addresses.get(address=ip_adr))
                ip_id = int_ip[0]
                ipid = ip_id[1]
                device.update({'device': device.id,
                               'oob_ip': ipid})

def load_device_data(device_id, data_file):
    with open(data_file, 'r') as file:
        data = yaml.safe_load(file)
    return data['data'].get(device_id, {})

def load_config_files(file_paths):
    parsed_data = []
    for file_path in file_paths:
        with open(file_path, 'r') as file:
            parsed_data.append(yaml.safe_load(file))
    return parsed_data

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python script.py <msn_iosxr.yaml> <config_file1> <config_file2> ...")
        sys.exit(1)

    device_info_file = sys.argv[1]
    config_file_paths = sys.argv[2:]

    with open(device_info_file, 'r') as file:
        device_data = yaml.safe_load(file)

    for device_id, device_info in device_data['data'].items():
        config_files = [file for file in config_file_paths if device_info['host.name'] in file]
        if not config_files:
            print(f"No config file found for device {device_info['host.name']}")
            continue

        for config_file in config_files:
            with open(config_file, 'r') as file:
                config_data = yaml.safe_load(file)

            device = create_or_update_device(config_data, device_info)
            create_or_update_interfaces(device, config_data['interface'])

            print(f"Device {device.name} created/updated successfully with interfaces and other parameters.")

