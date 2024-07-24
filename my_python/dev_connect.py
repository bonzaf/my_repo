import ipaddress
import sys
import configparser

# Retrieve credentials from environment variables
# Create a parser for the configuration file
config = configparser.ConfigParser()

try:
    config.read('crd.ini')
    username = config.get('Credentials', 'username')
    password = config.get('Credentials', 'password')
except FileNotFoundError:
    print("Configuration file not found.")
except configparser.NoSectionError:
    print("The 'Credentials' section is missing in the configuration file.")
except configparser.NoOptionError:
    print("One or more required options are missing in the 'Credentials' section.")



def dev_connect(ip_list):
    # Function to prepare device connection with check IP correction
    if type(ip_list) == str:
        ip_list = [ip_list]
    device_params = []
    for ip in ip_list:
        try:
            if ipaddress.ip_address(ip):
                devices = {
                    "device_type": "cisco_xr",
                    "ip": ip,
                    "username": username,
                    "password": password,
                    "conn_timeout": 120,
                    # "port": 23,
                }

                device_params.append(devices)
        except ValueError as error:
            #print(error)
            sys.exit("ip address is incorrect!")
    return device_params
