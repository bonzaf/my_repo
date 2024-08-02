import ipaddress
import sys
import configparser
import yaml
from pprint import pprint
import time
import datetime
import re
from netmiko import (
    ConnectHandler,
    NetMikoAuthenticationException,
    NetmikoTimeoutException,
    ReadTimeout
)
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import pickle
import os
import time

startTime = time.time()

def dev_connect(ip_list):
    config = configparser.ConfigParser()
    username = ''
    password = ''
    pprint(ip_list)
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
                }
                device_params.append(devices)
        except ValueError as error:
            sys.exit("ip address is incorrect!")
    return device_params

def collect_datas(file_inventory, file_commands):
    ip_list_asr9k = []
    ip_list_xrv = []
    ip_list_ncs54 = []
    commands_list_asr9k = []
    commands_list_xrv = []
    commands_list_ncs54 = []
    send_dict = {}

    with open(file_inventory, 'r') as f_hosts, open(file_commands, 'r') as f_params:
        inventory = yaml.safe_load(f_hosts)
        command = yaml.safe_load(f_params)

        for device_id, device_data in inventory['data'].items():
            for dev_type, dev_param_list in command['oper_data_parsers'].items():
                ip = device_data['host.oob.ip']
                hardware_type = device_data['host.hw.type']

                for dev_param in dev_param_list:
                    hw_commands = dev_param['requests']
                    if dev_type == 'asr9k' and hw_commands not in commands_list_asr9k:
                        commands_list_asr9k.append(hw_commands)
                    elif dev_type == 'xrv' and hw_commands not in commands_list_xrv:
                        commands_list_xrv.append(hw_commands)
                    elif dev_type == 'ncs54' and hw_commands not in commands_list_ncs54:
                        commands_list_ncs54.append(hw_commands)

                if hardware_type == 'asr9k':
                    send_dict.setdefault(hardware_type, {'ip': [], 'commands': commands_list_asr9k})
                    if ip not in ip_list_asr9k:
                        ip_list_asr9k.append(ip)
                        send_dict[hardware_type]['ip'].append(ip)
                elif hardware_type == 'xrv':
                    send_dict.setdefault(hardware_type, {'ip': [], 'commands': commands_list_xrv})
                    if ip not in ip_list_xrv:
                        ip_list_xrv.append(ip)
                        send_dict[hardware_type]['ip'].append(ip)
                elif hardware_type == 'ncs54':
                    send_dict.setdefault(hardware_type, {'ip': [], 'commands': commands_list_ncs54})
                    if ip not in ip_list_ncs54:
                        ip_list_ncs54.append(ip)
                        send_dict[hardware_type]['ip'].append(ip)

        send_to_devs(send_dict, file_inventory)
        pprint(send_dict)
        runtime = float("%0.2f" % (time.time() - startTime))
        devcount = f'asr9k: {len(ip_list_asr9k)}, xrv: {len(ip_list_xrv)}, ncs54: {len(ip_list_ncs54)}'
        run_time = f'DONE RUNTIME: {runtime} SEC'
        return devcount, run_time

def send_to_devs(params_dict, inventory_file, limit=10):
    with open(inventory_file, 'r') as file:
        hosts_data = yaml.safe_load(file)['data']
    cmd_all_devices_output_dict = {}
    ip_to_host_id = {data['host.oob.ip']: host_id for host_id, data in hosts_data.items()}
    with ThreadPoolExecutor(max_workers=limit) as executor:
        futures = []
        for device_id, device_data in hosts_data.items():
            host_ip = device_data['host.oob.ip']
            hw_type = device_data['host.hw.type']
            commands = params_dict.get(hw_type, {}).get('commands', [])
            devices = dev_connect(host_ip)
            if commands:
                future = executor.submit(send_command_mark1, devices[0], commands)
                futures.append(future)

        for future in as_completed(futures):
            result = future.result()
            for ip, command in result[0].items():
                pprint(ip)
                cmd_all_devices_output_dict[ip_to_host_id[ip]] = command
                all_commands_output = ""
                for cmd, output in command.items():
                    for prmt, com in output.items():
                        all_commands_output += com + "\n"

                filename = f'{ip}_conf.txt'
                pprint(filename)
                with open(filename, 'w') as f_n:
                    f_n.write(all_commands_output)

    timestamp = datetime.now()
    result_collect_dict = {'@timestamp': timestamp, 'data': cmd_all_devices_output_dict.copy()}
    output_directory = r'/root/my_repo/temp_conf/'
    os.makedirs(output_directory, exist_ok=True)
    output_file_path = os.path.join(output_directory, f"{time.strftime('%Y%m%d-%H%M%S')}_odata_collect_inventory.pickle")

    with open(output_file_path, 'wb') as f:
        pickle.dump(result_collect_dict, f)
    return result_collect_dict

def send_command_mark1(device_data, command_list):
    command_output_dict = {}
    error_ip_str = ''
    ip = device_data['ip']
    command_output_dict[ip] = {}
    logging.getLogger('netmiko').setLevel(logging.WARNING)
    logging.basicConfig(format='%(threadName)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
    start_msg = '===> {} Connection: {}'
    received_msg = '<=== {} Received:   {}'
    logging.info(start_msg.format(datetime.now().time(), ip))
    pprint(device_data)
    try:
        with ConnectHandler(**device_data) as ssh:
            ssh.enable()
            prompt = ssh.find_prompt()
            results = {}
            for command_item in command_list:
                for command in command_item:
                    cmd = command['cmd']
                    cmd_type = command.get('type', 'static')
                    if cmd_type == 'static':
                        cmd_out = ssh.send_command(cmd)
                        command_output_dict[ip][cmd] = {prompt + cmd: prompt + cmd_out}
                        results[command['cmd']] = cmd_out
                    elif cmd_type == 'dynamic' and 'depends_on' in command:
                        dependency_output = results.get(command['depends_on'])
                        if dependency_output:
                            extracted_data = extract_data(dependency_output, command['depends_on'])
                            for dynamic_cmd in extracted_data:
                                cmd_out = ssh.send_command(dynamic_cmd)
                                command_output_dict[ip][dynamic_cmd] = {prompt + dynamic_cmd: prompt + dynamic_cmd + cmd_out}
            logging.info(received_msg.format(datetime.now().time(), ip))
    except (NetmikoTimeoutException, NetMikoAuthenticationException, ReadTimeout) as error:
        error_ip_str += f"Connection error: {ip}\n{error}\n{'*' * 100}\n"
    return command_output_dict, error_ip_str

if __name__ == "__main__":
    collect_datas('msn_iosxr.yaml', 'basic_collect_cmds.yaml')

