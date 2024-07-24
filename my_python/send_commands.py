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
from dev_connection import dev_connect
import pickle
import os
from pprint import pprint
import yaml
import time

# collect data with ip:commands dicts
def send_to_devs(params_dict, inventory_file, limit=1000):
    with open(inventory_file, 'r') as file:
        hosts_data = yaml.safe_load(file)['data']
    cmd_all_devices_output_dict = {}
    ip_to_host_id = {data['host.ip']: host_id for host_id, data in hosts_data.items()}
    with ThreadPoolExecutor(max_workers=limit) as executor:
        futures = []
        for device_id, device_data in hosts_data.items():
            host_ip = device_data['host.ip']
            hw_type = device_data['host.hw.type']
            commands = params_dict.get(hw_type, {}).get('commands', [])
            devices = dev_connect(host_ip)
            if commands:
                future = executor.submit(send_command_mark1, devices[0], commands)
                futures.append(future)

        for future in as_completed(futures):
            result = future.result()
            for ip, command in result[0].items():
                #for cmd, output in command:

                cmd_all_devices_output_dict[ip_to_host_id[ip]] = command

    timestamp = datetime.now()
    result_collect_dict = {'@timestamp': timestamp, 'data': cmd_all_devices_output_dict.copy()}

    # Specify the directory where you want to save the file
    output_directory = r'C:\Users\yarik\PycharmProjects\global_network_audit\collect_data\\'

    # Ensure the directory exists, create if not
    os.makedirs(output_directory, exist_ok=True)

    # Construct the full path including the directory
    output_file_path = os.path.join(output_directory,
                                    f"{time.strftime('%Y%m%d-%H%M%S')}_odata_collect_inventory.pickle")

    with open(output_file_path, 'wb') as f:
        pickle.dump(result_collect_dict, f)
    return result_collect_dict


def send_command_mark1(device_data, command_list):
    """Send commands to a device and log the results, adapted for dynamic commands."""
    command_output_dict = {}
    error_ip_str = ''
    ip = device_data['ip']
    command_output_dict[ip] = {}
    logging.getLogger('netmiko').setLevel(logging.WARNING)
    logging.basicConfig(format='%(threadName)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
    start_msg = '===> {} Connection: {}'
    received_msg = '<=== {} Received:   {}'
    logging.info(start_msg.format(datetime.now().time(), ip))

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
                            extracted_data = extract_data(dependency_output, command['depends_on']) #here is DIR parsed
                            for dynamic_cmd in extracted_data:
                                cmd_out = ssh.send_command(dynamic_cmd)
                                command_output_dict[ip][dynamic_cmd] = {prompt + dynamic_cmd: prompt + dynamic_cmd + cmd_out}
            logging.info(received_msg.format(datetime.now().time(), ip))
    except (NetmikoTimeoutException, NetMikoAuthenticationException, ReadTimeout) as error:
        error_ip_str += f"Connection error: {ip}\n{error}\n{'*' * 100}\n"
    return command_output_dict, error_ip_str
