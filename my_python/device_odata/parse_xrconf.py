import yaml
import re
from ciscoconfparse import CiscoConfParse
from pprint import pprint
import sys

def parse_config_file(file_path_list):
    results = []

    for file_path in file_path_list:
        with open(file_path, 'r') as file:
            config = file.read()

        parse = CiscoConfParse(config.splitlines())
        result = {}

        # Parse hostname
        hostname = parse.find_objects(r'^hostname ')[0].text.split()[1]
        result['hostname'] = hostname

        # Parse usernames
        usernames = parse.find_objects(r'^username ')
        result['username'] = []
        for user in usernames:
            username = {
                'name': user.text.split()[1],
                'group': [child.text.split()[1] for child in user.children if 'group' in child.text],
                'secret': next((child.text.split(' ', 2)[2] for child in user.children if 'secret' in child.text), None)
            }
            result['username'].append(username)

        # Parse AAA
        aaa = parse.find_objects(r'^aaa ')
        result['aaa'] = {}
        for a in aaa:
            aaa_type = a.text.split()[1]
            aaa_command = a.text.split()[2]
            aaa_value = ' '.join(a.text.split()[3:])
            if aaa_type not in result['aaa']:
                result['aaa'][aaa_type] = {}
            result['aaa'][aaa_type][aaa_command] = aaa_value

        # Parse simple flags
        if parse.find_objects(r'^cdp'):
            result['cdp'] = True

        # Parse VRF
        vrfs = parse.find_objects(r'^vrf ')
        result['vrf'] = []
        for vrf in vrfs:
            vrf_name = vrf.text.split()[1]
            address_family = vrf.re_search_children(r'address-family ')
            af_dict = {}
            for af in address_family:
                af_name = af.text.split()[1]
                import_rt = [child.text for child in af.re_search_children(r'import route-target')]
                export_rt = [child.text for child in af.re_search_children(r'export route-target')]
                af_dict[af_name] = {
                    'import_route_target': import_rt,
                    'export_route_target': export_rt
                }
            vrf_dict = {
                'name': vrf_name,
                'address-family': af_dict
            }
            result['vrf'].append(vrf_dict)

        # Parse line
        lines = parse.find_objects(r'^line ')
        result['line'] = {}
        for line in lines:
            line_name = line.text.split()[1]
            line_dict = {}
            for child in line.children:
                if 'authorization exec' in child.text:
                    line_dict['authorization_exec'] = child.text.split()[2]
                elif 'authorization commands' in child.text:
                    line_dict['authorization_commands'] = child.text.split()[2]
                elif 'login authentication' in child.text:
                    line_dict['login_authentication'] = child.text.split()[2]
                elif 'exec-timeout' in child.text:
                    line_dict['exec_timeout'] = ' '.join(child.text.split()[1:])
                elif 'session-limit' in child.text:
                    line_dict['session_limit'] = int(child.text.split()[1])
                elif 'session-timeout' in child.text:
                    line_dict['session_timeout'] = int(child.text.split()[1])
                elif 'transport input' in child.text:
                    line_dict['transport_input'] = child.text.split()[2]
                elif 'transport output' in child.text:
                    line_dict['transport_output'] = child.text.split()[2]
            result['line'][line_name] = line_dict

        # Parse vty pool
        vty_pools = parse.find_objects(r'^vty-pool ')
        result['vty_pool'] = {}
        for vty in vty_pools:
            pool_name = vty.text.split()[1]
            range_vals = vty.text.split()[2]
            line_template = vty.text.split()[4]
            result['vty_pool'][pool_name] = {
                'range': range_vals,
                'line_template': line_template
            }

        # Parse call home
        call_home = parse.find_objects(r'^call-home ')
        if call_home:
            result['call_home'] = {}
            for child in call_home[0].children:
                if 'service active' in child.text:
                    result['call_home']['service_active'] = True
                elif 'contact' in child.text:
                    result['call_home']['contact'] = child.text.split()[1]
                elif 'profile' in child.text:
                    profile_name = child.text.split()[1]
                    profile_active = any(grandchild.text == 'active' for grandchild in child.children)
                    destination_method = next((grandchild.text.split()[-1] for grandchild in child.children if
                                               'destination transport-method' in grandchild.text), None)
                    result['call_home']['profile'] = {
                        'name': profile_name,
                        'active': profile_active,
                        'destination_transport_method': destination_method
                    }

        # Parse interfaces
        interfaces = parse.find_objects(r'^interface ')
        result['interface'] = []
        for intf in interfaces:
            intf_dict = {
                'name': intf.text.split()[1]
            }
            for child in intf.children:
                if 'description' in child.text:
                    intf_dict['description'] = ' '.join(child.text.split()[1:])
                elif 'ipv4 address' in child.text:
                    intf_dict['ipv4_address'] = ' '.join(child.text.split()[2:])
                elif 'shutdown' in child.text:
                    intf_dict['shutdown'] = True
                elif 'vrf' in child.text:
                    intf_dict['vrf'] = child.text.split()[1]
                elif 'cdp' in child.text:
                    intf_dict['cdp'] = True
            result['interface'].append(intf_dict)

        # Parse route policies
        route_policies = parse.find_objects(r'^route-policy ')
        result['route_policy'] = []
        for rp in route_policies:
            rp_name = rp.text.split()[1]
            rp_statements = [child.text for child in rp.children]
            rp_dict = {
                'name': rp_name,
                'policy': rp_statements
            }
            result['route_policy'].append(rp_dict)

        # Parse router ospf
        ospf = parse.find_objects(r'^router ospf ')
        if ospf:
            ospf_dict = {}
            ospf_dict['name'] = ospf[0].text.split()[2]
            for child in ospf[0].children:
                if 'nsr' in child.text:
                    ospf_dict['nsr'] = True
                elif 'log adjacency changes detail' in child.text:
                    ospf_dict['log_adjacency_changes_detail'] = True
                elif 'router-id' in child.text:
                    ospf_dict['router_id'] = child.text.split()[1]
                elif 'segment-routing mpls' in child.text:
                    ospf_dict['segment_routing'] = {'mpls': True}
                elif 'segment-routing sr-prefer' in child.text:
                    ospf_dict['segment_routing']['sr_prefer'] = True
                elif 'auto-cost reference-bandwidth' in child.text:
                    ospf_dict['auto_cost_reference_bandwidth'] = int(child.text.split()[2])
                elif 'max-metric router-lsa on-startup' in child.text:
                    ospf_dict['max_metric_router_lsa_on_startup'] = int(child.text.split()[3])
                elif 'area' in child.text:
                    area_id = child.text.split()[1]
                    ospf_dict['area'] = {'id': area_id, 'interface': []}
                    for grandchild in child.children:
                        if 'interface' in grandchild.text:
                            intf_dict = {'name': grandchild.text.split()[1]}
                            for ggchild in grandchild.children:
                                if 'passive enable' in ggchild.text:
                                    intf_dict['passive'] = 'enable'
                                elif 'prefix-sid index' in ggchild.text:
                                    intf_dict['prefix_sid_index'] = int(ggchild.text.split()[2])
                                elif 'bfd' in ggchild.text:
                                    if 'bfd' not in intf_dict:
                                        intf_dict['bfd'] = {}
                                    if 'minimum-interval' in ggchild.text:
                                        intf_dict['bfd']['minimum_interval'] = int(ggchild.text.split()[2])
                                    elif 'fast-detect' in ggchild.text:
                                        intf_dict['bfd']['fast_detect'] = True
                                    elif 'multiplier' in ggchild.text:
                                        intf_dict['bfd']['multiplier'] = int(ggchild.text.split()[2])
                                elif 'cost' in ggchild.text:
                                    intf_dict['cost'] = int(ggchild.text.split()[1])
                                elif 'network' in ggchild.text:
                                    intf_dict['network'] = ggchild.text.split()[1]
                            ospf_dict['area']['interface'].append(intf_dict)
            result['router'] = {'ospf': ospf_dict}

        # Parse router bgp
        bgp = parse.find_objects(r'^router bgp ')
        if bgp:
            bgp_dict = {}
            bgp_dict['asn'] = int(bgp[0].text.split()[2])
            for child in bgp[0].children:
                if 'nsr' in child.text:
                    bgp_dict['nsr'] = True
                elif 'bgp router-id' in child.text:
                    bgp_dict['router_id'] = child.text.split()[2]
                elif 'mpls activate' in child.text:
                    bgp_dict['mpls_activate'] = True
                elif 'interface' in child.text:
                    bgp_dict['interface'] = child.text.split()[1]
                elif 'bgp graceful-restart' in child.text:
                    bgp_dict['graceful_restart'] = True
                elif 'bgp log neighbor changes detail' in child.text:
                    bgp_dict['log_neighbor_changes_detail'] = True
                elif 'ibgp policy out enforce-modifications' in child.text:
                    bgp_dict['ibgp_policy_out_enforce_modifications'] = True
                elif 'address-family' in child.text:
                    af_name = ' '.join(child.text.split()[1:]).replace(' ', '_')
                    if 'address_family' not in bgp_dict:
                        bgp_dict['address_family'] = {}
                    af_dict = {}
                    for grandchild in child.children:
                        if 'table-policy' in grandchild.text:
                            af_dict['table_policy'] = grandchild.text.split()[1]
                        elif 'network' in grandchild.text:
                            network = grandchild.text.split()[1]
                            route_policy = grandchild.text.split()[3]
                            af_dict['network'] = {network: {'route_policy': route_policy}}
                        elif 'allocate-label' in grandchild.text:
                            af_dict['allocate_label'] = grandchild.text.split()[1]
                    bgp_dict['address_family'][af_name] = af_dict
                elif 'neighbor' in child.text:
                    neighbor_ip = child.text.split()[1]
                    neighbor_dict = {'ip': neighbor_ip}
                    for grandchild in child.children:
                        if 'remote-as' in grandchild.text:
                            neighbor_dict['remote_as'] = int(grandchild.text.split()[1])
                        elif 'bfd' in grandchild.text:
                            if 'bfd' not in neighbor_dict:
                                neighbor_dict['bfd'] = {}
                            if 'fast-detect' in grandchild.text:
                                neighbor_dict['bfd']['fast_detect'] = True
                            elif 'multiplier' in grandchild.text:
                                neighbor_dict['bfd']['multiplier'] = int(grandchild.text.split()[2])
                            elif 'minimum-interval' in grandchild.text:
                                neighbor_dict['bfd']['minimum_interval'] = int(grandchild.text.split()[2])
                        elif 'ebgp-multihop' in grandchild.text:
                            neighbor_dict['ebgp_multihop'] = int(grandchild.text.split()[1])
                        elif 'dscp' in grandchild.text:
                            neighbor_dict['dscp'] = grandchild.text.split()[1]
                        elif 'description' in grandchild.text:
                            neighbor_dict['description'] = ' '.join(grandchild.text.split()[1:])
                        elif 'update-source' in grandchild.text:
                            neighbor_dict['update_source'] = grandchild.text.split()[1]
                        elif 'address-family' in grandchild.text:
                            af_name = ' '.join(grandchild.text.split()[1:]).replace(' ', '_')
                            af_dict = {}
                            for ggchild in grandchild.children:
                                if 'send-community-ebgp' in ggchild.text:
                                    af_dict['send_community_ebgp'] = True
                                elif 'route-policy' in ggchild.text:
                                    direction = ggchild.text.split()[1]
                                    rp_name = ggchild.text.split()[2]
                                    if 'route_policy' not in af_dict:
                                        af_dict['route_policy'] = {}
                                    af_dict['route_policy'][direction] = rp_name
                                elif 'send-extended-community-ebgp' in ggchild.text:
                                    af_dict['send_extended_community_ebgp'] = True
                                elif 'next-hop-unchanged' in ggchild.text:
                                    af_dict['next_hop_unchanged'] = True
                                elif 'maximum-prefix' in ggchild.text:
                                    af_dict['maximum_prefix'] = ' '.join(ggchild.text.split()[1:])
                            neighbor_dict['address_family'] = {af_name: af_dict}
                    bgp_dict['neighbor'] = neighbor_dict
                elif 'vrf' in child.text:
                    vrf_name = child.text.split()[1]
                    rd = None
                    af_dict = {}
                    for grandchild in child.children:
                        if 'rd' in grandchild.text:
                            rd = grandchild.text.split()[1]
                        elif 'address-family' in grandchild.text:
                            af_name = ' '.join(grandchild.text.split()[1:]).replace(' ', '_')
                            af_dict[af_name] = {}
                            for ggchild in grandchild.children:
                                if 'redistribute' in ggchild.text:
                                    if 'redistribute' not in af_dict[af_name]:
                                        af_dict[af_name]['redistribute'] = []
                                    af_dict[af_name]['redistribute'].append(ggchild.text.split()[1])
                    bgp_dict['vrf'] = {
                        'name': vrf_name,
                        'rd': rd,
                        'address_family': af_dict
                    }
            result['router']['bgp'] = bgp_dict

        # Save result for the current config file
        results.append(result)

        # Write the result to a YAML file
        output_file_path = f"/root/my_repo/my_python/parsed_dev_data/{hostname}_parsed_config.yaml"
        with open(output_file_path, 'w') as file:
            yaml.dump(result, file, default_flow_style=False)
        print(f"Configuration has been parsed and saved to {output_file_path}")

    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parse_configs.py /parsed_dev_data/<config_file1> <config_file2> ...")
        sys.exit(1)

    config_file_path_list = sys.argv[1:]
    parsed_data = parse_config_file(config_file_path_list)

    pprint(parsed_data)
