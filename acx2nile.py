#!/usr/bin/env python3
import getpass
import csv
import re
from netmiko import ConnectHandler
import pandas as pd

# ---- Parsers ----

def parse_mac_table(output):
    entries = []
    for line in output.splitlines():
        m = re.match(r'^\s*(\d+)\s+([0-9a-f:.]+)\s+(\S+)', line, re.I)
        if m:
            entries.append({'vlan': m.group(1), 'mac': m.group(2), 'port': m.group(3)})
    return entries


def parse_poe(output):
    poe = {}
    for line in output.splitlines():
        m = re.match(r'^(\d+/\d+/\d+)\s+\S+\s+delivers\s+([\d.]+)Watts', line)
        if m:
            poe[m.group(1)] = float(m.group(2))
    return poe


def parse_int_status(output):
    stats = {}
    for line in output.splitlines():
        cols = line.split()
        if len(cols) >= 4 and re.match(r'\d+/\d+/\d+', cols[0]):
            port, speed, duplex = cols[0], cols[2], cols[3]
            stats[port] = (speed, duplex)
    return stats


def parse_lldp_detail(output):
    neighbors, current = [], {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith('Local Port id:'):
            if current:
                neighbors.append(current)
                current = {}
            current['local_port'] = line.split(':',1)[1].strip()
        elif line.startswith('Chassis id:'):
            current['neighbor_id'] = line.split(':',1)[1].strip()
        elif line.startswith('Port id:'):
            current['neighbor_port'] = line.split(':',1)[1].strip()
        elif line.startswith('Management address:'):
            current['neighbor_ip'] = line.split(':',1)[1].strip()
    if current:
        neighbors.append(current)
    return neighbors


def parse_protocols(output):
    protos = []
    for proto in ['spanning-tree', 'lacp', 'lldp', 'rstp', 'ospf', 'bgp', 'vrf']:
        if proto in output.lower():
            protos.append(proto)
    return protos


def parse_dhcp_helpers(cfg):
    dhcp = {}
    current_intf = None
    for line in cfg.splitlines():
        m = re.match(r'interface\s+(\S+)', line)
        if m:
            current_intf = m.group(1)
            dhcp[current_intf] = []
        elif current_intf and 'ip helper-address' in line:
            addrs = re.findall(r'ip helper-address\s+(\S+)', line)
            dhcp[current_intf].extend(addrs)
    return dhcp


def parse_auth(cfg):
    auth = {}
    current_intf = None
    for line in cfg.splitlines():
        m = re.match(r'interface\s+(\S+)', line)
        if m:
            current_intf = m.group(1)
            auth[current_intf] = []
        elif current_intf and ('authentication port-access' in line.lower() or 'dot1x' in line.lower()):
            auth[current_intf].append(line.strip())
    return auth


def parse_radius_servers(cfg):
    # captures IPs of configured RADIUS servers
    servers = re.findall(r'radius-server host\s+(\S+)', cfg)
    return list(set(servers))

# ---- Collection Logic ----

def collect_from_switch(host, username, password):
    conn = ConnectHandler(device_type='aruba_os', host=host,
                          username=username, password=password, fast_cli=False)
    sw = {'hostname': host}

    # Device info
    ver = conn.send_command('show version')
    m = re.search(r'Model:\s+(\S+)', ver)
    sw['model'] = m.group(1) if m else ''
    m = re.search(r'Software Version:\s+(.+)', ver)
    sw['os'] = m.group(1).strip() if m else ''

    # Tables and stats
    macs = parse_mac_table(conn.send_command('show mac-address-table'))
    poe = parse_poe(conn.send_command('show poe'))
    intf_stats = parse_int_status(conn.send_command('show interfaces status'))

    # LLDP discovery
    lldp = parse_lldp_detail(conn.send_command('show lldp neighbors detail'))

    # Running config and protocol summary
    cfg = conn.send_command('show running-config')
    sw['protocols'] = parse_protocols(cfg)
    sw['architecture_guess'] = 'leaf' if len(lldp) > 4 else 'spine' if len(lldp) <= 4 else 'unknown'

    # DHCP helpers, auth, and RADIUS
    dhcp_helpers = parse_dhcp_helpers(cfg)
    auth_ifaces = parse_auth(cfg)
    radius_servers = parse_radius_servers(cfg)

    sw['total_poe_W'] = sum(poe.values())
    sw['radius_servers'] = ','.join(radius_servers)

    # Build host records with per-port info
    host_records = []
    for entry in macs:
        port = entry['port']
        rec = {
            'switch': host,
            'mac': entry['mac'],
            'vlan': entry['vlan'],
            'port': port,
            'poe_W': poe.get(port, 0.0),
            'speed': intf_stats.get(port, ('n/a','n/a'))[0],
            'duplex': intf_stats.get(port, ('n/a','n/a'))[1],
            'lldp_neighbors': ','.join(n['neighbor_id'] for n in lldp if n.get('local_port') == port),
            'dhcp_helpers': ','.join(dhcp_helpers.get(port, [])),
            'auth_config': ';'.join(auth_ifaces.get(port, [])),
        }
        host_records.append(rec)

    conn.disconnect()
    return sw, host_records, lldp

# ---- Topology Discovery ----

def main():
    seed = input('Enter seed switch IP address: ').strip()
    username = input('Username: ').strip()
    password = getpass.getpass('Password: ')

    discovered, to_discover = set(), [seed]
    summary_list, all_hosts, topology = [], [], {}

    while to_discover:
        ip = to_discover.pop(0)
        if ip in discovered:
            continue
        discovered.add(ip)
        print(f'Collecting from {ip}...')
        sw, hosts, neighbors = collect_from_switch(ip, username, password)
        summary_list.append(sw)
        all_hosts.extend(hosts)
        topology[ip] = []
        for n in neighbors:
            nbr_ip = n.get('neighbor_ip')
            if nbr_ip:
                topology[ip].append(nbr_ip)
                if nbr_ip not in discovered and nbr_ip not in to_discover:
                    to_discover.append(nbr_ip)

    # Export CSVs
    pd.DataFrame(all_hosts).to_csv('hosts.csv', index=False)
    pd.DataFrame(summary_list).to_csv('switch_summary.csv', index=False)
    with open('topology.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['source', 'target'])
        for src, targets in topology.items():
            for tgt in targets:
                writer.writerow([src, tgt])

    # Export Graphviz DOT
    with open('topology.dot', 'w') as f:
        f.write('graph topology {\n')
        for src, targets in topology.items():
            for tgt in targets:
                f.write(f'    "{src}" -- "{tgt}";\n')
        f.write('}\n')

    print('Discovery complete. CSVs and DOT file generated.')

if __name__ == '__main__':
    main()
