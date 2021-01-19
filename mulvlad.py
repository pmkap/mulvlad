#!/usr/bin/env python3

import argparse
import importlib.util
import os
import random
import subprocess
import sys

from pyroute2 import IPRoute, WireGuard
import requests

if os.geteuid():
    sys.exit('This should be run with root privileges.')

# import global config file
spec = importlib.util.spec_from_file_location('config', '/usr/local/etc/mulvlad/config.py')
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)

def main():
    # CLI Interface
    parser = argparse.ArgumentParser()
    parser.add_argument('cmd', choices=['start', 'stop', 'rotate'])
    args = parser.parse_args()

    if args.cmd == 'start':
        start()
    elif args.cmd == 'stop':
        stop()
    elif args.cmd == 'rotate':
        rotate()


def pick_relay(locations=config.LOCATIONS):
    r = requests.get('https://api.mullvad.net/app/v1/relays')
    relays =  r.json()['wireguard']['relays']
    candidates = []
    for r in relays:
        if r['active']:
            for location in locations:
                if location in r['location']:
                    candidates.append(r)
                    break

    if not config.PREFER_OWNED:
        picked = random.choice(candidates)
    else:
        owned = []
        rented = []
        for r in candidates:
            if r['owned']:
                owned.append(r)
            else:
                rented.append(r)
        picked = random.choice(owned) if owned else random.choice(rented)

    return picked['ipv4_addr_in'], picked['public_key']


def replace_key(new):
    """Replace public key on the Mullvad servers via the API.
    Whenever a key is pushed to Mullvad.net, remember the key also in /var/local/mulvlad/pubkey so that we know which key to replace on the mullvad servers the next time."""
    try:
        with open('/var/local/mulvlad/pubkey', 'r') as file:
            old = file.read().strip()
    except FileNotFoundError:
        # if there is no remembered key just use anything for the API call. Apparently it doesn't matter.
        old='H9TjgrQ2DIu5JE3KdgEelDBeKf1MBwruJu6Ia86ZHxs='

    r = requests.post(
            'https://api.mullvad.net/app/v1/replace-wireguard-key',
            headers={'Authorization': f'Token {config.ACCOUNT}'},
            json={'old': old, 'new': new})

    if 'error' in r.json():
        raise RuntimeError(str(r.json()))

    else:
        if not os.path.isdir('/var/local/mulvlad/'):
            os.makedirs('/var/local/mulvlad/')
        with open('/var/local/mulvlad/pubkey', 'w') as file:
            file.write(new)

        return r.json()['ipv4_address']


def create_interface():
    ip = IPRoute()
    interfaces = [i[0].dump()['attrs'][0][1] for i in ip.get_links()]
    if config.IFNAME not in interfaces:
        ip.link('add', ifname=config.IFNAME, kind='wireguard')
        idx = ip.link_lookup(ifname=config.IFNAME)[0]
        ip.link('set', index=idx, state='up')
    else:
        # interface already exists, delete and recreate
        idx = ip.link_lookup(ifname=config.IFNAME)[0]
        ip.link('del', index=idx)
        ip.link('add', ifname=config.IFNAME, kind='wireguard')
        idx = ip.link_lookup(ifname=config.IFNAME)[0]
        ip.link('set', index=idx, state='up')


def delete_interface():
    ip = IPRoute()
    interfaces = [i[0].dump()['attrs'][0][1] for i in ip.get_links()]
    if config.IFNAME in interfaces:
        idx = ip.link_lookup(ifname=config.IFNAME)[0]
        ip.link('del', index=idx)
    if '0.0.0.0/0' in config.ALLOWED_IPS:
        # TODO: do this with pyroute2 instead of subprocess
        rules = ['table main suppress_prefixlength 0', 'not fwmark 51820 table 51820']
        for rule in rules:
            subprocess.run(f'ip rule del {rule}'.split())


def add_addr(client_ip):
    ip = IPRoute()
    idx = ip.link_lookup(ifname=config.IFNAME)[0]

    address, prefixlen = client_ip.split('/')
    prefixlen = int(prefixlen)

    ip.flush_addr(index=idx)
    ip.addr('add', index=idx, address=address, prefixlen=prefixlen)


def wg_set(**kwargs):
    wg = WireGuard()
    
    interface_kwargs = ['private_key', 'fwmark', 'listen_port']
    peer_kwargs = ['public_key', 'remove', 'preshared_key', 'endpoint_addr', 'endpoint_port', 'persistent_keepalive', 'allowed_ips']
    interface = {}
    peer = {}
    for arg, value in kwargs.items():
        if arg in interface_kwargs:
            interface[arg] = value
        elif arg in peer_kwargs:
            peer[arg] = value

    if 'endpoint_addr' in peer and 'endpoint_port' not in peer:
        peer['endpoint_port'] = 51820
    
    if peer:
        wg.set(config.IFNAME, **interface, peer=peer)
    else:
        wg.set(config.IFNAME, **interface)


def add_routes():
    for i in config.ALLOWED_IPS:
        if i == '0.0.0.0/0':
            add_default()
        else:
            add_route(i)


def add_route(route, table=None):
    ip = IPRoute()
    idx = ip.link_lookup(ifname=config.IFNAME)[0]
    ip.route('add', dst=route, oif=idx, table=table)


def add_default():
    ip = IPRoute()
    wg = WireGuard()

    wg_set(fwmark=51820)
    add_route('0.0.0.0/0', table=51820)

    # TODO: implement these two in pyroute2
    subprocess.run('ip rule add not fwmark 51820 table 51820'.split(), check=True)
    subprocess.run('ip rule add table main suppress_prefixlength 0'.split(), check=True)


def genkeypair():
    p = subprocess.run("wg genkey".split(), stdout=subprocess.PIPE)
    privkey = p.stdout.strip()
    p = subprocess.run("wg pubkey".split(), input=privkey, stdout=subprocess.PIPE)
    pubkey = p.stdout.strip()
    
    return privkey.decode(), pubkey.decode()


def start():
    privkey, pubkey = genkeypair()
    server_ip, server_pubkey = pick_relay()
    client_ip = replace_key(pubkey)
    create_interface()
    add_addr(client_ip)
    wg_set(private_key=privkey, public_key=server_pubkey, endpoint_addr=server_ip, allowed_ips=config.ALLOWED_IPS)
    add_routes()


def stop():
    delete_interface()


def rotate():
    privkey, pubkey = genkeypair()
    address = replace_key(pubkey)
    add_addr(address)
    wg_set(private_key=privkey)
    add_routes()


def switch_relay():
    wg = WireGuard()
    old_server_pubkey = wg.info(config.IFNAME)[0].WGDEVICE_A_PEERS['value'][0].WGPEER_A_PUBLIC_KEY['value'].decode()
    wg_set(remove=True, public_key=old_server_pubkey)

    server_ip, server_pubkey = pick_relay()
    wg_set(endpoint_addr=server_ip, public_key=server_pubkey, allowed_ips=config.ALLOWED_IPS)


if __name__ == '__main__':
    main()
