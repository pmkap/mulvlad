#!/usr/bin/env python3
import importlib.util
import random
import subprocess

import requests
from pyroute2 import IPRoute, WireGuard

# import global config file
spec = importlib.util.spec_from_file_location('config', '/usr/local/etc/mulvlad/config.py')
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)


def pick_relay():
    r = requests.get('https://api.mullvad.net/app/v1/relays')
    relays =  r.json()['wireguard']['relays']

    relays = [r for r in relays if r['active'] and 'de-' in r['location']]

    owned = [r for r in relays if r['owned']]
    rented = [r for r in relays if not r['owned']]
    
    picked = random.choice(owned) if owned else random.choice(rented)
    return picked['ipv4_addr_in'], picked['public_key']


def replace_key(new):
    """Whenever a key is pushed to Mullvad.net, remember the key also in /var/local/mulvlad/pubkey so that we know which key to replace on the mullvad servers the next time."""
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
        with open('/var/local/mulvlad/pubkey', 'w') as file:
            file.write(new)
        return r.json()['ipv4_address']


def create_interface():
    ip = IPRoute()
    interfaces = [i[0].dump()['attrs'][0][1] for i in ip.get_links()]
    if config.IFNAME not in interfaces:
        ip.link('add', ifname=config.IFNAME, kind='wireguard')
    else:
        # interface already exists, delete and recreate
        idx = ip.link_lookup(ifname=config.IFNAME)[0]
        ip.link('del', index=idx)
        ip.link('add', ifname=config.IFNAME, kind='wireguard')


def setup_interface(*, privkey, server_pubkey, client_ip, server_ip):
    ip = IPRoute()
    wg = WireGuard()
    
    idx = ip.link_lookup(ifname=config.IFNAME)[0]

    ip.link('set', index=idx, state='down')

    # flush and add address
    address, prefixlen = client_ip.split('/')
    prefixlen = int(prefixlen)
    ip.flush_addr(index=idx)
    ip.addr('add', index=idx, address=address, prefixlen=prefixlen)
    
    # wg set
    peer = {'public_key': server_pubkey,
            'endpoint_addr': server_ip,
            'endpoint_port': 51820,
            'allowed_ips': ['0.0.0.0/0']}
    wg.set(config.IFNAME, private_key=privkey, peer=peer)
    
    ip.link('set', index=idx, state='up')


def genkeypair():
    p = subprocess.run("wg genkey".split(), capture_output=True)
    privkey = p.stdout.strip()
    p = subprocess.run("wg pubkey".split(), input=privkey, capture_output=True)
    pubkey = p.stdout.strip()
    
    return privkey.decode(), pubkey.decode()
