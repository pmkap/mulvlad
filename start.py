#!/usr/bin/env python3

import mulvlad

privkey, pubkey = mulvlad.genkeypair()
server_ip, server_pubkey = mulvlad.pick_relay()
client_ip = mulvlad.replace_key(pubkey)

mulvlad.create_interface()
mulvlad.setup_interface(
        privkey=privkey,
        server_pubkey=server_pubkey,
        client_ip=client_ip,
        server_ip=server_ip)
