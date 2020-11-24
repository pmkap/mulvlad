# mulvlad
**Unofficial** Mullvad.net client written in Python. Similiar to wg-quick, but with some additions to handle keys and relays via the Mullvad.net API.

## Dependencies
* requests
* pyroute2

## Usage
Place a `config.py` file in `/usr/local/etc/mulvlad/` looking the following:
```python
ACCOUNT = '9999999999999999'
IFNAME = 'wg1-mull'
ALLOWED_IPS = ['10.64.0.1/32']
```
As this file contains the Mullvad.net account number, it's maybe a good idea to make this file `chmod 700` with root as its owner.

Set everything up:
`mulvlad.py start`

Rotate keys:
`mulvlad.py rotate`

Or use the Systemd Units and Timer.

## TODO
* handle overriding default route
