#!/usr/bin/python

import secrets
import requests
import sys
import json

URI_START=secrets.uri_start
STAGE="dev"
URL_BASE="https://%s.execute-api.us-east-1.amazonaws.com/%s"%(URI_START, STAGE)

class Cst:
    def __init__(self, username, password):
        r = requests.post(URL_BASE + "/users/%s/tokens"%username, data={"password": password})
        self.token = r.json()["token"]

    def post(self, path, data):
        h = {"Authorization":  "Bearer %s" % self.token}
        r = requests.post(URL_BASE + path, json=data, headers=h)
        return r.json()

    def get(self, path):
        headers = {"Authorization": "Bearer " + self.token}
        r = requests.get(url=(URL_BASE + path), headers=headers)
        return r.json()

def get_port_forwards(c):
    rules = c.get('/network/iptables/rules')
    possible_forwards = {}
    for rule in rules['tables']['nat']['rules']:
        if 'destinationPort' in rule and 'destinationIp' in rule:
            possible_forwards[rule['destinationPort']] =  rule['destinationIp']
    port_forwards = {}
    for rule in rules['tables']['filter']['rules']:
        if 'destinationPort' in rule and 'chain' in rule:
            if rule['destinationPort'] in possible_forwards and rule['chain'] == 'FORWARD' and rule['jump'] == "ACCEPT":
                port_forwards[rule['destinationPort']] = possible_forwards[rule['destinationPort']]
    return port_forwards

def add_port_forward(c, ip, int_port, ext_port):
    rules = c.get('/network/iptables/rules')

    port_forwards = get_port_forwards(c)

    # First add the filter rule
    # Find the last index of any existing port forwarding rules
    findex = 10
    for i, rule in enumerate(rules['tables']['filter']['rules']):
        if 'destinationPort' in rule and rule['destinationPort'] in port_forwards:
            findex = i

    # TODO: autodetect interfaces and vlan

    newfilterrule = {
        "inInterface": "enp2s0",
        "protocol": "tcp",
        "chain": "FORWARD",
        "jump": "ACCEPT",
        "outInterface": "enp3s0.2048",
        "destinationPort": str(int_port),
        "match": "tcp"
    }

    rules['tables']['filter']['rules'].insert(findex + 1, newfilterrule)

    nindex = 1
    for i, rule in enumerate(rules['tables']['nat']['rules']):
        if 'destinationPort' in rule and rule['destinationPort'] in port_forwards:
            nindex = i

    newnatrule = {
          "inInterface": "enp2s0",
          "protocol": "tcp",
          "chain": "PREROUTING",
          "destinationIp": "%s:%d" % (ip, int_port),
          "jump": "DNAT",
          "destinationPort": str(ext_port),
        "match": "tcp"
    }

    rules['tables']['nat']['rules'].insert(nindex + 1, newnatrule)

    with open('debugout.txt','w') as f:
        f.write(json.dumps(rules))
    r = c.post('/network/iptables/rules', rules)
    return r



def main():
    username, password = (secrets.un, secrets.pw)
    c = Cst(username, password)
    #print(json.dumps(add_port_forward(c, '10.204.80.142', 22, 2222)))
    print(json.dumps(c.get('/network/iptables/rules')))
    #print(json.dumps(get_port_forwards(c)))

if __name__ == "__main__":
    main()
