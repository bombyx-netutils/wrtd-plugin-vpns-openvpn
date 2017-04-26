#!/usr/bin/python3

import os
import sys
import json
import socket


serverPort = sys.argv[1]

data = dict()
if os.environ['script_type'] == "client-connect":
    data["cmd"] = "add"
elif os.environ['script_type'] == "client-disconnect":
    data["cmd"] = "del"
else:
    assert False
data["ip"] = os.environ['ifconfig_pool_remote_ip']
data["hostname"] = os.environ['username']

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(("127.0.0.1", serverPort), json.dumps(data))
sock.close()
