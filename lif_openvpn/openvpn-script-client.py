#!/usr/bin/python3

import os
import re
import sys
sys.path.append('/usr/lib/fpemud-vpn-server')
from fcs_common import FcsCommon


def _addToFakeLeaseFile(filename, ip, hostname):
    if hostname == "":
        hostname = "*"
    with open(filename, "a") as f:
        f.write("1108086503 00:00:00:00:00:00 %s %s 00:00:00:00:00:00\n" % (ip, hostname))


def _removeFromFakeLeaseFile(filename, ip):
    lineList = []
    with open(filename, "r") as f:
        lineList = f.read().rstrip("\n").split("\n")

    pattern = "[0-9]+ +([0-9a-f:]+) +([0-9\.]+) +(\\S+) +\\S+"
    lineList2 = []
    for line in lineList:
        m = re.match(pattern, line)
        if ip != m.group(2):
            lineList2.append(line)

    with open(filename, "w") as f:
        for line in lineList2:
            f.write(line + "\n")


tmpDir = sys.argv[1]
apiPort = int(sys.argv[2])
scriptType = os.environ['script_type']
ip = os.environ['ifconfig_pool_remote_ip']
hostname = os.environ['username']
vpnId = int(ip.split(".")[2])
fakeLeasesFile = os.path.join(tmpDir, "vpn-%d-openvpn.fake.leases" % (vpnId))

if scriptType == "client-connect":
    _addToFakeLeaseFile(fakeLeasesFile, ip, hostname)
    FcsCommon.externalAddClient(apiPort, ip, hostname, False)
elif scriptType == "client-disconnect":
    FcsCommon.externalRemoveClient(apiPort, ip, False)
    _removeFromFakeLeaseFile(fakeLeasesFile, ip)
else:
    assert False
