#!/usr/bin/python3

import os
import sys
sys.path.append('/usr/lib/fpemud-vpn-server')
from fcs_common import FcsCommon

scriptType = sys.argv[1]
ip = sys.argv[3]
apiPort = 2220          # fixme
hostname = os.environ.get("DNSMASQ_SUPPLIED_HOSTNAME", "")

if scriptType == "add":
    FcsCommon.externalAddClient(apiPort, ip, hostname)
elif scriptType == "old":
    pass
elif scriptType == "del":
    FcsCommon.externalRemoveClient(apiPort, ip)
else:
    assert False
