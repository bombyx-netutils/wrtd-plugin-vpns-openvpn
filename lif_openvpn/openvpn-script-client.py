#!/usr/bin/python3

import os
import re
import sys


tmpDir = sys.argv[1]
apiPort = int(sys.argv[2])
scriptType = os.environ['script_type']
ip = os.environ['ifconfig_pool_remote_ip']
hostname = os.environ['username']

if scriptType == "client-connect":
    FcsCommon.externalAddClient(apiPort, ip, hostname, False)
elif scriptType == "client-disconnect":
    FcsCommon.externalRemoveClient(apiPort, ip, False)
else:
    assert False
