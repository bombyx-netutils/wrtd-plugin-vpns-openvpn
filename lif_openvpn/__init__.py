#!/usr/bin/python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-

import os
import pwd
import grp
import socket
import struct
import fcntl
import subprocess


def get_plugin_list():
    return [
        "openvpn",
    ]


def get_plugin(name):
    if name == "openvpn":
        return _PluginObject()
    else:
        assert False


class _PluginObject:

    def init2(self, instanceName, cfg, brname, tmpDir):
        assert instanceName == ""
        self.cfg = cfg
        self.brname = brname
        self.tmpDir = tmpDir
        self.apiPort = None                         # fixme
        self.proto = self.cfg.get("proto", "udp")
        self.port = self.cfg.get("port", 1194)

        self.n2nSupernodeProc = None
        self.proc = None

    def start(self):
        self._runOpenvpnServer()

    def stop(self):
        if self.proc is not None:
            self.proc.terminate()
            self.proc.wait()
            self.proc = None

    def interface_appear(self, ifname):
        if ifname == "wrt-lif-ovpn":
            _Util.addInterfaceToBridge(self.brname, ifname)
            return True
        else:
            return False

    def interface_disappear(self, ifname):
        pass

    def _runOpenvpnServer(self, i):
        selfdir = os.path.dirname(os.path.realpath(__file__))
        cfgf = os.path.join(self.tmpDir, "config.ovpn")
        mngf = os.path.join(self.tmpDir, "management.socket")

        # generate openvpn config file
        # notes:
        # 1. no comp-lzo. it seems that "push comp-lzo" leads to errors, and I don't think compression saves much
        with open(cfgf, "w") as f:
            f.write("tmp-dir %s\n" % (self.tmpDir))

            f.write("proto %s\n" % (self.proto)
            f.write("port %s\n" % (self.port)
            f.write("\n")

            f.write("dev-type tap\n")
            f.write("dev wrt-lif-ovpn\n")
            f.write("keepalive 10 120\n")
            f.write("\n")

            f.write("local %s\n" % (FcsUtil.getInterfaceIp(self.oif)))
            f.write("server 10.8.%d.0 %s\n" % (i, self.netmask))
            f.write("topology subnet\n")
            f.write("client-to-client\n")
            f.write("\n")

            f.write("duplicate-cn\n")
            # f.write("ns-cert-type client\n")
            f.write("verify-x509-name %s name\n" % (self.clientCertCn))
            f.write("\n")

            f.write("script-security 2\n")
            f.write("auth-user-pass-verify \"%s/openvpn-script-auth.sh\" via-env\n" % (selfdir))
            f.write("client-connect \"%s/openvpn-script-client.py %s %d\"\n" % (selfdir, self.tmpDir, self.apiPort))
            f.write("client-disconnect \"%s/openvpn-script-client.py %s %d\"\n" % (selfdir, self.tmpDir, self.apiPort))
            f.write("\n")

            f.write("push \"redirect-gateway\"\n")
            f.write("\n")

            # f.write("push \"dhcp-option DNS 10.8.%d.1\"\n" % (i))
            # f.write("\n")

            f.write("ca %s\n" % (self.caCertFile))
            f.write("cert %s\n" % (self.servCertFile))
            f.write("key %s\n" % (self.servKeyFile))
            f.write("dh %s\n" % (self.servDhFile))
            f.write("\n")

            f.write("user nobody\n")
            f.write("group nobody\n")
            f.write("\n")

            f.write("persist-key\n")
            f.write("persist-tun\n")
            f.write("\n")

            f.write("management %s unix\n" % (mngf))
            # f.write("management-client-user ?\n")
            # f.write("management-client-group ?\n")
            f.write("\n")

            f.write("status %s/status.log\n" % (self.tmpDir))
            f.write("status-version 2\n")
            f.write("verb 4\n")

        # run openvpn process
        cmd = ""
        cmd += "/usr/sbin/openvpn "
        cmd += "--config %s " % (cfgf)
        cmd += "--writepid %s/openvpn.pid " % (self.tmpDir)
        cmd += "> %s/openvpn.out 2>&1" % (self.tmpDir)
        self.proc = subprocess.Popen(cmd, shell=True, universal_newlines=True)


class _Util:

    @staticmethod
    def addInterfaceToBridge(brname, ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            ifreq = struct.pack("16si", ifname, 0)
            ret = fcntl.ioctl(s.fileno(), 0x8933, ifreq)            # SIOCGIFINDEX
            ifindex = struct.unpack("16si", ret)[1]

            ifreq = struct.pack("16si", brname, ifindex)
            fcntl.ioctl(s.fileno(), 0x89a2, ifreq)                  # SIOCBRADDIF
        finally:
            s.close()
