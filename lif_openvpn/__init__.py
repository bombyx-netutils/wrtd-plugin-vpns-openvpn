#!/usr/bin/python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-

import os
import socket
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

    def init2(self, instanceName, cfg, tmpDir):
        assert instanceName == ""
        self.cfg = cfg
        self.tmpDir = tmpDir

        self.proto = self.cfg.get("proto", "udp")
        self.port = self.cfg.get("port", 1194)

        self.intfName = "wrt-lif-ovpn"
        self.intfIp = None                  # fixme


        self.serverFile = os.path.join(self.tmpDir, "cmd.socket")
        self.proc = None
        self.bridge = None

    def start(self):
        self._runOpenvpnServer()
        self.bridge = _VirtualBridge(self.tmpDir)

    def stop(self):
        if self.proc is not None:
            self.proc.terminate()
            self.proc.wait()
            self.proc = None

    def get_bridge(self):
        return self.bridge

    def interface_appear(self, bridge, ifname):
        if ifname == "wrt-lif-ovpn":
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

            f.write("proto %s\n" % (self.proto))
            f.write("port %s\n" % (self.port))
            f.write("\n")

            f.write("dev-type tap\n")
            f.write("dev wrt-lif-ovpn\n")
            f.write("keepalive 10 120\n")
            f.write("\n")

            f.write("local %s\n" % ())
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
            f.write("client-connect \"%s/openvpn-script-client.py %s\"\n" % (selfdir, self.serverFile))
            f.write("client-disconnect \"%s/openvpn-script-client.py %s\"\n" % (selfdir, self.serverFile))
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


class _VirtualBridge:

    def __init__(self, tmpDir):
        self.tmpDir = tmpDir
        self.l2DnsPort = None
        self.clientAppearFunc = None
        self.clientChangeFunc = None
        self.clientDisappearFunc = None

        self.brname = "wrt-lif-ovpn"
        self.ip = "192.168.2.1"
        self.mask = "255.255.255.0"
        self.dhcpRange = ("192.168.2.2", "192.168.2.50")

        self.serverFile = os.path.join(self.tmpDir, "cmd.socket")
        self.cmdSock = None
        self.cmdServerThread = None

        self.myhostnameFile = os.path.join(self.tmpDir, "dnsmasq.myhostname")
        self.selfHostFile = os.path.join(self.tmpDir, "dnsmasq.self")
        self.hostsDir = os.path.join(self.tmpDir, "hosts.d")
        self.pidFile = os.path.join(self.tmpDir, "dnsmasq.pid")
        self.dnsmasqProc = NoneserverFile

    def init2(self, l2DnsPort, clientAppearFunc, clientChangeFunc, clientDisappearFunc):
        self.l2DnsPort = l2DnsPort
        self.clientAppearFunc = clientAppearFunc
        self.clientChangeFunc = clientChangeFunc
        self.clientDisappearFunc = clientDisappearFunc
        self._runDnsmasq()
        self._runCmdServer()

    def dispose(self):
        self._stopCmdServer()
        self._stopDnsmasq()

    def get_bridge_id(self):
        return "bridge-" + self.ip

    def get_ip(self):
        return self.ip

    def get_netmask(self):
        return self.mask_VirtualBridge

    def get_subhost_ip_range(self):
        # return (start_ip, ip_number, count)
        assert False

    def on_other_bridge_created(self, id):
        with open(os.path.join(self.hostsDir, id), "w") as f:
            pass

    def on_other_bridge_destroyed(self, id):
        os.unlink(os.path.join(self.hostsDir, id))

    def on_subhost_owner_connected(self, id):
        with open(os.path.join(self.hostsDir, id), "w") as f:
            pass
        
    def on_subhost_owner_disconnected(self, id):
        os.unlink(os.path.join(self.hostsDir, id))

    def on_upstream_connected(self, id):
        with open(os.path.join(self.hostsDir, id), "w") as f:
            pass

    def on_upstream_disconnected(self, id):
        os.unlink(os.path.join(self.hostsDir, id))

    def on_host_appear(self, sourceId, ipDataDict):
        bChanged = False
        fn = os.path.join(self.hostsDir, sourceId)
        with open(fn, "a") as f:
            for ip, data in ipDataDict.items():
                if "hostname" in data:
                    f.write(ip + " " + hostname + "\n")
                    bChanged = True

        if bChanged:
            self.dnsmasqProc.send_signal(signal.SIGHUP)

    def on_host_disappear(self, sourceId, ipList):
        fn = os.path.join(self.hostsDir, sourceId)
        bChanged = False

        lineList = []
        with open(fn, "r") as f:
            lineList = f.read().rstrip("\n").split("\n")

        lineList2 = []
        for line in lineList:
            if ip != line.split(" ")[0]:
                lineList2.append(line)
            else:
                bChanged = True

        if bChanged:
            with open(fn, "w") as f:
                for line in lineList2:
                    f.write(line + "\n")
            self.dnsmasqProc.send_signal(signal.SIGHUP)

    def on_host_refresh(self, sourceId, ipDataDict):
        fn = os.path.join(self.hostsDir, sourceId)

        buf = ""
        with open(fn, "r") as f:
            buf = f.read()
        
        buf2 = ""
        for ip, data in ipDataDict.items():
            if "hostname" in data:
                buf2 += ip + " " + hostname + "\n"

        if buf != buf2:
            with open(fn, "w") as f:
                f.write(buf2)
            self.dnsmasqProc.send_signal(signal.SIGHUP)

    def _runCmdServer(self):
        self.cmdSock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.cmdSock.bind(self.serverFile)

        self.cmdServerThread = _CmdServerThread(self)
        self.cmdServerThread.start()

    def _stopCmdServer(self):
        if self.cmdServerThread is not None:
            self.cmdSock.close()
            self.cmdServerThread.join()
            self.cmdServerThread = None
        else:
            if self.cmdSock is not None:
                self.cmdSock.close()

    def _runDnsmasq(self):
        # myhostname file
        with open(self.myhostnameFile, "w") as f:
            f.write("%s %s\n" % (self.ip, socket.gethostname()))

        # self host file
        with open(self.selfHostFile, "w") as f:
            f.write("")

        # make hosts directory
        os.mkdir(self.hostsDir)

        # generate dnsmasq config file
        buf = ""
        buf += "strict-order\n"
        buf += "bind-interfaces\n"                            # don't listen on 0.0.0.0
        buf += "interface=lo,%s\n" % (self.brname)
        buf += "user=root\n"
        buf += "group=root\n"
        buf += "\n"
        buf += "domain-needed\n"
        buf += "bogus-priv\n"
        buf += "no-hosts\n"
        buf += "server=127.0.0.1#%d\n" % (self.l2DnsPort)
        buf += "addn-hosts=%s\n" % (self.hostsDir)                       # "hostsdir=" only adds record, no deletion, so not usable
        buf += "addn-hosts=%s\n" % (self.myhostnameFile)                 # we use addn-hosts which has no inotify, and we send SIGHUP to dnsmasq when host file changes
        buf += "addn-hosts=%s\n" % (self.selfHostFile)
        buf += "\n"
        cfgf = os.path.join(self.tmpDir, "dnsmasq.conf")
        with open(cfgf, "w") as f:
            f.write(buf)

        # run dnsmasq process
        cmd = "/usr/sbin/dnsmasq"
        cmd += " --keep-in-foreground"
        cmd += " --conf-file=\"%s\"" % (cfgf)
        cmd += " --pid-file=%s" % (self.pidFile)
        self.dnsmasqProc = subprocess.Popen(cmd, shell=True, universal_newlines=True)

    def _stopDnsmasq(self):
        if self.leaseScanTimer is not None:
            GLib.source_remove(self.leaseScanTimer)
            self.leaseScanTimer = None
            self.lastScanRecord = None
        if self.dnsmasqProc is not None:
            self.dnsmasqProc.terminate()
            self.dnsmasqProc.wait()
            self.dnsmasqProc = None
        os.unlink(self.pidFile)
        shutil.rmtree(self.hostsDir)
        os.unlink(self.selfHostFile)
        os.unlink(self.myhostnameFile)


class _CmdServerThread(threading.Thread):

    def __init__(self, pObj):
        threading.Thread.__init__(self)
        self.pObj = pObj

    def run(self):
        while True:
            jsonObj = None
            try:
                buf = self.pObj.cmdSock.recvfrom(4096).decode("utf-8")
                jsonObj = json.loads(buf)
            except socket.error:
                break

            if jsonObj["cmd"] == "add":
                # add to dnsmasq host file
                _Util.addToDnsmasqHostFile(self.pObj.selfHostFile, jsonObj["ip"], jsonObj["hostname"])
                self.pObj.dnsmasqProc.send_signal(signal.SIGHUP)
                # notify lan manager
                data = dict()
                data[jsonObj["ip"]] = dict()
                data[jsonObj["ip"]]["hostname"] = jsonObj["hostname"]
                _Util.idleInvoke(self.pObj.clientAppearFunc, self.pObj.get_bridge_id(), data)
            elif jsonObj["cmd"] == "del":
                # remove from dnsmasq host file
                _Util.removeFromDnsmasqHostFile(self.pObj.selfHostFile, jsonObj["ip"])
                self.pObj.dnsmasqProc.send_signal(signal.SIGHUP)
                # notify lan manager
                data = [jsonObj["ip"]]
                _Util.idleInvoke(self.pObj.clientDisappearFunc, self.pObj.get_bridge_id(), data)
            else:
                assert False


class _Util:

    @staticmethod
    def addToDnsmasqHostFile(filename, ip, hostname):
        with open(filename, "a") as f:
            f.write(ip + " " + hostname + "\n")

    @staticmethod
    def removeFromDnsmasqHostFile(filename, ip):
        lineList = []
        with open(filename, "r") as f:
            lineList = f.read().rstrip("\n").split("\n")

        lineList2 = []
        for line in lineList:
            if ip != line.split(" ")[0]:
                lineList2.append(line)

        with open(filename, "w") as f:
            for line in lineList2:
                f.write(line + "\n")

    @staticmethod
    def idleInvoke(func, *args):
        def _idleCallback(func, *args):
            func(*args)
            return False
        GLib.idle_add(_idleCallback, func, *args)
