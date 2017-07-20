#!/usr/bin/python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-

import os
import json
import time
import socket
import random
import signal
import shutil
import logging
import netifaces
import ipaddress
import subprocess
from collections import OrderedDict
from OpenSSL import crypto
from gi.repository import GLib


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

    def init2(self, instanceName, cfg, tmpDir, varDir, bridgePrefix, l2DnsPort, clientAddFunc, clientChangeFunc, clientRemoveFunc, firewallAllowFunc):
        self.instanceName = instanceName
        self.cfg = cfg
        self.tmpDir = tmpDir
        self.varDir = varDir
        if self.instanceName == "":
            self.logger = logging.getLogger(self.__module__ + "." + self.__class__.__name__)
        else:
            self.logger = logging.getLogger(self.__module__ + "." + self.__class__.__name__ + "." + self.instanceName)

        self.proto = self.cfg.get("proto", "udp")
        self.port = self.cfg.get("port", 1194)

        self.bridge = _VirtualBridge(self, bridgePrefix, l2DnsPort, clientAddFunc, clientRemoveFunc, firewallAllowFunc)

        self.clientCertCn = "wrtd-openvpn-client"
        self.keySize = 1024
        self.caCertFile = os.path.join(self.varDir, "ca-cert.pem")
        self.caKeyFile = os.path.join(self.varDir, "ca-privkey.pem")
        self.servCertFile = os.path.join(self.varDir, "server-cert.pem")
        self.servKeyFile = os.path.join(self.varDir, "server-privkey.pem")
        self.servDhFile = os.path.join(self.varDir, "dh.pem")

        self.serverFile = os.path.join(self.tmpDir, "cmd.socket")

    def start(self):
        if not os.path.exists(self.caCertFile) or not os.path.exists(self.caKeyFile):
            caCert, caKey = _Util.genSelfSignedCertAndKey("wrtd-openvpn-ca", self.keySize)
            _Util.dumpCertAndKey(caCert, caKey, self.caCertFile, self.caKeyFile)
            if os.path.exists(self.servCertFile):
                os.unlink(self.servCertFile)
            if os.path.exists(self.servKeyFile):
                os.unlink(self.servKeyFile)
            if os.path.exists(self.servDhFile):
                os.unlink(self.servDhFile)
        else:
            caCert, caKey = _Util.loadCertAndKey(self.caCertFile, self.caKeyFile)

        if not os.path.exists(self.servCertFile) or not os.path.exists(self.servKeyFile) or not os.path.exists(self.servDhFile):
            cert, k = _Util.genCertAndKey(caCert, caKey, "wrtd-openvpn", self.keySize)
            _Util.dumpCertAndKey(cert, k, self.servCertFile, self.servKeyFile)
            _Util.genDh(self.keySize, self.servDhFile)

        self.bridge._runOpenvpnServer()
        while self.bridge.brname not in netifaces.interfaces():
            time.sleep(1.0)

        self.bridge._runDnsmasq()
        self.bridge._runCmdServer()

    def stop(self):
        self.bridge._stopCmdServer()
        self.bridge._stopDnsmasq()
        self.bridge._stopOpenvpnServer()

    def get_bridge(self):
        assert self.bridge.openvpnProc is not None
        return self.bridge

    def generate_client_script(self, ip, ostype):
        # get CA certificate and private key
        caCert, caKey = _Util.loadCertAndKey(self.caCertFile, self.caKeyFile)

        # generate certificate and private key
        cert, k = _Util.genCertAndKey(caCert, caKey, self.clientCertCn, self.keySize)

        # generate client script
        caStr = crypto.dump_certificate(crypto.FILETYPE_PEM, caCert).decode("ascii")
        certStr = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("ascii")
        keyStr = crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("ascii")
        if ostype == "linux":
            return self.__createLinuxClientScript(ip, caStr, certStr, keyStr)
        elif ostype == "win32":
            return self.__createWin32ClientScript(ip, caStr, certStr, keyStr)
        else:
            assert False

    def __createLinuxClientScript(self, ip, caStr, certStr, keyStr):
        selfdir = os.path.dirname(os.path.realpath(__file__))

        buf = ""
        with open(os.path.join(selfdir, "client-script-linux.sh.in")) as f:
            buf = f.read()

        buf = buf.replace("@instance@", self.instanceName)
        buf = buf.replace("@hostname@", ip)
        buf = buf.replace("@ca_cert@", caStr)
        buf = buf.replace("@client_cert@", certStr)
        buf = buf.replace("@client_key@", keyStr)
        buf = buf.replace("@proto@", self.proto)
        buf = buf.replace("@port@", str(self.port))

        tdir = os.path.join(self.tmpDir, "repo")
        try:
            _Util.gitClone("https://github.com/masterkorp/openvpn-update-resolv-conf", tdir, shallow=True, quiet=True)
            with open(os.path.join(tdir, "update-resolv-conf.sh"), "r") as f:
                fstr = f.read().replace("'", "'\\''")
                buf = buf.replace("@update_resolv_conf_sh@", fstr)
        finally:
            if os.path.exists(tdir):
                shutil.rmtree(tdir)

        tdir = os.path.join(self.tmpDir, "repo")
        try:
            _Util.gitClone("https://github.com/jonathanio/update-systemd-resolved", tdir, shallow=True, quiet=True)
            with open(os.path.join(tdir, "update-systemd-resolved"), "r") as f:
                fstr = f.read().replace("'", "'\\''")
                buf = buf.replace("@update_systemd_resolved_sh@", fstr)
        finally:
            if os.path.exists(tdir):
                shutil.rmtree(tdir)

        return ("client-script.sh", buf)

    def __createWin32ClientScript(self, ip, caStr, certStr, keyStr, entryInfoList):
        assert False        # lack of mantainence

        selfdir = os.path.dirname(os.path.realpath(__file__))

        buf = ""
        with open(os.path.join(selfdir, "client-script-win32.vbs.in")) as f:
            buf = f.read()

        buf = buf.replace("@instance@", self.instanceName)
        buf = buf.replace("@hostname@", "fpemud.ddns.net")          # fixme

        s = "CA_CERT = \"\"\n"
        for line in caStr.split("\n"):
            s += "CA_CERT = CA_CERT & \"%s\" & vbCrLf\n" % (line)
        buf = buf.replace("@ca_cert@", s)

        s = "CERT = \"\"\n"
        for line in certStr.split("\n"):
            s += "CERT = CERT & \"%s\" & vbCrLf\n" % (line)
        buf = buf.replace("@client_cert@", s)

        s = "KEY = \"\"\n"
        for line in keyStr.split("\n"):
            s += "KEY = KEY & \"%s\" & vbCrLf\n" % (line)
        buf = buf.replace("@client_key@", s)

        s = "ReDim ENTRY_NAME_A(%d)\n" % (len(entryInfoList))
        for i in range(0, len(entryInfoList)):
            s += "ENTRY_NAME_A(%d) = \"%s\"\n" % (i, entryInfoList[i][0])
        buf = buf.replace("@entry_name_a@", s)

        s = "ReDim ENTRY_VTYPE_A(%d)\n" % (len(entryInfoList))
        for i in range(0, len(entryInfoList)):
            s += "ENTRY_VTYPE_A(%d) = \"%s\"\n" % (i, entryInfoList[i][1])
        buf = buf.replace("@entry_vtype_a@", s)

        s = "ReDim ENTRY_PROTO_A(%d)\n" % (len(entryInfoList))
        for i in range(0, len(entryInfoList)):
            s += "ENTRY_PROTO_A(%d) = \"%s\"\n" % (i, entryInfoList[i][2])
        buf = buf.replace("@entry_proto_a@", s)

        s = "ReDim ENTRY_PORT_A(%d)\n" % (len(entryInfoList))
        for i in range(0, len(entryInfoList)):
            s += "ENTRY_PORT_A(%d) = \"%s\"\n" % (i, entryInfoList[i][3])
        buf = buf.replace("@entry_port_a@", s)

        return ("client-script.vbs", buf)


class _VirtualBridge:

    def __init__(self, pObj, prefix, l2dns_port, clientAddFunc, clientRemoveFunc, firewallAllowFunc):
        assert prefix[1] == "255.255.255.0"

        self.pObj = pObj
        self.l2DnsPort = l2dns_port
        self.clientAddFunc = clientAddFunc
        self.clientRemoveFunc = clientRemoveFunc
        self.firewallAllowFunc = firewallAllowFunc

        if self.pObj.instanceName == "":
            self.brname = "wrtd-openvpn"
        else:
            self.brname = "wrtd-openvpn-" + self.pObj.instanceName
            if len(self.brname) >= 16:               # IFNAMESIZ
                self.brname = self.brname[:15]
        self.brnetwork = ipaddress.IPv4Network(prefix[0] + "/" + prefix[1])

        self.brip = ipaddress.IPv4Address(prefix[0]) + 1
        self.dhcpRange = (self.brip + 1, self.brip + 49)

        self.openvpnProc = None

        self.myhostnameFile = os.path.join(self.pObj.tmpDir, "dnsmasq.myhostname")
        self.selfHostFile = os.path.join(self.pObj.tmpDir, "dnsmasq.self")
        self.hostsDir = os.path.join(self.pObj.tmpDir, "hosts.d")
        self.pidFile = os.path.join(self.pObj.tmpDir, "dnsmasq.pid")
        self.dnsmasqProc = None

        self.serverFile = os.path.join(self.pObj.tmpDir, "cmd.socket")
        self.cmdSock = None
        self.cmdSockWatch = None
        self.ipHostDict = None

    def get_name(self):
        return self.brname

    def get_prefix(self):
        return (str(self.brnetwork.network_address), str(self.brnetwork.netmask))

    def get_bridge_id(self):
        return "bridge-%s" % (self.brip)

    def on_source_add(self, source_id):
        with open(os.path.join(self.hostsDir, source_id), "w") as f:
            f.write("")

    def on_source_remove(self, source_id):
        os.unlink(os.path.join(self.hostsDir, source_id))

    def on_host_add(self, source_id, ip_data_dict):
        fn = os.path.join(self.hostsDir, source_id)
        itemDict = _Util.dnsmasqHostFileToOrderedDict(fn)
        bChanged = False

        for ip, data in ip_data_dict.items():
            if ip in itemDict:
                if "hostname" in data:
                    if itemDict[ip] != data["hostname"]:
                        itemDict[ip] = data["hostname"]
                        bChanged = True
                else:
                    del itemDict[ip]
                    bChanged = True
            else:
                if "hostname" in data:
                    itemDict[ip] = data["hostname"]
                    bChanged = True

        if bChanged:
            _Util.dictToDnsmasqHostFile(itemDict, fn)
            self.dnsmasqProc.send_signal(signal.SIGHUP)

    def on_host_change(self, source_id, ip_data_dict):
        self.on_host_add(source_id, ip_data_dict)

    def on_host_remove(self, source_id, ip_list):
        fn = os.path.join(self.hostsDir, source_id)
        itemDict = _Util.dnsmasqHostFileToOrderedDict(fn)
        bChanged = False

        for ip in ip_list:
            if ip in itemDict:
                del itemDict[ip]
                bChanged = True

        if bChanged:
            _Util.dictToDnsmasqHostFile(itemDict, fn)
            self.dnsmasqProc.send_signal(signal.SIGHUP)

    def on_host_refresh(self, source_id, ip_data_dict):
        fn = os.path.join(self.hostsDir, source_id)
        itemDict = _Util.dnsmasqHostFileToDict(fn)

        itemDict2 = dict()
        for ip, data in ip_data_dict.items():
            if "hostname" in data:
                itemDict2[ip] = data["hostname"]

        if itemDict != itemDict2:
            _Util.dictToDnsmasqHostFile(itemDict2, fn)
            self.dnsmasqProc.send_signal(signal.SIGHUP)

    def _runOpenvpnServer(self):
        selfdir = os.path.dirname(os.path.realpath(__file__))
        cfgf = os.path.join(self.pObj.tmpDir, "config.ovpn")
        mngf = os.path.join(self.pObj.tmpDir, "management.socket")

        # generate openvpn config file
        # notes:
        # 1. no comp-lzo. it seems that "push comp-lzo" leads to errors, and I don't think compression saves much
        with open(cfgf, "w") as f:
            f.write("tmp-dir %s\n" % (self.pObj.tmpDir))

            f.write("proto %s\n" % (self.pObj.proto))
            f.write("port %s\n" % (self.pObj.port))
            f.write("\n")

            f.write("dev-type tap\n")
            f.write("dev %s\n" % (self.brname))
            f.write("keepalive 10 120\n")
            f.write("\n")

            f.write("topology subnet\n")
            f.write("server %s %s nopool\n" % (self.brnetwork.network_address, self.brnetwork.netmask))
            f.write("ifconfig-pool %s %s %s\n" % (self.dhcpRange[0], self.dhcpRange[1], self.brnetwork.netmask))
            f.write("client-to-client\n")
            f.write("\n")

            f.write("duplicate-cn\n")
            # f.write("ns-cert-type client\n")
            f.write("verify-x509-name %s name\n" % (self.pObj.clientCertCn))
            f.write("\n")

            f.write("script-security 2\n")
            f.write("auth-user-pass-verify \"%s/openvpn-script-auth.sh\" via-env\n" % (selfdir))
            f.write("client-connect \"%s/openvpn-script-client.py %s\"\n" % (selfdir, self.pObj.serverFile))
            f.write("client-disconnect \"%s/openvpn-script-client.py %s\"\n" % (selfdir, self.pObj.serverFile))
            f.write("\n")

            f.write("push \"dhcp-option DNS %s\"\n" % (self.brip))
            f.write("push \"redirect-gateway\"\n")
            f.write("\n")

            f.write("ca %s\n" % (self.pObj.caCertFile))
            f.write("cert %s\n" % (self.pObj.servCertFile))
            f.write("key %s\n" % (self.pObj.servKeyFile))
            f.write("dh %s\n" % (self.pObj.servDhFile))
            f.write("\n")

            # f.write("user nobody\n")
            # f.write("group nobody\n")
            # f.write("\n")

            f.write("persist-key\n")
            f.write("persist-tun\n")
            f.write("\n")

            f.write("management %s unix\n" % (mngf))
            # f.write("management-client-user ?\n")
            # f.write("management-client-group ?\n")
            f.write("\n")

            f.write("status %s/status.log\n" % (self.pObj.tmpDir))
            f.write("status-version 2\n")
            f.write("verb 4\n")

        # run openvpn process
        cmd = ""
        cmd += "/usr/sbin/openvpn "
        cmd += "--config %s " % (cfgf)
        cmd += "--writepid %s/openvpn.pid " % (self.pObj.tmpDir)
        cmd += "> %s/openvpn.out 2>&1" % (self.pObj.tmpDir)
        self.openvpnProc = subprocess.Popen(cmd, shell=True, universal_newlines=True)

        self.firewallAllowFunc("tcp dport %d" % (self.pObj.port))

    def _stopOpenvpnServer(self):
        if self.openvpnProc is not None:
            self.openvpnProc.terminate()
            self.openvpnProc.wait()
            self.openvpnProc = None

    def _runCmdServer(self):
        self.cmdSock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.cmdSock.bind(self.serverFile)
        self.cmdSockWatch = GLib.io_add_watch(self.cmdSock, GLib.IO_IN, self.__cmdServerWatch)
        self.ipHostDict = dict()

    def _stopCmdServer(self):
        self.ipHostDict = None
        if self.cmdSockWatch is not None:
            GLib.source_remove(self.cmdSockWatch)
            self.cmdSockWatch = None
        if self.cmdSock is not None:
            self.cmdSock.close()
            self.cmdSock = None

    def _runDnsmasq(self):
        # myhostname file
        with open(self.myhostnameFile, "w") as f:
            f.write("%s %s\n" % (self.brip, socket.gethostname()))

        # self host file
        with open(self.selfHostFile, "w") as f:
            f.write("")

        # make hosts directory
        os.mkdir(self.hostsDir)

        # generate dnsmasq config file
        buf = ""
        buf += "strict-order\n"
        buf += "bind-interfaces\n"                            # don't listen on 0.0.0.0
        buf += "interface=%s\n" % (self.brname)
        buf += "except-interface=lo\n"                        # don't listen on 127.0.0.1
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
        cfgf = os.path.join(self.pObj.tmpDir, "dnsmasq.conf")
        with open(cfgf, "w") as f:
            f.write(buf)

        # run dnsmasq process
        cmd = "/usr/sbin/dnsmasq"
        cmd += " --keep-in-foreground"
        cmd += " --conf-file=\"%s\"" % (cfgf)
        cmd += " --pid-file=%s" % (self.pidFile)
        self.dnsmasqProc = subprocess.Popen(cmd, shell=True, universal_newlines=True)

    def _stopDnsmasq(self):
        if self.dnsmasqProc is not None:
            self.dnsmasqProc.terminate()
            self.dnsmasqProc.wait()
            self.dnsmasqProc = None
        if os.path.exists(self.pidFile):
            os.unlink(self.pidFile)
        if os.path.exists(self.hostsDir):
            shutil.rmtree(self.hostsDir)
        if os.path.exists(self.selfHostFile):
            os.unlink(self.selfHostFile)
        if os.path.exists(self.myhostnameFile):
            os.unlink(self.myhostnameFile)

    def __cmdServerWatch(self, source, cb_condition):
        try:
            buf = self.cmdSock.recvfrom(4096)[0].decode("utf-8")
            jsonObj = json.loads(buf)
            if jsonObj["cmd"] == "add":
                _Util.addToDnsmasqHostFile(self.selfHostFile, jsonObj["ip"], jsonObj["hostname"])
                self.dnsmasqProc.send_signal(signal.SIGHUP)
                self.ipHostDict[jsonObj["ip"]] = jsonObj["hostname"]
                self.pObj.logger.info("Client %s(%s) appeared." % (jsonObj["hostname"], jsonObj["ip"]))
                data = dict()
                data[jsonObj["ip"]] = dict()
                data[jsonObj["ip"]]["hostname"] = jsonObj["hostname"]
                self.clientAddFunc(self.get_bridge_id(), data)
            elif jsonObj["cmd"] == "del":
                _Util.removeFromDnsmasqHostFile(self.selfHostFile, jsonObj["ip"])
                self.dnsmasqProc.send_signal(signal.SIGHUP)
                data = [jsonObj["ip"]]
                self.clientRemoveFunc(self.get_bridge_id(), data)
                self.pObj.logger.info("Client %s(%s) disappeared." % (self.ipHostDict[jsonObj["ip"]], jsonObj["ip"]))
            else:
                assert False
        except Exception as e:
            self.pObj.logger.error("receive error", exc_info=True)       # fixme
        finally:
            return True


class _Util:

    @staticmethod
    def dnsmasqHostFileToDict(filename):
        ret = dict()
        with open(filename, "r") as f:
            for line in f.read().split("\n"):
                if line.startswith("#") or line.strip() == "":
                    continue
                t = line.split(" ")
                ret[t[0]] = t[1]
        return ret

    @staticmethod
    def dnsmasqHostFileToOrderedDict(filename):
        ret = OrderedDict()
        with open(filename, "r") as f:
            for line in f.read().split("\n"):
                if line.startswith("#") or line.strip() == "":
                    continue
                t = line.split(" ")
                ret[t[0]] = t[1]
        return ret

    @staticmethod
    def dictToDnsmasqHostFile(ipHostnameDict, filename):
        with open(filename, "w") as f:
            for ip, hostname in ipHostnameDict.items():
                f.write(ip + " " + hostname + "\n")

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
    def genCertAndKey(caCert, caKey, cn, keysize):
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, keysize)

        cert = crypto.X509()
        cert.get_subject().CN = cn
        cert.set_serial_number(random.randint(0, 65535))
        cert.gmtime_adj_notBefore(100 * 365 * 24 * 60 * 60 * -1)
        cert.gmtime_adj_notAfter(100 * 365 * 24 * 60 * 60)
        cert.set_issuer(caCert.get_subject())
        cert.set_pubkey(k)
        cert.sign(caKey, 'sha1')

        return (cert, k)

    @staticmethod
    def genSelfSignedCertAndKey(cn, keysize):
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, keysize)

        cert = crypto.X509()
        cert.get_subject().CN = cn
        cert.set_serial_number(random.randint(0, 65535))
        cert.gmtime_adj_notBefore(100 * 365 * 24 * 60 * 60 * -1)
        cert.gmtime_adj_notAfter(100 * 365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha1')

        return (cert, k)

    @staticmethod
    def loadCertAndKey(certFile, keyFile):
        cert = None
        with open(certFile, "rt") as f:
            buf = f.read()
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, buf)

        key = None
        with open(keyFile, "rt") as f:
            buf = f.read()
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, buf)

        return (cert, key)

    @staticmethod
    def dumpCertAndKey(cert, key, certFile, keyFile):
        with open(certFile, "wb") as f:
            buf = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
            f.write(buf)
            os.fchmod(f.fileno(), 0o644)

        with open(keyFile, "wb") as f:
            buf = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
            f.write(buf)
            os.fchmod(f.fileno(), 0o600)

    @staticmethod
    def genDh(key_size, outfile):
        cmd = "/usr/bin/openssl dhparam -out \"%s\" %d" % (outfile, key_size)
        proc = subprocess.Popen(cmd, shell=True, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        retcode = proc.wait()
        assert retcode == 0

    @staticmethod
    def gitClone(url, destDir, shallow=False, quiet=False):
        cmdList = ["/usr/bin/git", "clone"]
        if shallow:
            cmdList.append("--depth")
            cmdList.append("1")
        if quiet:
            cmdList.append("-q")
        cmdList.append(url)
        cmdList.append(destDir)
        subprocess.check_call(cmdList)
