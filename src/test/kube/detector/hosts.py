from socket import socket
import logging
from netaddr import IPNetwork
import re
import __main__

from netifaces import AF_INET, ifaddresses, interfaces
from src.conf.objects import Vulnerability,Service, NewHostEvent, Event
from src.conf.abcd import works
from src.types import Detector,Cluster

notIp=['0','1']
notIface = ['lo', 'docker', 'cni', 'flannel', 'veth']

ifaceList = dict()
ifaceRaw = list(map(lambda x: re.sub('[.|0-9]','',x),interfaces()))
map(lambda x,y: ifaceList.update({x:y}),ifaceRaw,interfaces())

global node_count
node_count = 0

class HostEvent(Event):
    pass

class HostDetectorPreStart:
    @staticmethod
    def generate_subnet(ip, sn="24"):
        subnet = IPNetwork('{ip}/{sn}'.format(ip=ip, sn=sn))
        for ip in IPNetwork(subnet):
            if str(ip).split('.')[3] not in notIp:
                logging.debug("generate_subnet yielding {0}".format(ip))
                yield ip

    @staticmethod
    def detect_server(host,port):
        s = socket()
        s.settimeout(1.5)
        try:
            success = s.connect_ex((str(host),port))
            if success == 0:
                return True
        except: pass
        finally: s.close()
        return False


@works.hang(HostEvent)
class HostDetector(Detector):
    def __init__(self, event):
        self.event = event

    def execute(self):
        for ip in self.iface_subnet():
            works.pick_point(NewHostEvent(host=ip))
        if __main__.options.details:
            for ip in self.pod_subnet():
                works.pick_point(NewHostEvent(pod_host=ip))

    def iface_subnet(self):
        for iface in ifaceList:
            if iface not in notIface:
                for i in ifaddresses(ifaceList[iface]).setdefault(AF_INET,[]):
                    for ip in HostDetectorPreStart.generate_subnet(i['addr'],'24'):
                        yield ip


    def pod_subnet(self):
        for iface in ifaceList:
            if iface in notIface[1] or iface in notIface[3]:
                print(iface)
                for i in ifaddresses(ifaceList[iface]).setdefault(AF_INET,[]):
                    for ip in HostDetectorPreStart.generate_subnet('10.244.1.0','24'):
                        yield ip


