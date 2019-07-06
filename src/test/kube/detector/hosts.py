from socket import socket
import json
import requests
import threading
import logging
from netaddr import IPNetwork
import re
import subprocess
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

global auth_lock
auth_lock = threading.Lock()
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

class AuthScanEvent(Event):
    def __init__(self, predefined_hosts=list()):
        self.predefined_hosts = predefined_hosts

class AuthBase(object):
    def __init__(self, name='', service='', image='', host='', pod_ip=''):
        self.name = name
        self.service = service
        self.image = image
        self.host = host
        self.pod_ip = pod_ip

class AuthPod(AuthBase):
    def __init__(self, name='', service='', image='', host='', pod_ip=''):
        AuthBase.__init__(self,name, service, image, host, pod_ip)

class AuthService(AuthBase):
    def __init__(self,name='', service='', image='', host='', pod_ip=''):
        AuthBase.__init__(self,name, service, image, host, pod_ip)
        self.host_ip = host

class AuthVulnerability(AuthBase,Event):
    def __init__(self,version='',path=''):
        self.version = version
        self.path = path
        self.token = True



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
            if iface in notIface[2] or iface in notIface[3]:
                for i in ifaddresses(ifaceList[iface]).setdefault(AF_INET,[]):
                    for ip in HostDetectorPreStart.generate_subnet('10.244.1.0','24'):
                        yield ip


@works.hang(AuthScanEvent)
class AuthDetector(Detector):
    def __init__(self, event):
        self.event = event
        self.path = "https://{}:{}/api/v1/".format(self.event.host, 6443)
        self.host = self.event.host
        self.port = 6443
        token = ''
        service = ''

    @staticmethod
    def connect_host(protocol, host, port, headers=''):
        try:
            path = "{}://{}:{}".format(protocol,host,port)
            r = requests.get("{}/api/v1/pods".format(path), headers=headers, verify=False)
            r_ver = requests.get("{}/version".format(path), headers=headers, verify=False).content
            version = json.loads(r_ver)['gitVersion']
            works.pick_point(AuthVulnerability(version,"{}:{}".format(host,port)))
            cluster_info = json.loads(r.content)
            for info in cluster_info['items']:
                service = info['spec']['containers'][0]['name']
                image = info['spec']['containers'][0]['image']
                host_ip = info['status']['hostIP']
                pod_ip = info['status']['podIP']
                if host_ip != pod_ip:
                    works.pick_point(AuthPod("Pod", service, image, host_ip, pod_ip))
                else:
                    works.pick_point(AuthService("Service", service, image, host_ip, pod_ip))
        except(requests.exceptions.ConnectionError, KeyError):
            pass



    def execute(self):
        for iface in ifaceList:
            if iface not in notIface:
                for i in ifaddresses(ifaceList[iface]).setdefault(AF_INET,[]):
                    for ip in HostDetectorPreStart.generate_subnet(i['addr'],'32'):
                        if HostDetectorPreStart.detect_server(ip,6443):
                            self.host = ip
                            break

        if __main__.options.service == 'default' or __main__.options.service == None:
            self.service = subprocess.check_output("kubectl get secrets | grep ^{} | cut -f1 -d ''".format("default"),shell=True).split(' ')[0]
        else : 
            self.service = __main__.options.service
        
        logging.debug("\nservice account : {}\n".format(self.service))
        
        if __main__.options.service == 'default' or __main__.options.token:
            self.token = "Bearer " + subprocess.check_output("kubectl describe secret {} | grep -E '^token' | cut -f2 -d':' | tr -d \" \"".format(self.service), shell=True).split('\n')[0]
        else :
            self.token = __main__.options.token
        
        logging.debug("token : {}".format(self.token))
        headers={'Authorization': self.token}
        self.connect_host("https",self.host,self.port,headers)
        return None


