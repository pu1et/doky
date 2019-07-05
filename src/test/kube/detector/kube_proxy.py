import logging
import requests
import threading
from subprocess import Popen
import subprocess
import time
import __main__
from src.types import Detector
from src.conf.objects import OpenPortEvent, Service, Event
from src.conf.abcd import works
from src.test.kube.detector.hosts import AuthDetector


class ProxyScanEvent(Event):
    pass

class ProxyScanEvent(Event):
    def __init__(self, port):
        self.port = port
        self.path = ''


@works.hang(ProxyScanEvent)
class ProxyDetector(Detector):
    def __init__(self,event):
        self.event = event
        self.port = self.event.port
        self.host = self.event.host

    def execute(self):
        subprocess.Popen("kubectl proxy --port {}".format(self.port),shell=True)
        logging.debug("proxy port {} start to open...".format(self.port))
        self.host = '127.0.0.1'
        time.sleep(0.5)
        AuthDetector.connect_host("http",self.host,self.port)
        subprocess.call(['fuser','-k','-n','tcp',str(self.port)])

class KubeProxyEvent(Service, Event):
    def __init__(self):
        Service.__init__(self, name="Kube-Proxy", node="Node")

@works.hang(OpenPortEvent, expectport=lambda x:x.port == 8001)
class KubeProxy(Detector):
    def __init__(self, event):
        self.event = event
        self.host = host
        self.port = event.port or 8001

    @property
    def detect_kubeProxy(self):
        logging.debug("Detecting Kube-Proxy at {}:{}",self.host, self.port)
        r = requests.get("http://{}:{}/api/v1".format(self.host, self.port))
        if r.status_code == 200 and "APIResourceList" in r.text:
            return True

    def execute(self):
        if self.detect_kubeProxy():
            self.pick_point(KubeProxyEvent)
            


