import logging
import requests
from src.conf.objects import OpenPortEvent, Service, Event
from src.conf.abcd import works
from src.types import Detector

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
