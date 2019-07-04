import logging
import requests
import urllib3
from src.conf.objects import Vulnerability, OpenPortEvent, Event, Service
from src.conf.abcd import works
from src.types import Detector
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class KubeletEvent(Service,Event):
    def __init__(self):
        Service.__init__(self, name="Kubelet",node="Node")

@works.hang(OpenPortEvent, expectport=lambda x: x.port==10255 or x.port==10250)
class KubeletDetector(Detector):
    def __init__(self, event):
        self.event = event

    def detect_kubelet(self):
        logging.debug("Detecting Kubelet Service")
        
        if self.event.port == 10250: # https
            try:
                status = requests.get("https://{}:{}/pods".format(self.event.host, self.event.port),verify=False).status_code
                if status == 200 or status == 401 or status == 403:
                    self.pick_point(KubeletEvent())
            except Exception as e:
                logging.debug("https port 10250 don't response")

        elif self.event.port == 10255:
            status = requests.get("http://{}:{}/pods".format(self.event.host, self.event.port)).status_code
            if status == 200:
                self.pick_point(KubeletEvent())
            
              

    def execute(self):
        self.detect_kubelet()


