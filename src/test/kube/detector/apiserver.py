import requests
import logging

from src.types import Detector
from src.conf.objects import OpenPortEvent, Service, Event
from src.conf.abcd import works
import __main__

class ApiServer(Service, Event):
    def __init__(self):
        Service.__init__(self, name="API Server", path="api",node="Master")

@works.hang(OpenPortEvent, expectport=lambda x: x.port==443 or x.port==6443 or x.port==8080)
class ApiServerDetector(Detector):
    def __init__(self, event):
        self.event = event

    def execute(self):
        logging.debug("API server on {}:{}".format(self.event.host, self.event.port))
        self.make_request(protocol="https")
        self.make_request(protocol="http")

    def make_request(self, protocol):
        try:
            r = requests.get("{}://{}:{}".format(protocol, self.event.host, self.event.port), verify=False)
            if ('k8s' in r.text) or ('"code"' in r.text and r.status_code is not 200):
                self.event.node = "Master"
                self.pick_point(ApiServer())

        except requests.exceptions.SSLError:
            logging.debug("SSL Error on {}://{}:{}".format(protocol, self.event.host, self.event.port))
        except Exception as e:
            logging.debug("{} on {}:{}".format(e, self.event.host, self.event.port))
