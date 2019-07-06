import logging
from src.conf.objects import Event,Service,OpenPortEvent, NewHostEvent
from src.types import Detector
from socket import socket
from src.conf.abcd import works
import requests

ports = [80,443, 6443, 2379, 8001, 8080, 10250, 10255, 30000]

class PodServer(Service, Event):
    def __init__(self, whatpod):
        Service.__init__(self, name="Pod {}".format(whatpod))

    def __str__(self):
        return str(self.port)


@works.hang(NewHostEvent)
class PortDetector(Detector):
    def __init__(self, event):
        self.event = event
        if event.host:
            self.host = event.host
            print(self.host)
        elif event.pod_host:
            self.host = event.pod_host
            print(self.host)
        self.port = event.port

    def execute(self):
        logging.debug("host {} try ports: {}".format(self.host, ports))
        for port in ports:
            if self.detect_ports(self.host, port):
                logging.debug("port : {}".format(port))
                if port == 80:
                    r = requests.get("http://{host}:{port}".format(host=self.host,port=port))
                    if r.status_code == 200 and r.text != '':
                        if "nginx" in r.text:
                            logging.debug("PodServer")
                            self.pick_point(PodServer("nginx"))
                    else: self.pick_point(PodServer("none"))
                else : self.pick_point(OpenPortEvent(port=port))

    @staticmethod
    def detect_ports(host,port):
        s = socket()
        s.settimeout(1.5)
        try:
            success = s.connect_ex((str(host), port))
            if success == 0:
                return True
        except: pass
        finally: s.close()
        return False


