import logging
import threading
import __main__
from src.conf.abcd import works
from src.conf.objects import Event, Service, Vulnerability, DokyPrinter
from src.test.kube.detector.hosts import AuthVulnerability,AuthPod,AuthService


global service_lock
service_lock = threading.Lock()
services = list()

global vuln_lock
vuln_lock = threading.Lock()
vulns = list()

scanners = works.all_scanners

global auth_lock
auth_lock = threading.Lock()
auth_services = list()
auth_pods = list()


@works.hang(AuthPod)
@works.hang(AuthService)
@works.hang(AuthVulnerability)
@works.hang(Service)
@works.hang(Vulnerability)
class Importer(object):
    def __init__(self, event=None):
        self.event = event

    def execute(self):
        global services
        global vulns
        global auth_services
        global auth_pods
        bases = self.event.__class__.__mro__
        if Service in bases:
            service_lock.acquire()
            services.append(self.event)
            service_lock.release()

        elif Vulnerability in bases:
            vuln_lock.acquire()
            vulns.append(self.event)
            vuln_lock.release()
        
        elif AuthPod in bases:
            auth_lock.acquire()
            auth_pods.append(self.event)
            auth_lock.release()

        elif AuthService in bases:
            auth_lock.acquire()
            auth_services.append(self.event)
            auth_lock.release()


@works.hang(DokyPrinter)
class Printer(object):
    def __init__(self, event):
        self.event = event

    def execute(self):
        printer = __main__.printer.kube_printer()
        logging.info("\n{}\n".format("-"*10, printer))
        if __main__.options.token or __main__.options.service or __main.options.proxy:
            __main__.printer.send_auth_data()
        else: __main__.printer.send_data()
        
