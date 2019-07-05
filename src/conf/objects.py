import logging
import requests
import json
import threading
from src.types import InformationDisclosure, DenialOfService, RemoteCodeExec, IdentityTheft, PrivilegeEscalation, AccessRisk, UnauthenticatedAccess
from src.conf import abcd

class Event(object):
    def __init__(self):
        self.previous = None
        self.auth_host = ''
        self.token = None

    def __getattr__(self, name):
        if name == 'previous':
            return None
        for event in self.history:
            if name in event.__dict__:
                return event.__dict__[name]

    def location(self):
        location = None
        logging.debug("self.previous : {}\nself.auth_host : {}\n\n".format(self.previous, self.auth_host))
        if self.token != None:
            location = self.auth_host
        elif self.previous or self.auth_host == '':
            location = self.previous.location()
        return location

    @property
    def history(self):
        previous, history = self.previous, list()
        while previous:
            history.append(previous)
            previous = previous.previous
        return history


class Service(object):
    def __init__(self, name, path="", node="Node",pod="Pod"):
        self.name = name
        self.path = path
        self.node = node
        self.pod = pod

    def get_name(self):
        return self.name

    def get_path(self):
        return "/" + self.path if self.path else ""

    def explain(self):
        return self.__doc__

class DockerVulnerability(object):
    def __init__(self, image, name, cvss, info):
        self.image = image
        self.name = name
        self.cvss = cvss
        self.info = info
        self.evidence = "nothing"


class Vulnerability(object):
    def __init__(self, component, name, category=None):
        self.component = component
        self.category = category
        self.name = name
        self.evidence = "nothing"
        self.node = "Node"


    def get_category(self):
        if self.category:
            return self.category.name

    def get_name(self):
        return self.name

    def explain(self):
        return self.__doc__

global host_lock
host_lock = threading.Lock()
host_count = 0

global pod_lock
pod_lock = threading.Lock()
pod_count = 0

class NewHostEvent(Event):
    def __init__(self, host=None, pod_host=None):
        global host_count
        global pod_count
        self.host = host
        self.pod_host = pod_host
        if host:
            host_lock.acquire()
            self.host_id = host_count
            host_count += 1
            host_lock.release()
        elif pod_host:
            pod_lock.acquire()
            self.pod_id = pod_count
            pod_count += 1
            pod_lock.release()

    def __str__(self):
        return str(self.host)
    
    def get_host(self):
        if self.host:
            return str(self.host)

    def get_pod(self):
        if self.pod:
            return str(self.pod_host)

class OpenPortEvent(Event):
    def __init__(self, port):
        self.port = port

    def __str__(self):
        return str(self.port)

    def location(self):
        if self.host:
            location = str(self.host) + ":" + str(self.port)
        elif self.pod_host:
            location = str(self.pod_host) + ":" + str(self.port)
        else:
            location = str(self.port)
        return location

class DokyWorked(Event):
    pass

class DokyPrinter(Event):
    pass

class DokyFinished(Event):
    pass
