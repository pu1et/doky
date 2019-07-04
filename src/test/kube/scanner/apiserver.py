import logging
import requests
import json

from src.conf.objects import Vulnerability, Event
from src.conf.abcd import works
from src.test.kube.detector.apiserver import ApiServer
from src.types import Scanner, Cluster

class ApiServerAccess(Vulnerability, Event):
    def __init__(self, evidence):
        Vulnerability.__init__(self, Cluster, name=name, category=category)
        self.evidence = evidence


class ApiServerScannerFinished(Event):
    pass

@works.hang(ApiServer)
class ApiServerScanner(Scanner):
    def __init__(self,event):
        self.event = event

    def access_api_server(self):
        logging.debug("Starting to access the API at {}:{}".format(self.event.host, self.event.port))
        try:
            r =requests.get("{}/api".format(self.path), headers=self.headers, verify=False)
            if r.status_code == 200 and r.content != "":
                return r.content
        except requests.exceptions.ConnectionError:
            pass
        return False

    def get_items(self, path):
        try:
            items = []
            r = requests.get(path, headers=self.headers, verify=False)
            if r.status_code == 200:
                resp = json.loads(r.content)
                for item in resp["items"]:
                    items.append(item["metadata"]["name"])
                return items

        except (requests.exceptions.ConnectionError, KeyError):
                pass

        return None

    def get_pods(self, namespace=None):
        pods = []
        try:
            if namespace is None:
                r = requests.get("{path}/api/v1/pods".format(path=self.path),
                        headers=self.headers, verify=False)
            else:
                r = requests.get("{path}/api/v1/namespaces/{namespaces}/pods".format(path=self.path),
                    headers=self.headers, verify=False)

            if r.status_code == 200:
                resp = json.loads(r.content)
                for item in resp["items"]:
                    name = item["metadata"]["name"].encode('ascii', 'ignore')
                    namespace = item["metadata"]["namespace"].encode('ascii','ignore')
                    pods.append({'name':name, 'namespace':namespace})

                return pods
        except (requests.excpetions.ConnectionError, KeyError):
            pass
        return None


    def execute(self):
        self.pick_point(ApiServerScannerFinished())
