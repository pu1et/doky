import threading
import subprocess
import logging
import requests
import ast

from src.conf.abcd import works
from src.conf.objects import Vulnerability, Event
from src.test.kube.detector import ApiServer,AuthVulnerability
from src.types import Scanner, Cluster, RemoteCodeExec, AccessRisk, InformationDisclosure, PrivilegeEscalation, DenialOfService, UnauthenticatedAccess

global final_pods
final_pods = ''
global check_lock
check_lock = threading.Lock()
global check
check = 0

class CheckCVE20181002105(Vulnerability, Event):
    """CVE-2018-1002105"""
    def __init__(self, evidence):
        Vulnerability.__init__(self, Cluster, name="Critical Privilege Escalation CVE", category=PrivilegeEscalation)
        if len(evidence) < 10 : self.evidence = evidence
        else : self.evidence = evidence[37:60]

class CheckCVE20191002100(Vulnerability, Event):
    """CVE-2019-1002100"""
    def __init__(self, evidence):
        Vulnerability.__init__(self, Cluster, name="Denial of Service to Kubernetes API Server", category=DenialOfService)
        if len(evidence) < 10 : self.evidence = evidence
        else : self.evidence = evidence[37:60]

class CheckCVE20181002101(Vulnerability, Event):
    """CVE-2018-1002101"""
    def __init__(self, evidence):
        Vulnerability.__init__(self, Cluster, name="lead to command line argument injection", category=RemoteCodeExec)
        if len(evidence) < 10 : self.evidence = evidence
        else : self.evidence = evidence[37:60]

class CheckCVE20199946(Vulnerability, Event):
    """CVE-2019-9946"""
    def __init__(self, evidence):
        Vulnerability.__init__(self, Cluster, name="Unauthenticated Access", category=UnauthenticatedAccess)
        if len(self.evidence) < 10 : evidence = evidence
        else : self.evidence = evidence[37:60]

class CheckCVE201911243(Vulnerability, Event):
    """CVE-2019-11243"""
    def __init__(self, evidence):
        Vulnerability.__init__(self, Cluster, name="remains service account credentials", category=InformationDisclosure)
        if len(evidence) < 10 : self.evidence = evidence
        else : self.evidence = evidence[37:60]

class CheckCVE201911244(Vulnerability, Event):
    """CVE-2019-11244"""
    def __init__(self, evidence):
        Vulnerability.__init__(self, Cluster, name="--cache-dir may be modified by other users/groups", category=UnauthenticatedAccess)
        if len(evidence) < 10 : self.evidence = evidence
        else : self.evidence = evidence[37:60]

class CheckCVE20191002101(Vulnerability, Event):
    """CVE-2019-1002101"""
    def __init__(self,evidence):
        Vulnerability.__init__(self, Cluster, name="run any code and output unexpected, malicious results", category=RemoteCodeExec)
        self.evidence = "* vulnerable pods * \n" + evidence

@works.hang(AuthVulnerability)
@works.hang(ApiServer)
class CVEScanner(Scanner):
    def __init__(self, event):
        self.event = event
        self.event.auth_host = self.event.path 
        self.headers = dict()
        self.path = "https://{}:{}".format(self.event.host, self.event.port)
        self.api_server_evidence = self.event.version
        self.k8sVersion = self.event.version

    def get_api_server_version(self):
        logging.debug("get api version at {}".format(self.path+"/version"))
        try:
            r = requests.get("{path}/version".format(path=self.path),headers=self.headers, verify=False)
            self.api_server_evidence = r.content
            resDict = ast.literal_eval(r.content)
            print(resDict)
            version = resDict["gitVersion"].split('.')
            first_version = eval(version[1])
            last_version = eval(version[2])
            return [first_version, last_version]

        except (requests.exceptions.ConnectionError, KeyError):
            return None


    def check_cve_2018_1002105(self, api_version):
        first_version = api_version[0]
        last_version = api_version[1]

        if first_version == 10 and last_version < 11:
            return True
        elif first_version== 11 and last_version < 5:
            return True
        elif first_version== 12 and last_version < 3:
            return True
        elif first_version< 10:
            return True

        return False

    def check_cve_2019_1002100(self, api_version):
        first_version= api_version[0]
        last_version= api_version[1]

        if first_version== 11 and last_version< 8:
            return True
        elif first_version== 12 and last_version< 6:
            return True
        elif first_version== 13 and last_version< 4:
            return True
        elif first_version< 11:
            return True

        return False

    def check_cve_2019_1002101(self):
        pods = subprocess.check_output('kubectl get pods',shell=True)
        pods = pods.split('\n')
        check_lock.acquire()
        global final_pods
        global check
        for i in range(1, len(pods)-1):
            pod = pods[i][:14]
            pod=pod.split(' ')[0]
            cmd = 'kubectl exec '
            cmd += pod
            cmd += ' -it md5sum /bin/tar'
            tar_cmd = subprocess.check_output(cmd,shell=True)
            tar_hash = tar_cmd.split(' ')[0]
            tar_org1 = '68b3f069b0d313789bc63483192bca6c' # gcr image
            tar_org2 = '9c3e73f32449d66a3a6685c7e9546fe1' # nginx image
            tar_org3 = '3fffeece80c12828a6eff78a0675b7f8' # myapp-pod image
            if not (tar_org1 == tar_hash and tar_org2 == tar_hash) and tar_org3 == tar_hash:     
                final_pods += pod
                final_pods += '\n'
                check = check +1
                
        if check != 0:
            check = 0
            check_lock.release()
            return True
        else:
            check_lock.release()
            return False

    def check_cve_2018_1002101(self, api_version):
        first_version= api_version[0]
        last_version= api_version[1]

        if first_version== 11 and last_version< 9:
            return True
        elif first_version== 12 and last_version< 7:
            return True
        elif first_version== 13 and last_version< 4:
            return True
        elif first_version == 14 and last_version< 1:
            return True
        elif first_version< 11:
            return True

        return False

    def check_cve_2019_9946(self, api_version):
        first_version= api_version[0]
        last_version= api_version[1]

        if first_version== 11 and last_version< 9:
            return True
        elif first_version== 12 and last_version< 6:
            return True
        elif first_version== 13: 
            if last_version < 4 or last_version == 6:
                return True
        elif first_version == 14 and last_version < 1:
            return True
        elif first_version < 11:
            return True

        return False

    def check_cve_2019_11243(self, api_version):
        first_version= api_version[0]
        last_version= api_version[1]

        if first_version == 12 and last_version< 5:
            return True
        elif first_version == 13 and last_version== 0:
            return True
        
        return False

    def check_cve_2019_11244(self, api_version):
        first_version= api_version[0]
        last_version= api_version[1]

        if first_version == 11 and last_version< 10:
            return True
        elif first_version == 12 and last_version< 7:
            return True
        elif first_version == 13 and last_version< 4:
            return True
        elif first_version == 14 and last_version< 1:
            return True
        elif first_version< 11 and last_version > 7:
            return True

        return False

    def execute(self):
        if self.k8sVersion == None:
            api_version = self.get_api_server_version()
        else: 
            api_version = self.k8sVersion.split('v')[1].split('.')
            api_version = [eval(api_version[1]), eval(api_version[2])]
        global final_pods
        if api_version:
#            if self.check_cve_2019_1002101():
#                self.pick_point(CheckCVE20191002101(final_pods))
#                final_pods = ''
            if self.check_cve_2019_9946(api_version):
                self.pick_point(CheckCVE20199946(self.api_server_evidence))
            if self.check_cve_2019_11243(api_version):
                self.pick_point(CheckCVE201911243(self.api_server_evidence))
            if self.check_cve_2019_11244(api_version):
                self.pick_point(CheckCVE201911244(self.api_server_evidence))
            if self.check_cve_2018_1002101(api_version):
                self.pick_point(CheckCVE20181002101(self.api_server_evidence))
            if self.check_cve_2018_1002105(api_version):
                self.pick_point(CheckCVE20181002105(self.api_server_evidence))
            if self.check_cve_2019_1002100(api_version):
                self.pick_point(CheckCVE20191002100(self.api_server_evidence))
        else: return

