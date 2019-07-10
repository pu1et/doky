import logging
import requests
from src.conf.abcd import works
from src.conf.objects import DockerVulnerability, Event
from src.test.docker.detector.container import Image
from src.types import Scanner

class CheckCVE20177308(DockerVulnerability, Event):
    def __init__(self, image, version, cvss, info):
        DockerVulnerability.__init__(self, image=image, name="CVE-2017-7308", cvss=cvss, info=info)
        self.evidence = version

class CheckCVE201815664(DockerVulnerability, Event):
    def __init__(self, image, version, cvss, info):
        DockerVulnerability.__init__(self, image=image, name="CVE-2018-15664", cvss=cvss, info=info)
        self.evidence = version
    
class CheckCVE201815514(DockerVulnerability, Event):
    def __init__(self, image, version, cvss, info):
        DockerVulnerability.__init__(self, image=image, name="CVE-2018-15514", cvss=cvss, info=info) 
        self.evidence = version

class CheckCVE20195736(DockerVulnerability, Event):
    def __init__(self, image, version, cvss, info):
        DockerVulnerability.__init__(self, image=image, name="CVE-2019-5736", cvss=cvss, info=info)
        self.evidence = version

@works.hang(Image)
class DockerCVEScanner(Scanner):
    def __init__(self,event):
        self.event = event
        self.image = self.event.image
        self.version = self.event.tag
        self.cvss = "default"
        self.info = "default"

    def get_image_version(self):
        if 'latest' in self.version:
            return False
        if 'v' in self.version:
            self.version = self.version[1:]
        if '-' in self.version:
            self.version = self.version.split('-')[0]
        logging.debug("image: {}, version: {}".format(self.image, self.version))
        
        ver = self.version.split('.')
        first_v = eval(ver[0])
        second_v = eval(ver[1])
        third_v = eval(ver[2])
        return [first_v, second_v, third_v]
    
    def get_cve_data(self):
        #URL = "hotsix.kro.kr/re_result.php"
        #res = requests.post(URL, data={'chk':'0.4','image_name':self.image, 'image_ver':self.version})
        #print(res.text)
        pass
    
    def check_cve_2017_7308(self, version):
        first_v = version[0]
        second_v = version[1]
        third_v = version[2]
        if first_v >= 1:
            return True
        return False

    def check_cve_2018_15664(self, version):
        first_v = version[0]
        second_v = version[1]
        third_v = version[2]
        if first_v >= 1:
            return True
        return False

    def check_cve_2018_15514(self, version):
        first_v = version[0]
        second_v = version[1]
        third_v = version[2]
        if first_v >= 1:
            return True
        return False

    def check_cve_2019_5736(self, version):
        first_v = version[0]
        second_v = version[1]
        third_v = version[2]
        if first_v >= 1:
            return True
        return False
    
    def execute(self):
        version = self.get_image_version()
        self.get_cve_data()
        if version:
            if self.check_cve_2017_7308(version):
                self.pick_point(CheckCVE20177308(self.image, self.version, self.cvss, self.info))
            if self.check_cve_2018_15664(version):
                self.pick_point(CheckCVE201815664(self.image, self.version, self.cvss, self.info))
            if self.check_cve_2018_15514(version):
                self.pick_point(CheckCVE201815514(self.image, self.version, self.cvss, self.info))
            if self.check_cve_2019_5736(version):
                self.pick_point(CheckCVE20195736(self.image, self.version, self.cvss, self.info))


