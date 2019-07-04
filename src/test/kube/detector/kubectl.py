import logging
import subprocess
from src.conf.objects import Event
from src.types import Detector
from src.conf.abcd import works

class KubectlEvent(Event):
    def __init__(self, version):
        self.version = version


class KubectlDetector(Detector):
    def __init__(self, event):
        self.event = event

    def execute(self):
        version = None
        try:
            version = subprocess.check_output('kubectl version --client',shell=True)
            version = version.split('GitVersion:')[1].split(',')[0]
        except Exception as e:
            logging.debug("There's no Kubectl client")
        if version:
            self.pick_point(KubectlEvent(version=version))
    
