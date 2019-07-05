import threading
import json
import docker
import logging
import subprocess
import __main__
from src.conf.abcd import works
from src.conf.objects import Event
from src.types import Detector


class Image(Event):
    def __init__(self, name, tag="latest"):
        self.name = name
        self.tag = tag

class Container(Event):
    def __init__(self, name, command, state):
        self.name = name
        self.command = command
        self.state = state

class Version(Event):
    def __init__(self, ver):
        self.version = ver

class DockerScanEvent(Event):
    pass

@works.hang(DockerScanEvent)
class DockerDetector(Detector):
    def __init__(self,event):
        self.event = event

    def execute(self):
        user = docker.APIClient(base_url='unix://var/run/docker.sock')
        
        version = user.version()['Components'][0]['Version']
        self.pick_point(Version(version))

        logging.debug("version : {}".format(version))
        for i in user.images():
            image = i['RepoTags'][0].split(':')
            image_name = image[0]
            image_tag = image[1]
            if image_name != '<none>':
                self.pick_point(Image(image_name, image_tag))
                logging.debug("image {}:{}".format(image_name, image_tag))
        for i in user.containers():
            command = i['Command']
            if len(command) > 50:
                command = command[:47] + "..."
            container_name= i['Names'][0][:50]
            if len(container_name) > 50:
                container_name = i['Names'][0][:47] + "..."
            state = i['State']
            logging.debug("Command: {}".format(command))
            logging.debug("Names: {}".format(container_name))
            logging.debug("State: {}".format(state))
            self.pick_point(Container(container_name, command, state))
        
        #a = subprocess.check_output(["sudo","docker","images"])
        #print(a)
        #print("container_list : {}".format(container_list))
