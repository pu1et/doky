import logging
import __main__
from src.conf.abcd import works
from src.test.docker.detector.container import Version, Image, Container
from src.conf.objects import Event, DockerVulnerability


class DockerPrinter(Event):
    pass

ver = list()
images = list()
containers = list()
vulns = list()

@works.hang(Version)
@works.hang(Image)
@works.hang(Container)
@works.hang(DockerVulnerability)
class Importer(object):
    def __init__(self, event=None):
        self.event = event

    def execute(self):
        global images
        global containers
        global vulns
        global ver

        bases = self.event.__class__.__mro__
        
        if Version in bases:
            ver.append(self.event)

        elif Image in bases:
            images.append(self.event)

        elif Container in bases:
            containers.append(self.event)

        elif DockerVulnerability in bases:
            vulns.append(self.event)

@works.hang(DockerPrinter)
class Printer(object):
    def __init__(self, event):
        self.event = event

    def execute(self):
        printer = __main__.printer.docker_printer()
        logging.info("\n{div}\n{printer}".format(div="-"*10, printer=printer))
        #__main__.printer.send_data()
