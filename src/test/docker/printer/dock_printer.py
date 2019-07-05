from prettytable import ALL, PrettyTable
from src.test.docker.printer.importer import ver, images, containers, vulns

class RealDockerPrinter(object):
    def docker_printer(self):
        output = ""
        ver_len = len(ver)
        image_len = len(images)
        container_len = len(containers)
        vuln_len = len(vulns)
        output += self.get_docker_version()

        if image_len:
            output += self.images_table()
            if container_len:
                output += self.containers_table()
                print(output)
            else:
                output += "\nThere's No Images\n"
            if vuln_len:
                output += self.vulns_table()
            else:
                output += "\nThere's No Vulnerabilities\n"
        else:
            output += "\nThere's No Imgaes\n"


    def get_docker_version(self):
        docker_table = PrettyTable(["docker.ver"],hrules=ALL)
        docker_table.max_width = 10
        for version in ver:
            docker_table.add_row([version.version])
        docker_ret = "\n\nDocker Version\n{}\n".format(docker_table)
        return docker_ret


    def images_table(self):
        images_table = PrettyTable(["Image","Tag"],hrules=ALL)
        images_table.max_width = 20
        images_table.sortby = "Image"
        for image in images:
            images_table.add_row([image.name, image.tag])
        images_ret = "\nImages\n{}\n".format(images_table)
        return images_ret

    def containers_table(self):
        containers_table = PrettyTable(["Container","Command","State"],hrules=ALL)
        containers_table.max_width = 50
        containers_table.sortby = "Container"
        for container in containers:
            containers_table.add_row([container.name, container.command, container.state])
        containers_ret = "\nContainers\n{}\n".format(containers_table)
        return containers_ret

    def vulns_table(self):
        vulns_table = PrettyTable(["Image","Vulnerability","CVSS","Description","Evidence"],hrules=ALL)
        vulns_table.max_width = 20
        vulns_table.sortby = "Image"
        for vuln in vulns:
            vulns_table.add_row([vuln.image, vuln.name, vuln.cvss, vuln.info, vuln.evidence])
        vulns_ret = "\nVulnerabilities\n{}\n".format(vulns_table)
        return vulns_ret
