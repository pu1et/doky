import logging
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
    
        print("image_len {}".format(image_len))
        print("container_len {}".format(container_len))
        print("vuln_len {}".format(vuln_len))
        
        if image_len:
            output += self.images_table()
            if container_len:
                output += self.containers_table()
            else:
                output += "\nThere's No Images\n"
                print("1")
                print(output)
            if vuln_len:
                output += self.vulns_table()
                print(output)
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
            images_table.add_row([image.image, image.tag])
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
    
    def send_docker_data(self):
        USER_TOKEN = __main__.email.get_email()
        URL = "http://hotsix.kro.kr/re_result.php"

        #Version
        #for version in ver:
        ver_data = {'chk':'5', 'user_id' : USER_TOKEN, 'docker_ver' : ver}
        res = requests.post(URL, data=ver_data)

        #Image
        for image in images:
            image_data = {'chk':'6', 'user_id' : USER_TOKEN, 'docker_image': image.image, 'docker_tag':image.tag}
            res = requests.post(URL, data=image_data)

        #Container
        for container in containers:
            container_data = {'chk':'7', 'user_id' : USER_TOKEN, 'cont_name' : container.name, 'cont_command':container.command, 'cont_state':container.state }
            res = requests.post(URL, data=container_data)

        #Vulnerability
        for vuln in vulns:
            vuln_data = {'chk':'8', 'user_id' : USER_TOKEN, 'docker_image' : vuln.image, 'docker_vuln' : vuln.name, 'docker_cvss': vuln.cvss, 'docker_description' : vuln.info, 'docker_evidence' : vuln.evidence}
            res = requests.post(URL, data=vuln_data)

        plus="="*len(USER_TOKEN)
        print("\x1b[1;34m\n==============================================================================={}\x1b[1;m".format(plus))
        print("\x1b[1;34mIf you confirm Kube-Six report, Click This ==> http://hotsix.kro.kr/result.php?{}\x1b[1;m".format(USER_TOKEN))
        print("\x1b[1;34m==============================================================================={}\x1b[1;m".format(plus))
