from __future__ import print_function
from prettytable import ALL, PrettyTable
import __main__
from .importer import auth_lock,auth_pods,auth_services, services, scanners, vulns, works, service_lock, vuln_lock
import logging

class BasePrinter(object):
    def get_pods(self):
        pods = list()
        pod_locations = set()
        service_lock.acquire()
        for pod in pods:
            pod_location = str(service.pod_host)
            if pod_location not in pod_locations:
                pods.append({"type": service.pod, "location":"{}:{}".format(service.pod_host,service.port)})
                pod_locations.add(pod_location)
        service_lock.release()
        return pods
    
    def get_nodes(self):
        nodes = list()
        node_locations = set()
        service_lock.acquire()
        for service in services:
            node_location = str(service.host)
            if node_location not in node_locations:
                nodes.append({"type": service.node, "location": str(service.host)})
                node_locations.add(node_location)
        service_lock.release()
        return nodes

    def get_services(self):
        services_data = list()
        service_lock.acquire()
        for service in services:
            if service.get_name() != 'Pod':
                services_data.append({"service": service.get_name(),
            "location": "{}:{}{}".format(service.host, service.port, service.get_path()),
            "description": service.explain()})
        service_lock.release()
        return services_data

    def get_vulns(self):
        vuln_lock.acquire()
        vuln_data = [{"location":vuln.location(),
            "category":vuln.category.name,
            "vulnerability":vuln.get_name(),
            "description":vuln.explain(),
            "version":str(vuln.evidence)}
            for vuln in vulns]
        vuln_lock.release()
        return vuln_data
    

class RealPrinter(BasePrinter):
    def kube_printer(self):
        output = ""

        vuln_lock.acquire()
        vuln_len = len(vulns)
        vuln_lock.release()

        scanners_len = len(scanners.items())

        service_lock.acquire()
        services_len = len(services)
        service_lock.release()

        auth_services_len = len(auth_services)

        logging.debug("Service len: {}".format(services_len))
        logging.debug("Vuln len: {}".format(vuln_len))
        logging.debug("Auth Service len: {}".format(auth_services_len))
        
        if services_len:
            output += self.nodes_table()
            if __main__.options.details:
                output += self.pods_table()
            output += self.services_table()
            if vuln_len:
                output += self.vulns_table()
            else:
                output += "\nThere's No Vulnerability"

        elif auth_services_len:
            output += self.auth_nodes_table()
            output += self.auth_pods_table()
            output += self.auth_services_table()
            if vuln_len:
                output += self.vulns_table()
            else:
                output += 'Theres No Vulnerability'
        else:
            print("\nThere's no cluster in your environment")
        print(output)
        return output

    def auth_pods_table(self):
        auth_table = PrettyTable(["Pod","Container Image","Image.ver","Node"], hrules=ALL)
        auth_table.align = "l"
        auth_table.max_width = 40
        auth_table.padding_width = 1
        auth_table.sortvy = "Node"
        auth_table.reversesort = True
        auth_table.header_style = "upper"
        
        auth_lock.acquire()
        for auth in auth_pods:
            auth_table.add_row([auth.pod_ip,auth.service,auth.image,auth.host])
        auth_lock.release()
        auth_ret = "\n\nReliable Pods\n\n{}\n".format(auth_table)
        return auth_ret


    def auth_nodes_table(self):
        auth_table = PrettyTable(["Node","Locations"], hrules=ALL)
        auth_table.align = "l"
        auth_table.max_width = 40
        auth_table.padding_width = 1
        auth_table.sortvy = "Node"
        auth_table.reversesort = True
        auth_table.header_style = "upper"
        host_memory = set()
        auth_lock.acquire()
        for auth in auth_services:
            host_ip = str(auth.host_ip)
            if host_ip not in host_memory:
                auth_table.add_row(["node",auth.host])
                host_memory.add(host_ip)
        auth_lock.release()
        auth_ret = "\n\nReliable Nodes\n\n{}\n".format(auth_table)
        return auth_ret

    def auth_services_table(self):
        auth_table = PrettyTable(["Service","Container Image","Image.ver","Node"], hrules=ALL)
        auth_table.align = "l"
        auth_table.max_width = 40
        auth_table.padding_width = 1
        auth_table.sortvy = "Node"
        auth_table.reversesort = True
        auth_table.header_style = "upper"

        auth_lock.acquire()
        for auth in auth_services:
            auth_table.add_row([auth.name,auth.service,auth.image,auth.host])
        auth_lock.release()
        auth_ret = "\n\nReliable Services\n\n{}\n".format(auth_table)
        return auth_ret

    def pods_table(self):
        pods_table = PrettyTable(["Pod", "Location"], hrules=ALL)
        pods_table.align = "l"
        pods_table.max_width = 20
        pods_table.padding_width = 1
        pods_table.sortvy = "Pod"
        pods_table.reversesort = True
        pods_table.header_style = "upper"
        id_memory = list()
        
        service_lock.acquire()
        for service in services:
            if service.pod_id not in id_memory and service.pod_host:
                pods_table.add_row([service.get_name(),service.pod_host])
                id_memory.append(service.pod_id)
        pods_ret = "\nPods\n{}\n".format(pods_table)
        service_lock.release()
        return pods_ret

    def nodes_table(self):
        nodes_table = PrettyTable(["Node", "Location"], hrules=ALL)
        nodes_table.align = "l"
        nodes_table.max_width = 20
        nodes_table.padding_width = 1
        nodes_table.sortby = "Node"
        nodes_table.reversesort = True
        nodes_table.header_style = "upper"
        id_memory = list()
        service_lock.acquire()
        for service in services:
            if service.host_id not in id_memory and service.host:
                nodes_table.add_row([service.node, service.host])
                id_memory.append(service.host_id)
        nodes_ret = "\n\nNodes\n{}\n".format(nodes_table)
        service_lock.release()
        return nodes_ret


    def services_table(self):
        services_table = PrettyTable(["Service", "Location"], hrules=ALL)
        services_table.align = "l"
        services_table.max_width = 30
        services_table.padding_width = 1
        services_table.sortby = "Service"
        services_table.reversesort = True
        services_table.header_style = "upper"
        service_lock.acquire()
        for service in services:
            if "Pod" not in service.get_name():
                services_table.add_row([service.get_name(), "{}:{}{}".format(service.host, service.port, service.get_path())])
        services_ret = "\nServices\n{}n\n".format(services_table)
        service_lock.release()
        return services_ret

    def vulns_table(self):
        column_names = ["Location", "Category", "Vulnerability", "Description", "Evidence"]
        vuln_table = PrettyTable(column_names, hrules=ALL)
        vuln_table.align = "l"
        vuln_table.max_width = 30
        vuln_table.sortby = "Location"
        vuln_table.reversesort = True
        vuln_table.padding_width = 1
        vuln_table.header_style = "upper"

        vuln_lock.acquire()
        for vuln in vulns:
            row = [vuln.location(), vuln.category.name, vuln.get_name(), vuln.explain()]
            evidence = str(vuln.evidence)
            row.append(evidence)
            vuln_table.add_row(row)
        vuln_lock.release()
        return "\n\nVnlnerabilities\n\n{}\n".format(vuln_table)

    def send_data(self):
        USER_TOKEN = __main__.email.get_email()
        URL = "http://hotsix.kro.kr/re_result.php"
        service_lock.acquire()
        for service in services:
            node_data = {'chk':'1','token' : USER_TOKEN, 'Type_1' : 'Node/Master', 'Location_1' : service.host}
            res = requests.post(URL, data=node_data)
        for service in services:
            location_2 = str(service.host) + ':' + str(service.port) + str(service.get_path())
            service_data = {'chk':'2','token' : USER_TOKEN, 'Service_2' : service.get_name(), 'Location_2' : location_2}
            res = requests.post(URL, data=service_data)
        service_lock.release()

        vuln_lock.acquire()
        for vuln in vulnerabilities:
            vuln_data = {'chk':'3','token' : USER_TOKEN, 'Location_3' : vuln.location(), 'Category_3' : str(vuln.category.name), 'Vulnerability_3': vuln.get_name(), 'Description_3' : vuln.explain(), 'Evidence_3' : vuln.evidence}
            res = requests.post(URL, data=vuln_data)

        vuln_lock.release()
        plus="="*len(USER_TOKEN)
        print("\x1b[1;34m\n==============================================================================={}\x1b[1;m".format(plus))
        print("\x1b[1;34mIf you confirm Kube-Six report, Click This ==> http://hotsix.kro.kr/result.php?{}\x1b[1;m".format(USER_TOKEN))
        print("\x1b[1;34m==============================================================================={}\x1b[1;m".format(plus))


