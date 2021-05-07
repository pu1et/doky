# doky

<h2>If you're running Docker, Kubernetes and both,</br> 
  You can scan your Nodes, Services, Vulnerabilities even Pods.</h2>
  
# Getting Started

```
# git clone https://github.com/pu1et/doky/
# cd doky
# ./doky.py
```
<h3>options</h3>

default : scan Nodes, Services, Vulnerabilites

__--details__ : scan all Kubernetes Components (Pods, Nodes, Services) and Vulnerabilities</br> 
__--token TOKEN__ : scan all Kubernetes Components (Pods, Nodes, Services) and Vulnerabilities using token</br> 
  >_This option can also be scanned from the Worker Node_</br> 
  > If you haven't modified service account file or don't know your token,
  > you can insert  __--token default__
  
__--service ACCOUNT__ : scan all Kubernetes Components (Pods, Nodes, Services) and Vulnerabilities using service account</br> 
  >_This option can also be scanned from the Worker Node_
  > If you haven't modified service account file or don't know your service account,
  > you can insert  __--service default__
  
__--proxy PORT__ : scan all Kubernetes Components (Pods, Nodes, Services) and Vulnerabilities locally using proxy
  > You have to specify the port you want to access the Api Server
  
__--docker__ : scan docker containers and Vulnerabilities only for docker

# Code Overview
## Project Structure
```
doky
 |  doky.py         # App entry point
 |
 └─ src            
    |- conf                           # Intialization before Scanning
    |   |- abcd.py                      # Create EventQueues(Threads), Create list of Event Classes, Add Objects of Event Class into EventQueues
    |   └─ objects.py                   # Define Base Classes
    | 
    └─ test                           # Scan the Docker or Kubernetes
        |- docker                       # Scan the Docker
        |   |- detector                   # Detect the Docker Environment  
        |   |   └─ container.py           # Detect the Docker Version, Docker images, Docker Containers
        |   |
        |   |- printer                  # Print the Docker
        |   |   |- docker_printer.py      # Print out result of Scanning Docker 
        |   |   └─ importer.py            # Save the Docker Version, Docker images, Docker Vulnerabilities
        |   |
        |   └─ scanner                  # Scan the Docker Vulnerabilities
        |       └─ cvescanner.py        
        |
        └─ kube                       # Scan the Kubernetes
            |- detector                 # Detect the Kubernetes Environment
            |   |- apiserver.py           # Scan the API Server of the Master node
            |   |- auth.py                # Using --service, --token option) Scan using the Service account or Token 
            |   |- hosts.py               # After Detecting the Subnet of the Node and Pod Interfaces, it creates a list of IP addresses in the Subnet
            |   |- kube_proxy.py          # Using --proxy option) Scan using the Proxy
            |   |- kubectl.py             # Scan the Kubectl Version
            |   |- kubelet.py             # Scan the Kubelet Version
            |   └─ ports.py               # Port Scanning of the list of IP addresses created in the hosts.py
            |
            |- printer                  # Print the Kubernetes
            |   |- importer.py            # Save the Kubernetes Pods, Services, Vulnerabilities
            |   └─ kube_printer.py        # Print the result of Scanning Kubernetes
            |
            └─ scanner                  # Scan the Kubernetes
                |- apiserver.py           # Scan the Kubernetes Pods, Services Using API Server
                └─ cvescanner.py          # Scan the Kubernetes Vulnerabilities
                
```

# Vulnerabilities

## Kubernetes 

- CVE-2019-9946
- CVE-2019-11243 
- CVE-2019-11244
- CVE-2019-1002100
- CVE-2019-1002101
- CVE-2018-1002100
- CVE-2018-1002101
- CVE-2018-1002105


More information about Kubernetes Vulnerabilities >>

https://www.cvedetails.com/vulnerability-list/vendor_id-15867/product_id-34016/Kubernetes-Kubernetes.html

## Docker 

- CVE-2017-7308
- CVE-2019-5736
- CVE-2018-15664
- CVE-2018-15514

More information about Docker Vulnerabilities >>

https://www.cvedetails.com/vulnerability-list/vendor_id-13534/product_id-28125/Docker-Docker.html


