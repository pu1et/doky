# doky

##If you're running Kubernets, You can scan your Nodes, Services, Vulnerabilities even Pods.

###options

default : scan Nodes, Services, Vulnerabilites
--details : scan all Kubernetes Components (Pods, Nodes, Services) and Vulnerabilities
--token TOKEN : scan all Kubernetes Components (Pods, Nodes, Services) and Vulnerabilities
  > If you haven't modified service account file or don't know your token,
  > you can insert  --token default
  
--service ACCOUNT : scan all Kubernetes Components (Pods, Nodes, Services) and Vulnerabilities
  > If you haven't modified service account file or don't know your service account,
  > you can insert  --service default
  
If you're running docker, You can scan your containers, Vulnerabilites 
--docker : scan docker containers and Vulnerabilities


##What Vulnerabilities? 

###Kubernetes >>

CVE-2019-9946
CVE-2019-11243
CVE-2019-11244
CVE-2019-1002100
CVE-2019-1002101
CVE-2018-1002100
CVE-2018-1002101
CVE-2018-1002105


More information about Kubernetes Vulnerabilities 
https://www.cvedetails.com/vulnerability-list/vendor_id-15867/product_id-34016/Kubernetes-Kubernetes.html



###Docker >>

CVE-2017-7308
CVE-2019-5736
CVE-2018-15664
CVE-2018-15514


More information about Docker Vulnerabilities
https://www.cvedetails.com/vulnerability-list/vendor_id-13534/product_id-28125/Docker-Docker.html

We are Good-Hot-Six
