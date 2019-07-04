# doky

<h2>If you're running Docker, Kubernets and both,</br> 
  You can scan your Nodes, Services, Vulnerabilities even Pods.</h2>

<h3>options</h3>

default : scan Nodes, Services, Vulnerabilites

--details : scan all Kubernetes Components (Pods, Nodes, Services) and Vulnerabilities</br> 
--token TOKEN : scan all Kubernetes Components (Pods, Nodes, Services) and Vulnerabilities
  > If you haven't modified service account file or don't know your token,
  > you can insert  --token default
  
--service ACCOUNT : scan all Kubernetes Components (Pods, Nodes, Services) and Vulnerabilities
  > If you haven't modified service account file or don't know your service account,
  > you can insert  --service default
  
--docker : scan docker containers and Vulnerabilities only for docker



<h2>What Vulnerabilities?</h2>

<h3>Kubernetes >></h3>

CVE-2019-9946</br> 
CVE-2019-11243</br> 
CVE-2019-11244</br> 
CVE-2019-1002100</br> 
CVE-2019-1002101</br> 
CVE-2018-1002100</br> 
CVE-2018-1002101</br> 
CVE-2018-1002105</br> 

</br> 
More information about Kubernetes Vulnerabilities </br> 

https://www.cvedetails.com/vulnerability-list/vendor_id-15867/product_id-34016/Kubernetes-Kubernetes.html



<h3>Docker >></h3>

CVE-2017-7308</br> 
CVE-2019-5736</br> 
CVE-2018-15664</br> 
CVE-2018-15514</br> 

</br> 
More information about Docker Vulnerabilities </br> 

https://www.cvedetails.com/vulnerability-list/vendor_id-13534/product_id-28125/Docker-Docker.html

<h1>We are Good-Hot-Six</h1>
