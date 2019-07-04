# doky

<h2>If you're running Docker, Kubernetes and both,</br> 
  You can scan your Nodes, Services, Vulnerabilities even Pods.</h2>

<h3>options</h3>

default : scan Nodes, Services, Vulnerabilites

__--details__ : scan all Kubernetes Components (Pods, Nodes, Services) and Vulnerabilities</br> 
__--token TOKEN__ : scan all Kubernetes Components (Pods, Nodes, Services) and Vulnerabilities using token</br> 
                   </br> _This option can also be scanned from the Worker Node_</br> 
  > If you haven't modified service account file or don't know your token,
  > you can insert  __--token default__
  
__--service ACCOUNT__ : scan all Kubernetes Components (Pods, Nodes, Services) and Vulnerabilities using service account</br> 
                        _This option can also be scanned from the Worker Node_</br>  
  > If you haven't modified service account file or don't know your service account,
  > you can insert  __--service default__
  
__--proxy PORT__ : scan all Kubernetes Components (Pods, Nodes, Services) and Vulnerabilities locally using proxy
  > You have to specify the port you want to access the Api Server
  
__--docker__ : scan docker containers and Vulnerabilities only for docker

</br>
<h3>You can see the result of scan on this site</h3>
>> http://hotsix.kro.kr/index.php
</br>
</br>

<h2>What Vulnerabilities?</h2>
</br>
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
</br>
CVE-2017-7308</br> 
CVE-2019-5736</br> 
CVE-2018-15664</br> 
CVE-2018-15514</br> 

</br> 
More information about Docker Vulnerabilities </br> 

https://www.cvedetails.com/vulnerability-list/vendor_id-13534/product_id-28125/Docker-Docker.html

<h1>We are Good-Hot-Six</h1>
