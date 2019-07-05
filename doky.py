#!/usr/bin/env python

import logging
import threading
import requests
import argparse

try:
    raw_input
except NameError:
    raw_input = input

loglevel = "DEBUG"
logging.basicConfig(level=logging.DEBUG, format='%(message)s', datefmt='%H:%M:%S')

parser = argparse.ArgumentParser(description='Doky - scans your Docker , also Kubernetes')
parser.add_argument('--details', action='store_true',help="scans the all pods in details")
parser.add_argument('-t','--token', type=str,help="scans on Worker Node using serviceaccount token")
parser.add_argument('-s','--service', type=str,help="scans only in a docker environment")
parser.add_argument('-p','--proxy', type=int, help="access Master API opening available port")
parser.add_argument('--docker', action='store_true', help="scans only in a docker environment")


options = parser.parse_args()

from src.test.kube.printer.kube_printer import RealPrinter

printer = RealPrinter()

from src.conf.abcd import works
from src.conf.objects import DokyPrinter, DokyWorked
from src.test.kube.detector.hosts import HostEvent, AuthScanEvent
from src.test.kube.detector.apiserver import ApiServerDetector
from src.test.kube.detector.ports import PortDetector
from src.test.kube.printer.kube_printer import RealPrinter
from src.test.kube.scanner.apiserver import ApiServerScanner
from src.test.kube.scanner.cvescanner import CVEScanner
from src.test.kube.detector.kube_proxy import ProxyScanEvent
import src


class Email:
    def __init__(self):
        self.email = ''
    def get_email(self):
        return self.email
    def set_email(self,email):
        self.email = email

email = Email()

global doky_lock
doky_lock = threading.Lock()
doky_work = False

def main():
    global doky_work
#    URL = "http://hotsix.kro.kr/re_result.php"
#    intro = "\x1b[1;34m\n\n"
#    intro += "    Dg.     qDi                             iQBBBBi :BB:                   dKDRBdu.              :BB  QBg          BBY\n"
#    intro += "    BBr     BBP             KBv            BBQv7jQv  JJ                    BBBMQBBBBs            .BQ  iU.          72\n"
#    intro += "    BB      BBj    sgBPr   jBBBjr         iBQ        :. ij.    uu          BQ:    .BBu    LRQU.  .BB   ..    LDBgi ...   .2BBK:   .vr   .vr   :IQBP:\n"
#    intro += "    BQQDQQRbBBs  EBBSudBB: DBBBR5          KBBBs     BBi.QB:  BB7          BBr     7BB  SBBiiBBP  BB  BBB  EBBqUEX QBg  BQB1uQBB  DBB   dBB  QBdirgv\n"
#    intro += "    BBRgQQMEBBv LBB    .BB  BBr              rQBQB.  BBi  ZBsBE            BBr     vBB iBBi::UBB  QB  PBB LBB      BQS BBP    1BB jBQ   jBB  BQg.\n"
#    intro += "    BB      BBs gBB     BB  BB7                 vQB  QBi  .QBQi            BB:     BBr 5BB:i7r:i  BB  PBB QBg      BBU BBr    rBB UBB   LBB   :PBBBi\n"
#    intro += "    BBi     BBI  BB7   BBM  BBE           vBr. .DBQ  BQr bBB PBB           BBM7YIBQB7   BBr      .QB  gBB .BBL   : BQE rBB.  .BBr iBB.  BBB  r   BBB\n"
#    intro += "    BB:     BQs   PBBBBBr   :BBBb         .BBBBBBj   BB:JBQ   bBB          QBBBBBgr      PBBBBBv .BB  XBR   EBBBBg QB1  .QBBBQQ.   UBBBXXBB .BBQBBS\n\x1b[1;m"
#    print(intro)
#    print("\x1b[1;34m    ================================================================================================================================================\x1b[1;m")
#    print("\x1b[1;34m    Hi, Kube-Six!\x1b[1;m")
#    print("\x1b[1;34m    Kube-Six scans security weaknesses in Kubernetes clusters!\x1b[1;m")
#    print("\x1b[1;34m    ================================================================================================================================================\n\x1b[1;m")
#    print("\x1b[1;34m    write your email (ex. user@google.com)\x1b[1;m")

#    USER_TOKEN = raw_input("\x1b[1;34m    My Email: \x1b[1;m")
#    if not "@" in USER_TOKEN:
#        USER_TOKEN = USER_TOKEN.split("@")[0]
#        print("check your email form:)")
#        return
#    else:
#        email.set_email(USER_TOKEN)
#        res = requests.post(URL, data={'chk':'0', 'token': USER_TOKEN})
#        if not "1" in res.text:
#            print("\x1b[1;34mThis email already exists.\n Please Try again.\x1b[1;m")
#            return
#        else:
    global doky_work
    all_options = [
            options.details,
            options.token,
            options.proxy,
            options.docker,
            options.service
            ]
    try:
        doky_lock.acquire()
        doky_work = True
        doky_lock.release()
        
        works.pick_point(DokyWorked())
        
        if not any(all_options) or options.details:
            works.pick_point(HostEvent())
            works.join()
        
        if options.docker:
            works.pick_point(DockerEvent())
            works.join()
         
        if options.service or options.token:
            print(options.service)
            print(options.token)
            works.pick_point(AuthScanEvent())
            works.join()
       
        if options.proxy:
            works.pick_point(ProxyScanEvent(options.proxy))
            works.join()

    except KeyboardInterrupt:
        logging.debug("KeyBoard Interrupt")
    finally:
        doky_lock.acquire()
        if doky_work:
            doky_lock.release()
            works.pick_point(DokyPrinter())
            works.join()
            works.free()
        else:
            doky_lock.release()


if __name__ == '__main__':
    main()
