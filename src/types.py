import logging

class DokyBase(object):
    def pick_point(self, event):
        works.pick_point(event, caller=self)

class Scanner(DokyBase):
    pass

class Detector(DokyBase):
    pass

class Cluster():
    name = "Cluster"

class InformationDisclosure(object):
    name = "Information Disclosure"

class RemoteCodeExec(object):
    name = "Remote code Execution"

class IdentityTheft(object):
    name = "Identity Theft"

class UnauthenticatedAccess(object):
    name = "Unauthenticated Access"

class AccessRisk(object):
    name = "Access Risk"

class PrivilegeEscalation(object):
    name = "Privilege Escalation"

class DenialOfService(object):
    name = "Denial of Service"



from .conf.abcd import works
