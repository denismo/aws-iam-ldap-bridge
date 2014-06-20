__author__ = 'Denis Mikhalkin'

import syslog
import ldap
import configparser

def pam_sm_authenticate(pamh, flags, argv):
    parser = configparser.ConfigParser()
    parser.read("/etc/aws_iam_ldap.conf")
    zone=parser.get("default","baseZone")

    dn="uid=%s,%s" % (pamh.user, zone)
    con = ldap.initialize(parser.get("default", "uri"))
    try:
        con.simple_bind(dn, pamh.authtok)
        res = con.search_s(dn, ldap.SCOPE_BASE, "(&(objectclass=posixaccount)(uid=%s))" % pamh.user, ["accessKey"], False)
        pamh.env['AWS_ACCESS_KEY_ID'] = res[0][1]['accessKey'][0]
        pamh.env['AWS_SECRET_ACCESS_KEY'] = pamh.authtok
        return pamh.PAM_SUCCESS
    except:
        return pamh.PAM_AUTH_ERR
    finally:
        con.unbind()

def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS

def pam_sm_acct_mgmt(pamh, flags, argv):
    return pamh.PAM_SUCCESS

def pam_sm_open_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS

def pam_sm_close_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS

def pam_sm_chauthtok(pamh, flags, argv):
    return pamh.PAM_SUCCESS
