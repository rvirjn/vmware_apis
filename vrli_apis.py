# Description: Contain vrli with vSphere integration administration related api
# Group-physical-st: optional
# Timeout: 24000

import traceback
import json
from restutil import RestUtil

__author__ = 'raviranjan'

vrli_ip, vrli_username, vrli_password = "", '', ''
vrops_ip, vrops_user, vrops_password = "", '', ''
nsxt_ip, nsxt_user, nsxt_pwd = '', '', ''
vc_ip, vc_user, vc_pwd = "", '', ""


VSPHERE = "https://{ip}/api/v1/vsphere"
VROPS = "https://{ip}/api/v1/vrops"
VSPHERE_TESTCONNECTION = "https://{ip}/api/v1/vsphere/testconnection"
VROPS_TESTCONNECTION = "https://{ip}/api/v1/vrops/testconnection"

sessionId = None
VRLI_SESSIONS = ''


class Authentication:
    def __init__(self, vrli_ip, vrli_username, vrli_password):
        """
           All Auth related api calls
           :param vrli_ip: VRLI hostname address only
           :param vrli_username: VRLI user name
           :param vrli_password: VRLI password
        """
        self.vrli_ip, self.vrli_uname, self.vrli_password = \
            vrli_ip, vrli_username, vrli_password
        self.rest = RestUtil()
        self.auth_sessionId = None
        global sessionId
        if not sessionId:
            self.auth_sessionId = self.get_vrli_auth_session(vrli_ip, vrli_username, vrli_password)
            sessionId = self.auth_sessionId
        else:
            self.auth_sessionId = sessionId
        self.headers = {'authorization': "Bearer %s" % self.auth_sessionId}

    def get_vrli_auth_session(self, vrli_ip, vrli_uname, vrli_password):
        """
        Get Authorization sessionId
        :return: Authoriztion ID
        """
        global sessionId
        if sessionId:
            return sessionId
        print('Getting sessionId for authorization')
        url = VRLI_SESSIONS.format(ip=vrli_ip)
        print('POST call to %s Retrieve VRLI auth sessionId' % url)
        payload = {"username": vrli_uname, "password": vrli_password}
        headers = {'content-type': "application/json"}
        print('Payload to get Auth sessionId %s' % json.dumps(payload))
        post_status, auth = None, None
        try:
            response = self.rest.post(url, payload, headers, 200, is_json=True)
            post_status = response.status_code
            root = json.loads(response.text)
            auth = root['sessionId']
            sessionId = auth
        except Exception as e:
            print(traceback.format_exc())
            print('Exception in getting response %s' % e)
        print('sessionId %s' % auth)
        return auth


class Integration(object):
    def __init__(self, vrli_ip, vrli_username, vrli_password):
        """
        :param args: test args
        :param vrli_ip: vrli IP address only
        :param vrli_username: vrli user name
        :param vrli_password: vrli password
        """
        self.vrli_ip, self.vrli_username, self.vrli_password = \
            vrli_ip, vrli_username, vrli_password
        auth_obj = Authentication(self.vrli_ip, self.vrli_username, self.vrli_password)
        self.headers = {'authorization': "Bearer %s" % auth_obj.auth_sessionId}
        self.rest = RestUtil()

    def get_vsphere(self):
        """
        Get all vCenter Server integration configurations
        :return: list vCenterServers
        """
        url = VSPHERE.format(ip=self.vrli_ip)
        print('Get vsphere integration configuration, url : %s' % url)
        get_status = None
        vcenters = None
        try:
            response = self.rest.get(url, headers=self.headers, status_code=200)
            get_status = response.status_code
            print(response.text)
            vcenters = json.loads(response.text)
        except Exception as e:
            print(traceback.format_exc())
            print('get_status: %s ' % get_status)
            print('Exception in getting response %s' % e)
        return vcenters

    def add_vsphere(self, vcenter_hostname, vcenter_username, vcenter_password):
        """
        Add new integration configuration to vCenter Server
        :param vcenter_hostname: vc IP address
        :param vcenter_username: vc user name
        :param vcenter_password: vc password
        :return: response
        """
        url = VSPHERE.format(ip=self.vrli_ip)
        print('post vsphere integration configuration, url : %s' % url)
        post_status = None
        response = None
        try:
            json_payload = {
                "acceptCert": 'true',
                "hostname": vcenter_hostname,
                "username": vcenter_username,
                "password": vcenter_password,
                "syslogProtocol": "UDP",
                "vsphereEventsEnabled": 'true',
                "configureEsxiHostsAutomatically": 'true',
                "target": self.vrli_ip
            }
            response = self.rest.post(url, json_payload, headers=self.headers, status_code=201)
            post_status = response.status_code
            print(
                'Successfully got response object status code: %s' %
                post_status)
            print(response.text)
        except Exception as e:
            print(traceback.format_exc())
            print('post_status: %s ' % post_status)
            print('Exception in getting response %s' % e)
        return response.text

    def test_vsphere_connection(self, vcenter_hostname, vcenter_username, vcenter_password):
        """
        test vCenter Server integration configuration
        :param vcenter_hostname: vc IP address
        :param vcenter_username: vc user name
        :param vcenter_password: vc password
        :return: response
        """
        url = VSPHERE_TESTCONNECTION.format(ip=self.vrli_ip)
        print('post test-connection vsphere integration, url : %s' %
                           url)
        response = None
        post_status = None
        try:
            json_payload = {
                "acceptCert": 'true',
                "hostname": vcenter_hostname,
                "username": vcenter_username,
                "password": vcenter_password,
            }
            response = self.rest.post(url, json_payload, headers=self.headers, status_code=200)
            post_status = response.status_code
            print(post_status)
            print(response.text)
        except Exception as e:
            print(traceback.format_exc())
            print('post_status: %s ' % post_status)
            print('Exception in getting response %s' % e)
        return response.text
    
    def get_vrops(self):
        """
        Get vrops Server integration configurations
        :return: response
        """
        url = VROPS.format(ip=self.vrli_ip)
        print('Get vrops integration configuration, url : %s' % url)
        get_status = None
        response = None
        try:
            response = self.rest.get(url, headers=self.headers, status_code_exception=False)
            get_status = response.status_code
            print(response.text)
            response = json.loads(response.text) if response.text else {}
        except Exception as e:
            print(traceback.format_exc())
            print('get_status: %s ' % get_status)
            print('Exception in getting response %s' % e)
        return response

    def add_vrops(self, vrops_hostname, vrops_username, vrops_password):
        """
        Add vRealize Operations Integration
        :param vrops_hostname: vrops IP address
        :param vrops_username: vrops username
        :param vrops_password: vrops password
        :return: response
        """
        url = VROPS.format(ip=self.vrli_ip)
        print('post vrops integration configuration, url : %s' % url)
        post_status = None
        response = None
        try:
            json_payload = {
                "acceptCert": 'true',
                "hostname": vrops_hostname,
                "username": vrops_username,
                "password": vrops_password,
                "enableAlertsIntegration": 'true',
                "enableLaunchInContext": 'true',
                "pushMetrics": 'true',
                "target": self.vrli_ip
            }
            response = self.rest.post(url, json_payload, headers=self.headers, status_code=201)
            post_status = response.status_code
            print(
                'Successfully got response object status code: %s' %
                post_status)
            print(response.text)
        except Exception as e:
            print(traceback.format_exc())
            print('post_status: %s ' % post_status)
            print('Exception in getting response %s' % e)
        return response.text

    def test_vrops_connection(self, vrops_hostname, vrops_username, vrops_password):
        """
        Test vRealize Operations Integration connection
        :param vrops_hostname: vrops IP address
        :param vrops_username: vrops username
        :param vrops_password: vrops password
        :return: response
        """
        url = VROPS_TESTCONNECTION.format(ip=self.vrli_ip)
        print('post test_connection vrops integration , url : %s' % url)
        post_status = None
        response = None
        try:
            json_payload = {
                "acceptCert": 'true',
                "hostname": vrops_hostname,
                "username": vrops_username,
                "password": vrops_password
            }
            response = self.rest.post(url, json_payload, headers=self.headers, status_code=200)
            post_status = response.status_code
            print(
                'Successfully got response object status code: %s' %
                post_status)
            response = response.text
            print(response)
        except Exception as e:
            print(traceback.format_exc())
            print('post_status: %s ' % post_status)
            print('Exception in getting response %s' % e)
        return response


if __name__ == "__main__":
    obj = Integration(vrli_ip, vrli_username, vrli_password)
    obj.add_vsphere(vc_ip, vc_user, vc_pwd)
    obj.test_vsphere_connection(vc_ip, vc_user, vc_pwd)
    obj.add_vrops(vrops_ip, vrops_user, vrops_password)
    obj.test_vrops_connection(vrops_ip, vrops_user, vrops_password)
