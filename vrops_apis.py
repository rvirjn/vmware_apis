# Description: Contain vrops administration related api
# Group-physical-st: optional
# Timeout: 24000

import traceback
from restutil import RestUtil
import json

__author__ = "raviranjan"


vrops_ip, vrops_user, vrops_password = "", '', ''
nsxt_ip, nsxt_user, nsxt_pwd = '', '', ''
vc_ip, vc_user, vc_pwd = "", '', ""

token = None

LIST_RESOURCES = 'https://{ip}/suite-api/api/adapterkinds/{' \
    'adapterKindKey}/resourcekinds/{resourceKindKey}/resources?page={' \
                 'page}&amp;pageSize={pageSize}'
LIST_ALL_RESOURCES = 'https://{ip}/suite-api/api/adapterkinds/{' \
    'adapterKindKey}/resources'
GET_ADAPTER_KINDS = 'https://{ip}/suite-api/api/adapterkinds'
CREATE_INSTANCE = "https://{ip}/suite-api/api/adapters/"
ADAPTER_KIND = "https://{ip}/suite-api/api/adapterkinds"
TOKEN = 'https://{ip}/suite-api/api/auth/token/acquire'
VALIDATE_TEST_CONNECTION = 'https://{ip}/suite-api/api/adapters/testConnection'
START_COLLECTION = "https://{ip}/suite-api/api/adapters/{adapterId}/monitoringstate/start"


class Authentication:
    def __init__(self, vrops_ip, vrops_username, vrops_password):
        """
           All Auth related api calls
           :param args: test args
           :param vrops_ip: VROPS hostname address only
           :param vrops_username: VROPS user name
           :param vrops_password: VROPS password
        """
        self.vrops_ip, self.vrops_uname, self.vrops_password = vrops_ip, vrops_username, vrops_password
        self.auth_token = None
        self.rest = RestUtil()
        global token
        if not token:
            self.auth_token = self.get_vrops_auth_token(vrops_ip, vrops_username, vrops_password)
            token = self.auth_token
        else:
            self.auth_token = token
        self.headers = {'accept': "application/json",
                        'authorization': "Bearer %s" % self.auth_token,
                        'content-type': "application/json"}

    def get_vrops_auth_token(self, vrops_ip, vrops_uname, vrops_password):
        """
        Get Authorization token
        :return: Authoriztion ID
        """
        global token
        if token:
            return token
        print('Getting token for authorization')
        TOKEN = 'https://{ip}/suite-api/api/auth/token/acquire'
        url = TOKEN.format(ip=vrops_ip)
        print('POST call to %s Retrieve VROPS auth token' % url)
        payload = {"username": vrops_uname, "password": vrops_password}
        headers = {'accept': "application/json",
                   'content-type': "application/json"}
        print('Payload to get AUth token %s' % json.dumps(payload))
        post_status, auth = None, None
        try:
            response = self.rest.post(url, payload, headers, 200, is_json=True)
            post_status = response.status_code
            root = json.loads(response.text)
            auth = root['token']
            token = auth
        except Exception as e:
            print(traceback.format_exc())
            print('Exception in getting response %s' % e)
        print('Token %s' % auth)
        return auth


class Adapter(object):
    def __init__(self, vrops_ip, vrops_admin_username, vrops_admin_password):
        """
        :param vrops_ip: vrops IP address only
        :param vrops_admin_username: vrops Administrator user name
        :param vrops_admin_password: vrops Administrator password
        """
        self.vrops_ip, self.vrops_admin_username, self.vrops_admin_password = \
            vrops_ip, vrops_admin_username, vrops_admin_password
        self.rest = RestUtil()
        self.auth = Authentication(vrops_ip, vrops_admin_username, vrops_admin_password)
        token = self.auth.get_vrops_auth_token(self.vrops_ip, self.vrops_admin_username, self.vrops_admin_password)
        self.headers = {'accept': "application/json",
                        'authorization': "vRealizeOpsToken %s" % token,
                        'content-type': "application/json"}
        self.data = None
        self.instance_id = None

    def add_vc_cloud_account(self, vc_ip, vc_user, vc_pwd, name="VC Adapter Instance",
                             cred_name="VC-Credential-1"):
        """
        Create adapter Instance
        :return: response in json
        """
        """
        Creates configure vc adapter.
        :return: object_id
        """
        url = CREATE_INSTANCE.format(ip=self.vrops_ip)
        print('Creates adapter instance for url:%s' % url)
        post_status = None
        res = None
        try:
            json_data = {
                "name": name,
                "description": "A vCenter Adapter Instance",
                "collectorId": "1",
                "adapterKindKey": "VMWARE",
                "resourceIdentifiers": [
                    {
                        "name": "AUTODISCOVERY",
                        "value": "true"
                    },
                    {
                        "name": "PROCESSCHANGEEVENTS",
                        "value": "true"
                    },
                    {
                        "name": "VCURL",
                        "value": "https://%s/sdk" % vc_ip
                    }
                ],
                "credential": {
                    "id": None,
                    "name": cred_name,
                    "adapterKindKey": "VMWARE",
                    "credentialKindKey": "PRINCIPALCREDENTIAL",
                    "fields": [
                        {
                            "name": "USER",
                            "value": vc_user
                        },
                        {
                            "name": "PASSWORD",
                            "value": vc_pwd
                        }
                    ]
                }
            }
            print(json_data)
            response = self.rest.post(url, headers=self.headers, data=json_data, status_code=201,
                                      is_json=True)
            res = json.loads(response.text)
            # self.data = json.dumps(res)
            self.data = res
            print(response.text)
            post_status = response.status_code
            print('Post call status code %s' % post_status)
            self.instance_id = res['id']
        except Exception as e:
            print(traceback.format_exc())
            print(traceback.format_exc())
            print('Exception in getting response %s' % e)
        return res

    def add_nsxt_cloud_account(self, nsxt_ip, nsxt_user, nsxt_pwd,
                               name="NSXT Adapter Instance",
                               cred_name="NSXT-Credential-1"):
        """
        Create adapter Instance
        :return: response in json
        """
        """
        Creates configure nsxt adapter.
        :return: object_id
        """
        url = CREATE_INSTANCE.format(ip=self.vrops_ip)
        print('Creates adapter instance for url:%s' % url)
        post_status = None
        res = None
        try:
            json_data = {
                "name": name,
                "description": "A NSXT Adapter Instance",
                "collectorId": "1",
                "adapterKindKey": "NSXTAdapter",
                "resourceIdentifiers": [
                    {
                        "name": "NSXTHOST",
                        "value": "%s" % nsxt_ip
                    }
                ],
                "credential": {
                    "id": None,
                    "name": cred_name,
                    "adapterKindKey": "NSXTAdapter",
                    "credentialKindKey": "NSXTCREDENTIAL",
                    "fields": [
                        {
                            "name": "USERNAME",
                            "value": nsxt_user
                        },
                        {
                            "name": "PASSWORD",
                            "value": nsxt_pwd
                        }
                    ]
                }
            }
            print(json_data)
            response = self.rest.post(url, headers=self.headers, data=json_data, status_code=201,
                                      is_json=True)
            res = json.loads(response.text)
            # self.data = json.dumps(res)
            self.data = res
            print(response.text)
            post_status = response.status_code
            print('Post call status code %s' % post_status)
            self.instance_id = res['id']
        except Exception as e:
            print(traceback.format_exc())
            print(traceback.format_exc())
            print('Exception in getting response %s' % e)
        return res

    def accept_certificates(self, data=None):
        """
        Accept adapter certificates
        :return: response in json
        """
        """
         Accept adapter certificates
        :return: object_id
        """
        url = CREATE_INSTANCE.format(ip=self.vrops_ip)
        print('Accept adapter certificates for url:%s' % url)
        patch_status = None
        res = None
        if not data:
            data = self.data
        try:
            response = self.rest.patch(url, headers=self.headers, data=data, status_code=200,
                                       is_json=True)
            print(response.text)
            patch_status = response.status_code
            print('Patch call status code %s' % patch_status)
            res = json.loads(response.text)
            resource_id = res['id']
            print('id:%s' % resource_id)
        except Exception as e:
            print(traceback.format_exc())
            print(traceback.format_exc())
            print('Exception in getting response %s' % e)
        return res

    def test_connection(self, data=None):
        """
        Perform adapter test connection
        :return: response in json
        """
        """
         Perform adapter test connection
        :return: object_id
        """
        url = VALIDATE_TEST_CONNECTION.format(ip=self.vrops_ip)
        print('Perform adapter test connection for url:%s' % url)
        patch_status = None
        res = None
        if not data:
            data = self.data
        try:
            print(data)
            response = self.rest.patch(url, headers=self.headers, data=data, status_code=200,
                                       is_json=True)
            print(response.text)
            patch_status = response.status_code
            print('patch call status code %s' % patch_status)
        except Exception as e:
            print(traceback.format_exc())
            print(traceback.format_exc())
            print('Exception in getting response %s' % e)
        return res

    def start_collection(self, adapter_id):
        """
        Perform adapter test connection
        :return: response in json
        """
        """
         start collection
        :return: object_id
        """
        url = START_COLLECTION.format(ip=self.vrops_ip, adapterId=adapter_id)
        print('Perform START_COLLECTION for url:%s' % url)
        put_status = None
        try:
            json_data = {}
            print(json_data)
            response = self.rest.put(url, headers=self.headers, data=json_data, status_code=200,
                                     is_json=True)
            print(response.text)
            put_status = response.status_code
            print('put call status code %s' % put_status)
        except Exception as e:
            print(traceback.format_exc())
            print(traceback.format_exc())
            print('Exception in getting response %s' % e)

    def get_instance_id(self, instance_name='Interop NSXT Adapter Instance'):
        """
        Returns adapter instance id from a system
        :return: response in json
        """
        url = CREATE_INSTANCE.format(ip=self.vrops_ip)
        print('Returns all the adapter instance resources for url:%s' % url)
        instances_with_id = {}
        get_status = None
        try:
            response = self.rest.get(url, headers=self.headers)
            print(response.text)
            root = json.loads(response.text)
            instances = root['adapterInstancesInfoDto']
            for instance in instances:
                name = instance['resourceKey']['name']
                instances_with_id[name] = instance['id']
            get_status = response.status_code
        except Exception as e:
            print(traceback.format_exc())
            print(traceback.format_exc())
            print('Exception in getting response %s' % e)
        return instances_with_id.get(instance_name, '')


if __name__ == "__main__":
    obj = Adapter(vrops_ip, vrops_user, vrops_password)
    vc_res = obj.add_vc_cloud_account(vc_ip, vc_user, vc_pwd)
    obj.accept_certificates(vc_res)
    obj.start_collection(vc_res['id'])
    nsx_res = obj.add_nsxt_cloud_account(nsxt_ip, nsxt_user, nsxt_pwd)
    obj.start_collection(nsx_res['id'])
