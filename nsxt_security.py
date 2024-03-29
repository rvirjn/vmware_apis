
from restutil import RestUtil
import json
import traceback

__author__ = 'raviranjan'


def get_sys_args_in_dict():
    from collections import OrderedDict
    import sys
    sys_args = OrderedDict()
    usr_command = " ".join(sys.argv)
    usr_command = usr_command.split('.py')[1]
    print("parse sys_args:%s" % usr_command)
    keys_values = usr_command.split('-x ')
    for key_value in keys_values:
        if not str(key_value).strip():
            continue
        k_v = key_value.split('=')
        if len(k_v) > 1:
            key, value = k_v[0], k_v[1]
            sys_args[key.strip()] = value.strip()
        else:
            print("%s does not have = to split" % key_value)
    return sys_args


class NSXT(object):
    def __init__(self, ip, user, password):
        self.rest = RestUtil()
        self.ip, self.user, self.password = ip,  user, password
        self.headers = {'Content-Type': 'application/json'}
        print(sys_args)

    # 1. Connect to NSXT VIP or NSXT version
    def get_nsx_version(self):
        url = 'https://%s/api/v1/node/version' % self.ip
        data = {}
        output = None
        status_code = None
        try:
            response = self.rest.get(url, headers=self.headers, auth=(self.user, self.password), log_text=False)
            status_code = response.status_code
            result = json.loads(response.text)
            # print("result %s" % result)
            output = result['product_version']
        except Exception as e:
            print(traceback.format_exc())
            print('status code: %s' % status_code)
            print('Exception %s' % e)
        return output

    # 2. get firewall
    def get_firewall(self, section_id=None):
        url = 'https://%s/api/v1/firewall/sections/%s/rules' % (self.ip, section_id)
        data = {}
        output = []
        status_code = None
        try:
            response = self.rest.get(url, headers=self.headers,auth=(self.user, self.password), log_text=False)
            status_code = response.status_code
            result = json.loads(response.text)
            # print("result %s" % result)
            result = result['results']
            for res in result:
                display_name = res['display_name']
                output.append(display_name)
        except Exception as e:
            print(traceback.format_exc())
            print('status code: %s' % status_code)
            print('Exception %s' % e)
        return output

    #  3. identify policy name: xxx
    def get_policy(self, name="Default Layer3 Section", type="LAYER3"):
        url = 'https://%s/api/v1/firewall/sections?type=%s' % (self.ip, type)
        data = {}
        output = None
        status_code = None
        try:
            response = self.rest.get(url, headers=self.headers,auth=(self.user, self.password), log_text=False)
            status_code = response.status_code
            result = json.loads(response.text)
            # print("result %s" % result)
            result = result['results']
            for res in result:
                display_name = res['display_name']
                if display_name == name:
                    output = res['id']
        except Exception as e:
            print(traceback.format_exc())
            print('status code: %s' % status_code)
            print('Exception %s' % e)
        return output

    #  4. identify source group name (query using user requested ips)
    #  5. identify destination group name (query using user requested ips)
    def get_group(self, ip=None):
        url = 'https://%s/policy/api/v1/infra/domains/default/groups' % self.ip
        data = {}
        output = None
        status_code = None
        try:
            response = self.rest.get(url, headers=self.headers,auth=(self.user, self.password), log_text=False)
            status_code = response.status_code
            result = json.loads(response.text)
            # print("result %s" % result)
            result = result['results']
            for res in result:
                expressions = res.get('expression')
                if expressions:
                    for expression in expressions:
                        ip_addresses = expression.get('ip_addresses')
                        if ip_addresses:
                            for ip_ in ip_addresses:
                                if ip_ == ip:
                                    output = res['display_name']
        except Exception as e:
            print(traceback.format_exc())
            print('status code: %s' % status_code)
            print('Exception %s' % e)
        return output

    #  6. identify destination group name (query using user requested ips)
    def get_service_group(self, port=None):
        url = 'https://%s/policy/api/v1/infra/services' % self.ip
        data = {}
        output = None
        status_code = None
        try:
            response = self.rest.get(url, headers=self.headers,auth=(self.user,self.password),log_text=False)
            status_code = response.status_code
            result = json.loads(response.text)
            # print("result %s" % result)
            result = result['results']
            for res in result:
                service_entries = res['service_entries']
                for service in service_entries:
                    destination_ports = service.get('destination_ports')
                    if destination_ports:
                        for destination_port in destination_ports:
                            if destination_port == port:
                                output = res['display_name']
                    source_ports = service.get('source_ports')
                    if source_ports:
                        for source_port in source_ports:
                            if source_port == port:
                                output = res['display_name']
        except Exception as e:
            print(traceback.format_exc())
            print('status code: %s' % status_code)
            print('Exception %s' % e)
        return output

    #  7. Apply to a given to segment
    def get_segment(self):
        url = 'https://%s/policy/api/v1/infra/segments' % self.ip
        data = {}
        output = []
        status_code = None
        try:
            response = self.rest.get(url, headers=self.headers,auth=(self.user, self.password), log_text=False)
            status_code = response.status_code
            result = json.loads(response.text)
            # print("result %s" % result)
            result = result['results']
            for res in result:
                display_name = res['display_name']
                output.append(display_name)
        except Exception as e:
            print(traceback.format_exc())
            print('status code: %s' % status_code)
            print('Exception %s' % e)
        return output


if __name__ == "__main__":
    sys_args = get_sys_args_in_dict()
    nsx = NSXT(sys_args['ip'], sys_args['user'], sys_args['password'])

    version = nsx.get_nsx_version()
    print("1. =============== output: %s" % version)

    section_id = nsx.get_policy(name='Default Layer3 Section')
    print("3. =============== output: %s" % section_id)

    source_group = nsx.get_group(ip='10.12.3.64/26')
    print("4. =============== output: %s" % source_group)

    dest_group = nsx.get_group(ip='11.12.3.64/26')
    print("5. =============== output: %s" % dest_group)

    port = nsx.get_service_group(port='22')
    print("6. =============== output: %s" % port)

    segments = nsx.get_segment()
    print("7. =============== output: %s" % segments)

    firewall = nsx.get_firewall(section_id)
    print("8. =============== output: %s" % firewall)


"""
How to run

python nsxt_security.py -x ip=wld01-nsx.local -x user=admin -x password=
"""