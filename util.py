import logging
import sys
from restutil import RestUtil
from collections import OrderedDict
import traceback
import json


def setup_logger(logger_name, log_file, debugmode=True):
    if debugmode:
        level = logging.DEBUG
    else:
        level = logging.INFO
    log_setup = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(asctime)s: %(levelname)s:\t%(module)s:%(lineno)s'
                                  ':: %(funcName)s :: %(message)s',
                                  datefmt='%m/%d/%Y %I:%M:%S %p')
    fileHandler = logging.FileHandler(log_file, mode='a')
    fileHandler.setFormatter(formatter)
    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)
    log_setup.setLevel(level)
    log_setup.addHandler(fileHandler)
    log_setup.addHandler(streamHandler)
    return log_setup


class Util:
    def __init__(self, logger=None):
        if not logger:
            logger = setup_logger('util.py', 'util.log', debugmode=True)
        self.logger = logger
        self.rest = RestUtil()
        self.headers = {'Content-Type': 'application/json'}

    def get_sys_argsv_in_dict(self):
        sys_argsv = OrderedDict()
        sys_args = " ".join(sys.argv)
        sys_args = sys_args.split('.py')[1]
        self.logger.info("parse sys_args:%s" % sys_args)
        keys_values = sys_args.split('-x ')
        for key_value in keys_values:
            self.logger.debug("key_value: %s " % key_value)
            if not str(key_value).strip():
                continue
            k_v = key_value.split('=')
            if len(k_v) > 1:
                key, value = k_v[0], k_v[1]
                sys_argsv[key] = value
            else:
                self.logger.error("%s does not have = to split" % key_value)
        self.logger.debug("Final sys_args %s " % sys_argsv)
        return sys_argsv

    def execute_rst(self, input_arg):
        status = None
        # Bridge : A UF Server which use to trigger VMware automation
        url = 'http://10.199.28.90:4100/cwp/v1/job/ucValidator/validate_input'
        workload_json = input_arg.get('workload_json')
        if workload_json:
            input_arg['workload_json'] = ''
        json_payload = {
            {
                "JOB": {
                    "job_Owner": "avi@vmware.com",
                    "inventory_version": "v2",
                    "job_Tag": "avi_rst",
                    "halt_on_Coredump": "no",
                    "abort_job_on_failure": "yes",
                    "skip_env_prep": "no",
                    "skip_vcheck": "yes",
                    "testbed": {
                        "Product": [
                            "vcenter",
                            "vcf",
                            "nsx"
                        ],
                        "testbed_json": {
                            "bringup_json": "%s" % input_arg.get('bringup-json'),
                            "workload_json": [
                                "%s" % input_arg.get('workload_json'),
                            ],
                            "jump_host": {
                                "linux_jump": {
                                    "ipaddress": input_arg.get('linux_jump'),
                                    "username": input_arg.get('linux_jump_username'),
                                    "password": input_arg.get('linux_jump_password')
                                },
                                "windows_jump": {
                                    "ipaddress": input_arg.get('linux_jump'),
                                    "username": input_arg.get('linux_jump_username'),
                                    "password": input_arg.get('linux_jump_password')
                                }
                            }
                        }
                    },
                    "operations": [
                        {
                            "operation": "MiscExecuteGoatCommand",
                            "product": "misc",
                            "product-identifier": "MGMT",
                            "rst_command": input_arg.get('rst_command')
                        }
                    ]
                }
            }
        }
        try:
            response = self.rest.put(url, json_payload, self.headers, 200, is_json=True)
            put_status = response.status_code
            print(
                'Successfully got response object status code: %s' %
                put_status)
            root = json.loads(response.text)
            status = root['status']
            job_id = root['job_id']
            report_location = root['report_location']
            print(report_location)
        except Exception as e:
            print(traceback.format_exc())
            print(
                'Exception while creating Load Balancer Virtual Server %s' %
                e)
        return status
