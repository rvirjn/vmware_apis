
from util import Util

__author__ = 'rkottapalli'


class VC(object):
    def __init__(self):
        self. util_obj= Util()
        self.input_arg = self.util_obj.get_sys_argsv_in_dict()
        print(self.input_arg)


    def deploy_vc(self):
        self.input_arg['file_path'] = 'interop/setup/install/install_vc.py'
        status = self.util_obj.execute_rst(self.input_arg)
        print(status)
        return status

    def configure_vc(self):
        self.input_arg['file_path'] = 'interop/setup/configure/vc_initial_configuration.py'
        status = self.util_obj.execute_rst(self.input_arg)
        print(status)
        return status


if __name__ == "__main__":
    vc_obj = VC()
    vc_obj.deploy_vc()


"""
How to Run
-------------
python3 deploy_vc.py

Mandatory args
-------------
-x buildnumber=xx
-x VCENTER_BUILD= -x VCENTER_BUILDTYPE=
-x bringup-json=jsons/bringup.json
-x interarc-setup-mgmt-json=jsons/setup_details.json
-x linux_jump=xx
-x linux_jump_username=xx
-x linux_jump_password=xx

 
optional args
----------------
-x buildtype=xx
-x iso_mount_dir_path=xx
-x skip-vm-deployment=
-x skip-configuration=
-x skip-vsan=
-x skip-nfs=

-x workload_json=

Example: python3 deploy_vc.py -x buildnumber=20395099 -x bringup-json=/dbc/jsons/bringup.json -x interarc-setup-mgmt-json=/dbc/sons/setup_details.json
"""