
from util import Util

__author__ = 'raviranjan'


class VC(object):
    def __init__(self):
        self.util_obj = Util()

    def deploy_vc(self):
        input_arg = self.util_obj.get_sys_argsv_in_dict()
        input_arg['rst_command'] = './rst -i interop/setup/install/install_vc.py'
        status = self.util_obj.execute_rst(input_arg)
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
-x bringup-json=xx
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
-x VCENTER_BUILD= -x VCENTER_BUILDTYPE=
-x workload_json=

Example: python3 deploy_vc.py -x buildnumber=20395099
"""