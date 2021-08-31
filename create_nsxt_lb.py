# Description: Contain vrli with vSphere integration administration related api
# Group-physical-st: optional
# Timeout: 24000

import traceback
import json
from restutil import RestUtil

__author__ = 'raviranjan'


nsxt_ip, nsxt_user, nsxt_pwd = '', '', ''
vc_ip, vc_user, vc_pwd = "", '', ""

T0_ROUTER_NAME = 'Automation_T0_Router'
T1_ROUTER_NAME = 'Automation_T1_Router'
NSX_EDGE_CLUSTER_NAME = 'Automation_edge-cluster'
virtual_server_ip_address = '172.17.230.24'
server_pool_vm1_ip_address="172.26.180.24"
server_pool_vm2_ip_address='172.26.184.24'
server_pool_vm3_ip_address='172.26.188.24'
member_port="443"
virtual_server_ip_address_port = '443'
monitor_port='80'
algorithm_type="LEAST_CONNECTION"


class NSXT(object):
    def __init__(self, nsxt_ip, nsxt_user, nsxt_pwd, vc_ip, vc_user, vc_pwd):
        """
        :param args: test args
        :param nsxt_ip: nsxt_ip IP address only
        :param nsxt_user: nsxt_user user name
        :param nsxt_pwd: nsxt_pwd password
        :param vc_ip: vc_ip IP address only
        :param vc_user: vc_user user name
        :param vc_pwd: vc_pwd password
        """
        self.nsxt_ip, self.nsxt_user, self.nsxt_pwd, self.vc_ip, self.vc_user, self.vc_pwd =\
            nsxt_ip, nsxt_user, nsxt_pwd, vc_ip, vc_user, vc_pwd
        self.rest = RestUtil()
        self.headers = {'Content-Type': 'application/json'}

    def get_edge_cluster_id_by_name(self, ec_name='nsx_Edge_Cluster_Name', site_id='default',
            enforcement_id='default'):
        """
        :param ec_name:
        :return:
        """
        print("edge_cluster id of cluster: %s" % ec_name)
        EDGE_CLUSTERS = 'https://{ip}/policy/api/v1/infra/sites/{' \
                        'site_id}/enforcement-points/{enforcement_id}/edge-clusters'
        url = EDGE_CLUSTERS.format(
            ip=self.nsxt_ip, site_id=site_id, enforcement_id=enforcement_id)
        print('Starting GET call to Retrieve information'
                           ' about specific edge clusters : %s' % url)
        get_status = None
        try:
            response = self.rest.get(
                url, headers=self.headers, auth=(
                    self.nsxt_user, self.nsxt_pwd))
            get_status = response.status_code
            child = json.loads(response.text)
            print("Response %s" % child)
            for cluster in child['results']:
                if ec_name == cluster['display_name']:
                    return cluster['id']
        except Exception as e:
            print(traceback.format_exc())
            print('get_status: %s' % get_status)
            print('Excep: in get edge cluster id  by name %s' % e)
        return None
    
    def get_t0_router_id_from_name(self, router_name="Auto_Test_t0"):
        """
        :return: 
        """
        """
        Returns information about a single t0 gateways
        :return: Specified logical Routers response info
        """
        T0_GATEWAYS = "https://{ip}/policy/api/v1/infra/tier-0s"
        url = T0_GATEWAYS.format(ip=self.nsxt_ip)
        print('Starting GET call to Retrieve information'
                           ' about Logical Router : %s' % url)
        t0_id = None
        get_status = None

        try:
            response = self.rest.get(
                url, headers=self.headers, auth=(
                    self.nsxt_user, self.nsxt_pwd))
            get_status = response.status_code
            print(
                'Successfully got response object status code %s' % get_status)
            child = json.loads(response.text)
            for t0 in child['results']:
                if t0['display_name'] == router_name:
                    t0_id = t0['id']
                    return t0_id
        except Exception as e:
            print(traceback.format_exc())
            print('get_status: %s' % get_status)
            print('Exception in get a t0 id from name %s' % e)
        return t0_id
    
    def get_t0_logical_router(self, router_id="Test_T0"):
        """
        Returns information about all logical routers
        :return: Specified logical Routers response info
        """

        # url = T0_GATEWAY.format(ip=self.nsxt_ip, id=router_id)
        T0_GATEWAY = "https://{ip}/policy/api/v1/infra/tier-0s/{id}"
        url = T0_GATEWAY.format(ip=self.nsxt_ip, id=router_id)
        print('Starting GET call to Retrieve information'
                           ' about specified Logical Router : %s' % url)
        get_status = None
        child = None
        try:
            response = self.rest.get(
                url, headers=self.headers, auth=(
                    self.nsxt_user, self.nsxt_pwd))
            get_status = response.status_code
            print(
                'Successfully got response object status code %s' % get_status)
            child = json.loads(response.text)
        except Exception as e:
            print(traceback.format_exc())
            print('get_status: %s' % get_status)
            print('Exception in getting a t0 response %s' % e)
        return child
    
    def get_t1_logical_router(self, router_id="Auto_Test_T1"):
        """
        Returns information about a single t1 gateways
        :return: Specified logical Routers response info
        """
        T1_GATEWAY = "https://{ip}/policy/api/v1/infra/tier-1s/{id}"
        url = T1_GATEWAY.format(ip=self.nsxt_ip, id=router_id)
        print('Starting GET call to Retrieve information'
                           ' about specified Logical Router : %s' % url)
        get_status = None
        child = None
        try:
            response = self.rest.get(
                url, headers=self.headers, auth=(
                    self.nsxt_user, self.nsxt_pwd))
            get_status = response.status_code
            print(
                'Successfully got response object status code %s' % get_status)
            child = json.loads(response.text)
        except Exception as e:
            print(traceback.format_exc())
            print('get_status: %s' % get_status)
            print('Exception in get a t1 %s' % e)
        return child

    def get_t1_router_id_from_name(self, router_name="Auto_Test_T1"):
        """
        Returns information about a single t1 gateways
        :return: Specified logical Routers response info
        """
        T1_GATEWAYS = "https://{ip}/policy/api/v1/infra/tier-1s"
        url = T1_GATEWAYS.format(ip=self.nsxt_ip)
        print('Starting GET call to Retrieve information'
                           ' about Logical Router : %s' % url)
        t1_id = None
        get_status = None

        try:
            response = self.rest.get(
                url, headers=self.headers, auth=(
                    self.nsxt_user, self.nsxt_pwd))
            get_status = response.status_code
            print(
                'Successfully got response object status code %s' % get_status)
            child = json.loads(response.text)
            for t1 in child['results']:
                if t1['display_name'] == router_name:
                    t1_id = t1['id']
                    print("Found router id %s" % t1_id)
                    return t1_id
        except Exception as e:
            print(traceback.format_exc())
            print('get_status: %s' % get_status)
            print('Exception in get a t1 id from name %s' % e)
        print("Router %s not found" % router_name)
        return t1_id

    def get_t1_logical_router_path_by_id(self, router_id=None):
        """
        GET T1 logical router path by id
        :return: t1 gateway path in uri format
        """
        t1_info = self.get_t1_logical_router(router_id=router_id)
        t1_path = t1_info.get("path")
        return t1_path
    def create_t1_logical_router(self, display_name="Auto_Test_T1",
                                 t0_router_id=None, edge_cluster_id=None,
                                 preferred_edge_paths=[],
                                 dhcp_server_name=None,
                                 route_advertisement_types=[],
                                 locale_services_name='locale_services_'):
        """
        Creating T1 logical Router
        :param display_name: display_name
        :param t0_router_id: optional T0 router id to be attached with T1
        :param edge_cluster_id: optional edge_cluster_id
        :param route_advertisement_types: [
               "TIER1_STATIC_ROUTES", "TIER1_CONNECTED", "TIER1_NAT",
               "TIER1_LB_VIP", "TIER1_LB_SNAT", "TIER1_DNS_FORWARDER_IP"]
        :return: router id
        """
        post_status = None
        json_payload = {}
        T1_GATEWAYS = "https://{ip}/policy/api/v1/infra/tier-1s"
        T1_GATEWAY = "https://{ip}/policy/api/v1/infra/tier-1s/{id}"
        url = T1_GATEWAYS.format(ip=self.nsxt_ip, id=display_name)
        if t0_router_id:
            t0_router = self.get_t0_logical_router(t0_router_id)
            json_payload["tier0_path"] = t0_router["path"]
        # if dhcp_server_name:
        #     path = []
        #     server_json = self.dhcp_server.get_dhcp_server_from_name(
        #         server_name=dhcp_server_name)
        #     path.append(server_json['path'])
        #     json_payload['dhcp_config_paths'] = path
        json_payload['display_name'] = display_name
        if route_advertisement_types:
            json_payload['route_advertisement_types'] = \
                route_advertisement_types
        print(
            'Starting PUT call to Create a T1 router . %s ' % url)
        print('json_payload %s ' % json_payload)
        try:
            response = self.rest.put(
                url, json_payload, self.headers, 200, auth=(
                    self.nsxt_user, self.nsxt_pwd), is_json=True)
            post_status = response.status_code
            print(
                'Successfully got response object status code: %s' %
                post_status)
            root = json.loads(response.text)
            self.t1_router_id = root['id']
            print('T1 Router id: %s' % self.t1_router_id)
            print('T1 Router id: %s' % self.t1_router_id)
        except Exception as e:
            print(traceback.format_exc())
            print('Exception while creating t1 router %s' % e)
        if self.t1_router_id and edge_cluster_id:
            locale_services_id = \
                self.create_locale_services(
                    router_id=self.t1_router_id,
                    edge_cluster_id=edge_cluster_id,
                    preferred_edge_paths=preferred_edge_paths,
                    locale_services_name=locale_services_name)
            return self.t1_router_id, locale_services_id
        return self.t1_router_id
    
    def create_locale_services(self, router_id=None, router_type="tier-1s",
                               edge_cluster_id=None, preferred_edge_paths=[],
                               locale_services_name=None,
                               route_redistribution_types=[]):
        """
        Create or update a Tier-1 locale-services
        :param display_name: display_name
        :param router_type: tier-0s or tier-1s
        :param edge_cluster_id: edge_cluster_id
        :param preferred_edge_paths: preferred edge paths eg ['abc','def']
        :return: locale service id
        """
        put_status = None
        locale_id = None
        LOCALE_SERVICES = 'https://{ip}/policy/api/v1/infra/{type}/{' \
                          'router_id}/locale-services'
        LOCALE_SERVICE = 'https://{ip}/policy/api/v1/infra/{type}/{' \
                         'router_id}/locale-services/{locale_services_id}'
        url = LOCALE_SERVICE.format(ip=self.nsxt_ip, type=router_type,
                                             router_id=router_id,
                                             locale_services_id=locale_services_name)
        print(
            'Starting PUT call to Create a T0 router . %s ' % url)
        json_payload = {}
        if edge_cluster_id and preferred_edge_paths:
            clus_json = self.get_edge_cluster_by_id(
                edge_cluster_id=edge_cluster_id)
            json_payload['edge_cluster_path'] = clus_json['path']
            json_payload['preferred_edge_paths'] = preferred_edge_paths
        if edge_cluster_id:
            clus_json = self.get_edge_cluster_by_id(
                edge_cluster_id=edge_cluster_id)
            json_payload['edge_cluster_path'] = clus_json['path']
            edges_json = self.list_edges_from_clusters(
                edge_cluster_id=edge_cluster_id)
            path = []
            for edge in edges_json['results']:
                path.append(edge['path'])
            json_payload['preferred_edge_paths'] = path
            # del json_payload['preferred_edge_paths']
        if route_redistribution_types:
            json_payload['route_redistribution_types'] = \
                route_redistribution_types
        try:
            response = self.rest.put(
                url, json_payload, self.headers, 200, auth=(
                    self.nsxt_user, self.nsxt_pwd), is_json=True)
            put_status = response.status_code
            print(
                'Successfully got response object status code: %s' %
                put_status)
            root = json.loads(response.text)
            locale_id = root['id']
            print(root)
            print('locale id: %s' % locale_id)
        except Exception as e:
            print(traceback.format_exc())
            print('Exception while updating router locale '
                                'serices %s' % e)
        return locale_id

    def list_edges_from_clusters(
            self,
            site_id='default',
            enforcement_id='default',
            edge_cluster_id=None):
        """
        Returns information of clusters
        Validate url '/infra/sites/default/enforcement-point/nsx/edge-clusters'
        :return: list of clusters
        """
        EDGE_NODES = 'https://{ip}/policy/api/v1/infra/sites/{' \
                     'site_id}/enforcement-points/{enforcement_id}/edge-clusters/{' \
                     'cluster_id}/edge-nodes'
        url = EDGE_NODES.format(ip=self.nsxt_ip, site_id=site_id,
                                                  enforcement_id=enforcement_id,
                                                  cluster_id=edge_cluster_id)
        print('Starting GET call to Retrieve information'
                           ' about all edge from clusters : %s' % url)
        get_status = None
        root = None
        try:
            response = self.rest.get(
                url, headers=self.headers, auth=(
                    self.nsxt_user, self.nsxt_pwd))
            get_status = response.status_code
            print(
                'Successfully got response object status code %s' % get_status)
            root = json.loads(response.text)
        except Exception as e:
            print(traceback.format_exc())
            print('get_status: %s ' % get_status)
            print('Exception in get all edge clusters %s' % e)
        return root
    
    def get_edge_cluster_by_id(self, edge_cluster_id=None,
                               site_id='default', enforcement_id='default'):
        """
        GET Edge Cluster by id
        :return: edge_cluster response json
        """

        print('edge_cluster id: %s' % edge_cluster_id)
        EDGE_CLUSTER_ID = 'https://{ip}/policy/api/v1/infra/sites/{' \
                          'site_id}/enforcement-points/{enforcement_id}/edge-clusters/{' \
                          'cluster_id}'
        url = EDGE_CLUSTER_ID.format(
            ip=self.nsxt_ip, site_id=site_id, enforcement_id=enforcement_id,
            cluster_id=edge_cluster_id)
        print('Starting GET call to Retrieve information'
                           ' about specific edge clusters : %s' % url)
        get_status = None
        child = None
        try:
            response = self.rest.get(
                url, headers=self.headers, auth=(
                    self.nsxt_user, self.nsxt_pwd))
            get_status = response.status_code
            print(
                'Successfully got response object status code %s' % get_status)
            child = json.loads(response.text)
            print("edge_cluster_id %s Response %s" %
                               (edge_cluster_id, child))
        except Exception as e:
            print(traceback.format_exc())
            print('get_status: %s' % get_status)
            print('Exception in getting edge cluster %s' % e)
        return child
    
    def create_load_balancer_monitor(
            self, profile_name="LB_Test_Monitor", resource_type="LBHttpMonitorProfile",
            monitor_port="80", request_url="/", response_codes=None, interval=5, timeout=5,
            rise_count=3, fall_count=3):
        """

        Creates Load Balancer monitor Profile
        :param profile_name: Profile name
        :type profile_name: str
        :param resource_type: Monitor Resource type enum(LBActiveMonitor, LBHttpMonitorProfile
         LBHttpsMonitorProfile, LBIcmpMonitorProfile, LBPassiveMonitorProfile, LBTcpMonitorProfile,
         LBUdpMonitorProfile)
        :type resource_type: enumerate
        :param monitor_port: Monitor port number
        :type monitor_port: str later to be converted to int
        :param request_url: monitor url
        :type request_url: str
        :param response_codes: server response codes
        :type response_codes: list
        :param interval:
        :type interval:
        :param timeout:
        :type timeout:
        :param rise_count:
        :type rise_count:
        :param fall_count:
        :type fall_count:
        :return: monitor_id and monitor_path
        :rtype: tuple
        """
        LB_MONITOR_PROFILE = "https://{ip}/policy/api/v1/infra/lb-monitor-profiles/{profile_name}"
        url = LB_MONITOR_PROFILE.format(ip=self.nsxt_ip, profile_name=profile_name)
        print('Starting PUT call to create Monitor Profile : %s' % url)
        put_status = None
        response_codes = [200] if not response_codes else response_codes
        json_payload = {
            "request_url": request_url, "response_status_codes": response_codes,
            "resource_type": resource_type, "monitor_port": monitor_port,
            "interval": interval, "timeout": timeout, "rise_count": rise_count,
            "fall_count": fall_count}
        monitor_id = None
        monitor_path = None
        try:
            response = self.rest.put(url, json_payload, self.headers, 200, auth=(
                self.nsxt_user, self.nsxt_pwd), is_json=True)
            put_status = response.status_code
            root = json.loads(response.text)
            monitor_id = root["id"]
            monitor_path = root["path"]
            print("monitor_id:%s | monitor_path:%s" % (
                monitor_id, monitor_path))
        except Exception as e:
            print(traceback.format_exc())
            print('Exception in creating monitor profile %s' % e)
        return monitor_id, monitor_path
    
    def create_http_server_pool(
            self, algorithm_type="ROUND_ROBIN", server_group_path=None,
            vm1_display_name="vm1_display_name", vm1_ip_address="20.20.20.20",
            vm2_display_name="vm2_display_name", vm2_ip_address="21.21.21.21",
            vm3_display_name="vm3_display_name", vm3_ip_address=None, member_port="80",
            monitor_path=None,
            server_pool_name="server_pool_name", min_active_members=1):
        """

        :param algorithm_type: Load Balancer Algorithm Name
        :param server_group_path: group_path of the servers
        :param vm1_display_name: VM1 Display Name
        :param vm1_ip_address: VM1 IP
        :param vm2_display_name: VM2 Display Name
        :param vm2_ip_address: VM2 IP
        :param vm3_display_name: VM3 Display Name
        :param vm3_ip_address: VM3 IP
        :param server_pool_name: Http server pool Name
        :param member_port: all member's port number
        :param monitor_path: monitor_path
        :param min_active_members:  No of Active members in pool
        :return: http_server_pool_id and https_server_pool_path
        """
        HTTP_SERVER_POOL = "https://{ip}/policy/api/v1/infra/lb-pools/{" \
                           "pool_name}"
        url = HTTP_SERVER_POOL.format(ip=self.nsxt_ip,
                                      pool_name=server_pool_name)
        print(
            'Starting PUT call to create HTTP Server POOL : '
            '%s' %
            url)
        put_status = None
        tag_status = False
        if server_group_path is not None:
            json_payload = {
                "algorithm": algorithm_type,
                "member_group": {
                    "group_path": server_group_path,
                    "ip_revision_filter": "IPV4"},
                "snat_translation": {"type": "LBSnatAutoMap"},
                'min_active_members': min_active_members,
                "display_name": server_pool_name}
        else:
            json_payload = {
                "algorithm": algorithm_type,
                "members": [{
                    "port": member_port,
                    "display_name": vm1_display_name,
                    "ip_address": vm1_ip_address
                }, {
                    "port": member_port,
                    "display_name": vm2_display_name,
                    "ip_address": vm2_ip_address
                }],
                "snat_translation": {"type": "LBSnatAutoMap"},
                'min_active_members': min_active_members,
                "display_name": server_pool_name
            }
            if vm3_ip_address:
                json_payload["members"].append({
                    "port": member_port,
                    "display_name": vm3_display_name,
                    "ip_address": vm3_ip_address
                })
            if monitor_path:
                json_payload["active_monitor_paths"] = [monitor_path]
        http_server_pool_id = 'None'
        http_server_pool_path = 'None'
        try:
            response = self.rest.put(
                url,
                json_payload,
                self.headers,
                200,
                auth=(self.nsxt_user, self.nsxt_pwd),
                is_json=True
            )
            put_status = response.status_code
            print(
                'Successfully got response object status code: %s' %
                put_status)
            root = json.loads(response.text)
            http_server_pool_id = root["id"]
            http_server_pool_path = root["path"]
            print("https server id is : {} and http_server_path "
                               "is : {}"
                               .format(http_server_pool_id,
                                       http_server_pool_path))
            tag_status = True
        except Exception as e:
            print(traceback.format_exc())
            print('Exception while Http Server Pool %s'
                                % e)
        return http_server_pool_id, http_server_pool_path
    
    def create_load_balancer_service(
            self,
            display_name='LoadBalancerService',
            size="SMALL",
            tier1_router_path='None'):
        """
        :param self:
        :param display_name: LB service name
        :param size: LB Serverice size
        :param tier1_router_path: T1 Router Path
        :return: lb_service_id and lb_Service_path
        """
        CREATE_LB = "https://{ip}/policy/api/v1/infra/lb-services/{" \
                    "service_name}"
        url = CREATE_LB.format(ip=self.nsxt_ip, service_name=display_name)
        print('Starting Put call to create new Edge node : %s'
                           % url)
        put_status = None
        tag_status = False
        lb_service_id = 'None'
        lb_service_path = 'None'
        json_payload = {

            "display_name": display_name,
            "connectivity_path": tier1_router_path,
            "size": size
        }
        try:
            response = self.rest.put(
                url,
                json_payload,
                self.headers,
                200,
                auth=(self.nsxt_user, self.nsxt_pwd),
                is_json=True
            )
            put_status = response.status_code
            print(
                'Successfully got response object status code: %s' %
                put_status)
            root = json.loads(response.text)
            lb_service_id = root["id"]
            lb_service_path = root["path"]
            print("lb service id is : {} and lb_service_path "
                               "is : {}"
                               .format(lb_service_id, lb_service_path))
            tag_status = True
        except Exception as e:
            print(traceback.format_exc())
            print('Exception while Load Balancer Service %s'
                                % e)
        return lb_service_id, lb_service_path
    
    def create_load_balancer_virtual_server(
            self,
            ip_address='10.10.10.10',
            display_name='lb_virtual_server',
            pool_path=None,
            lb_service_path=None,
            port="80"
    ):
        """

       :param ip_address: LB Server IP
       :param display_name: LB Server Name
       :param pool_path: Server Pool Path
       :param lb_service_path: LB service path
       :param port: Service Port number
       :return: virtual_server_id
       """
        LB_VIRTUAL_SERVER = "https://{ip}/policy/api/v1/infra/" \
                            "lb-virtual-servers/{server_name}"
        url = LB_VIRTUAL_SERVER.format(ip=self.nsxt_ip,
                                       server_name=display_name)
        print(
            'Starting PUT call to create new Load Balancer Virtual Server : '
            '%s' %
            url)
        put_status = None
        tag_status = False
        json_payload = {
            "ip_address": ip_address,
            "ports": [port],
            "display_name": display_name,
            "pool_path": pool_path,
            "application_profile_path": "/infra/lb-app-profiles"
                                        "/default-tcp-lb-app-profile",
            "default_pool_member_ports": [port],
            "lb_service_path": lb_service_path
        }
        virtual_server_id = None
        try:
            response = self.rest.put(
                url,
                json_payload,
                self.headers,
                200,
                auth=(self.nsxt_user, self.nsxt_pwd),
                is_json=True)
            put_status = response.status_code
            print(
                'Successfully got response object status code: %s' %
                put_status)
            root = json.loads(response.text)
            virtual_server_id = root['id']
            tag_status = True
        except Exception as e:
            print(traceback.format_exc())
            print(
                'Exception while creating Load Balancer Virtual Server %s' %
                e)
        return virtual_server_id


if __name__ == "__main__":
    obj = NSXT(nsxt_ip, nsxt_user, nsxt_pwd, vc_ip, vc_user, vc_pwd)
    ec_id = obj.get_edge_cluster_id_by_name(ec_name=NSX_EDGE_CLUSTER_NAME)
    t0_id = obj.get_t0_router_id_from_name(router_name=T0_ROUTER_NAME)
    t1_id = obj.create_t1_logical_router(display_name=T1_ROUTER_NAME, t0_router_id=t0_id, edge_cluster_id=ec_id)
    t1_path = obj.get_t1_logical_router_path_by_id(router_id=t1_id)
    obj.create_load_balancer_monitor(monitor_port=monitor_port)
    http_server_pool_id, http_server_pool_path = obj.create_http_server_pool(algorithm_type=algorithm_type,
                                vm1_ip_address=server_pool_vm1_ip_address,
                                vm2_ip_address=server_pool_vm1_ip_address,
                                vm3_ip_address=server_pool_vm1_ip_address,
                                member_port=member_port)
    lb_service_id, lb_service_path = obj.create_load_balancer_service(tier1_router_path=t1_path)
    obj.create_load_balancer_virtual_server(ip_address=virtual_server_ip_address, port=virtual_server_ip_address_port, pool_path=http_server_pool_path, lb_service_path=lb_service_path)
