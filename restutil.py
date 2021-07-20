# Description: REST utility functions for EvoRack
# Disabled: True

import http.client
import json
import logging
import os
import re
import time
import socket

import requests
from requests.exceptions import HTTPError
from requests.exceptions import ReadTimeout
from requests.packages.urllib3.exceptions import InsecureRequestWarning

TIMEOUT_3_MINUTES=180

__author__ = 'raviranjan'


current_file_path = os.path.dirname(__file__)
if not current_file_path:
    # Executing from current folder
    current_file_path = '.'
base_folder_path = current_file_path.split('utils')[0]


class RestUtil(object):
    def __init__(self, verbose_level=0):
        """
        REST utility class
        :param args: test args
        :param verbose_level: Verbose level of logging, default False
        :type verbose_level: int
        :return:
        """
        self.cookie = None
        # Disable warning
        # ssl_.py:90: InsecurePlatformWarning: A true SSLContext object
        # is not available.
        requests.packages.urllib3.disable_warnings()
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        if verbose_level:
            # FIXME: Currently prints in console, redirect it to log file
            http.client.HTTPConnection.debuglevel = verbose_level
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True

    def get(self, url, headers=None, status_code=200,
            status_code_exception=True, timeout=300, log_text=True, **kwargs):
        """
        Wrapper for python requests module get function
        :param url: URL to get
        :type url: str
        :param headers: Headers to be used during get
        :type headers: dict
        :param status_code: Status code expected from server
        :type status_code: int
        :param status_code_exception: Raise status code exception if set to True
        when the request status code does not match with provided status code
        :type status_code_exception: bool
        :param timeout: Timeout after which terminate the request, if it
        still waits
        :type timeout: int
        :param log_text: Log the data
        :type log_text: bool
        :param kwargs: Keyword based args
        :return: Request object that's returned by request get function
        """
        # Get token based auth for VCF Public APIs
        if not headers:
            headers = {}
        print('URL GET: %s' % url)
        print('Headers: %s' % headers)
        print('KW Args: %s' % kwargs)
        i = 0
        while True:
            try:
                # Keep track of APIs used
                req = requests.get(url, verify=False, proxies={},
                                   headers=headers, timeout=timeout, **kwargs)
                if log_text:
                    print(req.text)
                if status_code_exception and req.status_code != status_code:
                    # Raising HTTPError for Server Errors
                    if 500 <= req.status_code < 600:
                        req.raise_for_status()
                break
            except requests.exceptions.SSLError as ex:
                print(ex)
                print('URL before: %s' % url)
                url = re.sub('https://', 'http://', url)
                print('URL after: %s' % url)
                i += 1
                if i >= 3:
                    raise
            except (requests.ConnectionError, ReadTimeout,
                    requests.TooManyRedirects, requests.Timeout,
                    HTTPError) as ex:
                i += 1
                if i >= 10:
                    raise
                print('Request GET retry {}/9: {}'.format(i, ex))
                protocol, host_port, req_str = self.split_url(url)
                hostname = host_port.split(':')[0]
                self.is_host_reachable(hostname, TIMEOUT_3_MINUTES)
        else:
            raise AssertionError('GET request failed')
        print('Reason: %s' % req.reason)
        if log_text:
            print('Headers: %s' % str(headers))
        print('Status code: %s' % req.status_code)
        if status_code_exception and req.status_code != status_code:
            print('Text: %s' % req.text)
            raise AssertionError('Reason %s Text: %s' % (req.reason, req.text))
        return req

    def put(self, url, data, headers=None, status_code=200, is_json=True,
            status_code_exception=True, timeout=300, log_text=True, **kwargs):
        """
        Wrapper for python requests module put function
        :param url: URL to put
        :type url: str
        :param data: Data to be sent to server, default dict, could be string as
        well.If string modify is_json argument to False when calling this method
        :param headers: Headers to be used during put
        :type headers: dict
        :param status_code: Status code expected from server
        :type status_code: int
        :param is_json: Is the data sent to server is JSON ? Default True
        :type is_json: bool
        :param status_code_exception: Raise status code exception if set to True
        when the request status code does not match with provided status code
        :type status_code_exception: bool
        :param timeout: Timeout after which terminate the request, if it
        still waits
        :type timeout: int
        :param log_text: Log the data
        :type log_text: bool
        :param kwargs: Keyword based args
        :return: Request object that's returned by request put function
        """
        # Get token based auth for VCF Public APIs
        if not headers:
            headers = {}
        print('URL PUT :{}'.format(url))
        if is_json and data:
            print('JSON put')
            data = json.dumps(data)
            if 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/json'
        if log_text:
            print('Data: %s' % str(data))
        print('Headers: %s' % str(headers))
        print('KW Args: %s' % kwargs)
        i = 0
        while True:
            try:
                req = requests.put(url, data=data, verify=False, proxies={},
                                   headers=headers, timeout=timeout, **kwargs)
                if log_text:
                    print(req.text)
                if status_code_exception and req.status_code != status_code:
                    # Raising HTTPError for Server Errors
                    if 500 <= req.status_code < 600:
                        req.raise_for_status()
                break
            except requests.exceptions.SSLError as ex:
                print(ex)
                print('URL before: %s' % url)
                url = re.sub('https://', 'http://', url)
                print('URL after: %s' % url)
                i += 1
                if i >= 3:
                    raise
            except (requests.ConnectionError, ReadTimeout,
                    requests.TooManyRedirects, requests.Timeout) as ex:
                i += 1
                if i >= 3:
                    raise
                print(ex)
                protocol, host_port, req_str = self.split_url(url)
                hostname = host_port.split(':')[0]
                self.is_host_reachable(hostname, TIMEOUT_3_MINUTES)
        else:
            raise AssertionError('PUT request failed')
        print('Reason: %s' % req.reason)
        print('Status code: %s' % req.status_code)
        if status_code_exception and req.status_code != status_code:
            print('Text: %s' % req.text)
            raise AssertionError('Reason %s Text: %s' % (req.reason, req.text))
        return req

    def post(self, url, data, headers=None, status_code=200, is_json=True,
             status_code_exception=True, timeout=300, log_text=True,
             is_local_account=False, local_account_username=None,
             local_account_password=None, verify_success_status_stream=False, **kwargs):
        """
        Wrapper for python requests module post function
        :param url: URL to post
        :type url: str
        :param data: Data to be sent to server, default dict, could be string as
        well,If string modify is_json argument to False when calling this method
        :param headers: Headers to be used during post
        :type headers: dict
        :param status_code: Status code expected from server
        :type status_code: int
        :param is_json: Is the data sent to server is JSON ? Default True
        :type is_json: bool
        :param status_code_exception: Raise status code exception if set to True
        when the request status code does not match with provided status code
        :type status_code_exception: bool
        :param timeout: Timeout after which terminate the request, if it
        still waits
        :type timeout: int
        :param log_text: Log the data
        :type log_text: bool
        :param kwargs: Keyword based args
        :param is_local_account: Is the token generation based on local account ? Default False
        :param local_account_username: The local account username to generate token Default None
        :param local_account_password: The local account password to generate token Default None
        :param verify_success_status_stream: bool
        :type is_local_account: bool
        :return: Request object that's returned by request post function
        """
        # Get token based auth for VCF Public APIs
        if not headers:
            headers = {}

        print('URL POST: %s' % url)
        if is_json and data:
            data = json.dumps(data)
            if 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/json'
        if log_text:
            print('Data: %s' % str(data))
        print('Headers: %s' % str(headers))
        if kwargs:
            print('KW Args: %s' % kwargs)
        i = 0
        while True:
            try:
                if not data:
                    req = requests.post(url, verify=False, proxies={},
                                        headers=headers,
                                        timeout=timeout, **kwargs)
                else:
                    req = requests.post(url, data=data, verify=False,
                                        proxies={}, headers=headers,
                                        timeout=timeout, **kwargs)
                if log_text:
                    print(req)
                    print(req.text)
                if status_code_exception and req.status_code != status_code:
                    # Raising HTTPError for Server Errors
                    if status_code_exception and (500 <= req.status_code < 600):
                        req.raise_for_status()
                break
            except requests.exceptions.SSLError as ex:
                print(ex)
                print('URL before: %s' % url)
                url = re.sub('https://', 'http://', url)
                print('URL after: %s' % url)
                i += 1
                if i >= 3:
                    raise
            except (requests.ConnectionError, ReadTimeout,
                    requests.TooManyRedirects, requests.Timeout,
                    HTTPError) as ex:
                i += 1
                if i >= 10:
                    raise
                print(ex)
                protocol, host_port, req_str = self.split_url(url)
                hostname = host_port.split(':')[0]
                self.is_host_reachable(hostname, TIMEOUT_3_MINUTES)
        else:
            raise AssertionError('POST request failed')
        if req.reason:
            print('Reason: %s' % req.reason)
        print('Status code: %s' % req.status_code)
        """
        The right response can be anything in the 200 series.
        Same call at times can return multiple values which indicate success.
        """
        print('verify_success_status_stream '
                           'value: %s' % verify_success_status_stream)
        is_post_successful = False
        if verify_success_status_stream:
            if 199 < req.status_code < 300:
                is_post_successful = True
                print(
                    "Status Code falls within the HTTP success status stream -"
                    " Status code: %s" % req.status_code)
        if not is_post_successful:
            if status_code_exception and req.status_code != status_code:
                print(
                    "Status code from request %s does not match expected "
                    "status code %s" % (req.status_code, status_code))
                print('Text: %s' % req.text)
                msg = 'Reason %s Text: %s' % (req.reason, req.text)
                raise AssertionError(msg)
        return req

    def delete(self, url, data=None, headers=None, status_code=200,
               is_json=True, status_code_exception=True, timeout=300,
               log_text=True, **kwargs):
        """
        Wrapper for python requests module delete function
        :param url: URL to delete
        :type url: str
        :param data: Data to be sent to server, default dict, could be string as
        well.If string modify is_json argument to False when calling this method
        :param headers: Headers to be used during post
        :type headers: dict
        :param status_code: Status code expected from server
        :type status_code: int
        :param is_json: Is the data sent to server is JSON ? Default True
        :type is_json: bool
        :param status_code_exception: Raise status code exception if set to True
        when the request status code does not match with provided status code
        :type status_code_exception: bool
        :param timeout: Timeout after which terminate the request, if it
        still waits
        :type timeout: int
        :param log_text: Log the data
        :type log_text: bool
        :param kwargs: Keyword based args
        :return: Request object that's returned by request delete function
        """
        # Get token based auth for VCF Public APIs
        if not headers:
            headers = {}

        print('URL DELETE: %s' % url)
        if is_json and data:
            print('JSON Delete')
            data = json.dumps(data)
            if 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/json'
        if log_text:
            print('Data: %s' % str(data))
        print('Headers: %s' % str(headers))
        i = 0
        while True:
            try:
                if not data:
                    req = requests.delete(url, verify=False, proxies={},
                                          headers=headers, timeout=timeout,
                                          **kwargs)
                else:
                    req = requests.delete(url, data=data, verify=False,
                                          proxies={},
                                          headers=headers, timeout=timeout,
                                          **kwargs)
                if log_text:
                    print(req.text)
                if status_code_exception and req.status_code != status_code:
                    # Raising HTTPError for Server Errors
                    if 500 <= req.status_code < 600 and \
                            req.status_code != status_code:
                        req.raise_for_status()
                break
            except (requests.ConnectionError, ReadTimeout,
                    requests.TooManyRedirects, requests.Timeout) as ex:
                i += 1
                if i >= 3:
                    raise
                print(ex)
                delay = 10 * i
                print(
                    'Retry: %s after %s seconds' % (i, delay))
                time.sleep(delay)
        print('Reason: %s' % req.reason)
        if log_text:
            print('Text: %s' % req.text)
        print('Status code: %s' % req.status_code)
        if status_code_exception and req.status_code != status_code:
            print('Text: %s' % req.text)
            raise AssertionError('Reason %s Text: %s' % (req.reason, req.text))
        return req

    def patch(self, url, data, headers=None, status_code=200, is_json=True,
              status_code_exception=True, timeout=300, log_text=True, **kwargs):
        """
        Wrapper for python requests module patch function
        :param url: URL to patch
        :type url: str
        :param data: Data to be sent to server, default dict, could be string as
        well.If string modify is_json argument to False when calling this method
        :param headers: Headers to be used during patch
        :type headers: dict
        :param status_code: Status code expected from server
        :type status_code: int
        :param is_json: Is the data sent to server is JSON ? Default True
        :type is_json: bool
        :param status_code_exception: Raise status code exception if set to True
        when the request status code does not match with provided status code
        :type status_code_exception: bool
        :param timeout: Timeout after which terminate the request, if it
        still waits
        :type timeout: int
        :param log_text: Log the data
        :type log_text: bool
        :param kwargs: Keyword based args
        :return: Request object that's returned by request patch function
        """
        # Get token based auth for VCF Public APIs
        if not headers:
            headers = {}

        print('URL PATCH: %s' % url)
        if is_json and data:
            print('JSON patch')
            data = json.dumps(data)
            if 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/json'
        if log_text:
            print('Data: %s' % str(data))
        print('Headers: %s' % str(headers))
        i = 0
        while True:
            try:
                if data:
                    req = requests.patch(
                        url, data=data, verify=False, proxies={},
                        headers=headers, timeout=timeout, **kwargs)
                else:
                    req = requests.patch(
                        url, verify=False, proxies={},
                        headers=headers, timeout=timeout, **kwargs)
                if log_text:
                    print(req.text)
                if status_code_exception and req.status_code != status_code:
                    # Raising HTTPError for Server Errors
                    if 500 <= req.status_code < 600:
                        req.raise_for_status()
                break
            except requests.exceptions.SSLError as ex:
                print(ex)
                print('URL before: %s' % url)
                url = re.sub('https://', 'http://', url)
                print('URL after: %s' % url)
                i += 1
                if i >= 3:
                    raise
            except (requests.ConnectionError, ReadTimeout,
                    requests.TooManyRedirects, requests.Timeout) as ex:
                i += 1
                if i >= 3:
                    raise
                print(ex)
                protocol, host_port, req_str = self.split_url(url)
                hostname = host_port.split(':')[0]
                self.is_host_reachable(hostname, TIMEOUT_3_MINUTES)
        else:
            raise AssertionError('PATCH request failed')
        print('Reason: %s' % req.reason)
        if log_text:
            print('Text: %s' % req.text)
        print('Status code: %s' % req.status_code)
        if status_code_exception and req.status_code != status_code:
            print('Text: %s' % req.text)
            raise AssertionError('Reason %s Text: %s' % (req.reason, req.text))
        return req

    def is_host_reachable(self, host, timeout=60, ping_count=4,
                          ping_timeout=100):
        """
        Is host reachable
        :param host: Host to check
        :type host: str
        :param timeout: Time period to wait
        :type timeout: int
        :param ping_count: Ping count, default 4
        :type ping_count: int
        :param ping_timeout: Timeout for ping, default 100
        :type ping_timeout: int
        :return: True if reachable
        :rtype: bool
        """
        origin_hostname = socket.gethostname()
        origin_ip = socket.gethostbyname(origin_hostname)
        print('Ping from {}({}) to hostname: {}'.format(
            origin_hostname, origin_ip, host))
        if not host or host == 'None':
            return False
        elapsed_time = 0
        start_time = time.time()
        while elapsed_time < timeout:
            if self.ping_device(host, ping_count, ping_timeout):
                print("Host %s is reachable." % host)
                return True
            elapsed_time = time.time() - start_time
            msg = "Host %s is unreachable in %s seconds, sleep additional"
            msg += " 10 seconds"
            print(msg % (host, int(elapsed_time)))
            time.sleep(10)
        return False

    def split_url(self, url):
        print(url)
        url_match = re.search("^(https?|ftps?|file?)://(.+?)(/.*)$", url)
        protocol = url_match.group(1)
        host_port = url_match.group(2)
        req_str = url_match.group(3)
        print('%s - %s - %s' % (protocol, host_port, req_str))
        return protocol, host_port, req_str

    def ping_device(self, host, ping_count=4, timeout=100):
        """
        Ping a given device
        :param host: Host ip to ping
        :type host: str
        :param ping_count: How many ping count, default 4
        :type ping_count: int
        :param timeout: Ping timeout, default 100
        :type timeout: int
        :return: True on if host can be reachable, else False
        :rtype: bool
        """
        print('Hostname: %s' % host)
        if not host or host == 'None':
            return False
        import subprocess
        out_process = subprocess.Popen(
            ["/bin/ping", "-c%d" % ping_count, "-w%d" % timeout, host],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = out_process.communicate()
        if stderr:
            print("Ping return code: {} error: {} output:{}".format(
                out_process.returncode, stderr, stdout))
        ping_response = stdout.decode('utf-8')
        print("Ping response is %s" % ping_response)
        if ping_response.find(' 0% packet loss') > 0:
            print("Host %s is reachable" % host)
            return True
        else:
            print("Host %s is not reachable" % host)
            return False