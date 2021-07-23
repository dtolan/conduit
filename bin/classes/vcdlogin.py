'''
Handles all interactions with the VMWare VCD Environment
'''

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import xmltodict
import base64
from pprint import pprint
import json
import sys


class VcdLogin:
    def __init__(self, host, user, password):
        self.host = host
        self.user = user
        self.password = password
        self.disable_warnings = True
        self.verify_ssl_certs = False
        self.headers = dict()
        self.endpoint = "https://{}/api/".format(host)

    def login(self):
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        login_url, version = self.__set_login_and_version__()
        auth = "{}:{}".format(self.user, self.password)
        encoded_auth = str(base64.b64encode(auth.encode()))
        encoded_auth = encoded_auth[2:]
        encoded_auth = encoded_auth[:-1]
        self.headers = dict()
        self.headers['Authorization'] = "Basic {}".format(encoded_auth)
        self.headers['Accept'] = "application/*+xml;version={}".format(
            self.api_version)
        data = self.post(login_url, {})
        if data['status']:
            self.headers['Authorization'] = "Bearer {}".format(
                data['headers']['X-VMWARE-VCLOUD-ACCESS-TOKEN'])
        else:
            print("Error: Unable to perform login (post)")
            return False
        pprint(self.headers)

    def __set_login_and_version__(self):
        url = "{}versions".format(self.endpoint)
        supported_versions = self.get(url)
        version = 0
        login_url = ''
        if supported_versions['status']:
            for versions in supported_versions['data']['SupportedVersions']['VersionInfo']:
                if versions['@deprecated'] == 'false':
                    test_version = float(versions['Version'])
                    if test_version > version:
                        version = test_version
                        login_url = versions['LoginUrl']
        if version > 0:
            self.api_version = str(version)
        return login_url, version

    def __convert_to_dict__(self, content_type=None, content=None):

        if content is None:
            return {}
        try:
            data = content.decode("utf-8")
        except:
            data = content
        return_data = dict()
        result = None
        results = data.replace('ns2:', '')
        results = results.replace('ns5:', '')
        if content_type == 'text/xml' or ('application' in content_type and '+xml' in content_type):
            try:
                result = xmltodict.parse(results)
            except:
                pass
        elif 'json' in content_type:
            try:
                result = json.loads(results)
            except:
                pass

        if result is not None:
            return result
        else:
            return dict()

    def get(self, endpoint):

        if endpoint is None:
            return {'status': False, 'reason': 'No Endpoint provided'}
        p = requests.get(endpoint, headers=self.headers,
                         verify=self.verify_ssl_certs)
        return_data = dict()
        return_data['status_code'] = p.status_code
        return_data['headers'] = p.headers
        return_data['raw'] = p.content

        if int(p.status_code) < 300:
            return_data['status'] = True
        else:
            return_data['status'] = False

        content_type = p.headers['Content-Type']

        return_data['data'] = self.__convert_to_dict__(
            content_type=content_type, content=p.content)
        return return_data

    def post(self, endpoint, data):
        if endpoint is None:
            return {'status': False, 'reason': 'No Endpoint provided'}

        p = requests.post(endpoint, data=data,
                          headers=self.headers, verify=self.verify_ssl_certs)
        return_data = dict()
        return_data['status_code'] = p.status_code
        return_data['headers'] = p.headers
        return_data['raw'] = p.content
        if int(p.status_code) < 300:
            return_data['status'] = True
        else:
            return_data['status'] = False
            data = dict()
            return return_data
        if 'Content-Type' in p.headers:
            content_type = p.headers['Content-Type']
            return_data['data'] = self.__convert_to_dict__(
                content_type=content_type, content=p.content)
        else:
            return_data['data'] = {}

        return return_data
