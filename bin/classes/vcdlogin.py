'''
Handles all interactions with the VMWare VCD Environment
'''

#from sqlite3.dbapi2 import DatabaseError
#import requests
#from requests.api import post
#from requests.packages.urllib3.exceptions import InsecureRequestWarning
from classes.requester import Requester
import xmltodict
import base64
from pprint import pprint
import json
#import sys


class VcdLogin:
    def __init__(self, host):
        self.host = host
        self.endpoint = "https://{}/api/".format(host)
        self.requests = Requester(
            disable_warnings=True, verify_ssl_certs=False)

    def login(self, user, password):
        # requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        api_login_endpoint, api_version = self.__set_login_and_version__()
        return_login_dict = dict()
        if api_login_endpoint is not None:
            auth = "{}:{}".format(user, password)
            encoded_auth = str(base64.b64encode(auth.encode()))
            encoded_auth = encoded_auth[2:]
            encoded_auth = encoded_auth[:-1]
            headers = dict()
            headers['Authorization'] = "Basic {}".format(encoded_auth)
            headers['Accept'] = "application/*+xml;version={}".format(
                api_version)
            login = self.requests.post(
                endpoint=api_login_endpoint, headers=headers, body=None)

            return_text_dict = dict()
            return_text_dict['version'] = api_version
            return_text_dict['endpoint'] = self.endpoint

            return_login_dict['status_code'] = login.status_code
            return_login_dict['headers'] = login.headers
            return_login_dict['headers'].pop('Content-Length')
            return_login_dict['headers']['Content-Type'] = 'text/json'
            return_login_dict['text'] = json.dumps(return_text_dict)
        else:
            return_login_dict['status_code'] = 400
            return_login_dict['headers'] = dict()
            return_login_dict['text'] = 'Unable to determine VCD Login URL'

        return return_login_dict

    def __set_login_and_version__(self):
        api_login_endpoint = None
        api_version = 0

        data = self.requests.get(endpoint="{}versions".format(self.endpoint))
        if data.status_code <= 299:
            supported_versions = self.__convert_to_dict__(
                content_type=data.headers['Content-Type'], content=data.text)

            for versions in supported_versions['SupportedVersions']['VersionInfo']:
                if versions['@deprecated'] == 'false':
                    proposed_api_version = float(versions['Version'])
                    if proposed_api_version > api_version:
                        api_version = proposed_api_version
                        api_login_endpoint = versions['LoginUrl']
        return api_login_endpoint, api_version

    def __convert_to_dict__(self, content_type=None, content=None):

        if content is None:
            return {}
        try:
            data = content.decode("utf-8")
        except:
            data = content

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
