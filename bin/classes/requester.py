'''
Handles all interactions with the VMWare VCD Environment
'''

import requests
#from requests.packages.urllib3.exceptions import InsecureRequestWarning
import xmltodict
import base64
from pprint import pprint
import json
import sys


class Requester():
    def __init__(self):
        super(Requester, self).__init__()

    def get(self, endpoint=None, headers=None):
        if endpoint is None:
            return {'status': False, 'reason': 'No Endpoint provided'}
        return requests.get(endpoint, headers=headers)

    def post(self, endpoint=None, headers=None, body=None):
        if endpoint is None:
            return {'status': False, 'reason': 'No Endpoint provided'}
        try:
            data = body.decode("utf-8")
        except:
            data = body

        return requests.post(endpoint, headers=headers, data=data)

    def put(self, endpoint=None, headers=None, body=None):
        if endpoint is None:
            return {'status': False, 'reason': 'No Endpoint provided'}
        try:
            data = body.decode("utf-8")
        except:
            data = body
        return requests.put(endpoint, headers=headers, data=data)
