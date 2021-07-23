'''
Handles all interactions with the VMWare VCD Environment
'''

import requests
# from requests.packages.urllib3.exceptions import InsecureRequestWarning
import xmltodict
import base64
from pprint import pprint
import json
import sys


class Salt():
    def __init__(self, mappings=dict()):
        self.mappings = mappings
        self.session = requests.Session()
        self.headersIgnoreList = ['Content-Length']
        self.endpoint = None
        super(Salt, self).__init__()

    def login(self, login_information, destination):
        explodeDestination = destination.split(':')
        mapping = self.mappings

        port = None
        host = None
        protocol = None

        for x in range(len(explodeDestination)):
            mapKey = explodeDestination.pop(0)
            try:
                mapping = mapping[mapKey]
            except:
                mapping = dict()
            if 'host' in mapping:
                host = mapping['host']
            if 'protocol' in mapping:
                protocol = mapping['protocol']
            if 'port' in mapping:
                port = mapping['port']
            if 'defaults' in mapping:
                if 'host' in mapping['defaults']:
                    host = mapping['defaults']['host']
                if 'protocol' in mapping['defaults']:
                    protocol = mapping['defaults']['protocol']
                if 'port' in mapping['defaults']:
                    port = mapping['defaults']['port']
        self.endpoint = "{}://{}".format(protocol, host)
        if port is not None:
            self.endpoint = "{}:{}".format(self.endpoint, port)
        loginUrl = "{}/login".format(self.endpoint)
        self.session.post(loginUrl, json={
            'username': login_information['user'],
            'password': login_information['password'],
            'eauth': 'pam',
        })
        return

    def _array_to_dict(self, response, onlyAlive=True):
        returnDict = dict()
        if 'return' in response:
            for valueDict in response['return']:
                for key in valueDict:
                    if not onlyAlive or (onlyAlive and valueDict[key]):
                        returnDict[key] = valueDict[key]
        return returnDict

    def request(self, body):
        try:
            data = body.decode("utf-8")
        except:
            data = body
        json_data = json.loads(data)
        resp = self.session.post(self.endpoint, json=json_data)
        return resp
