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
from classes.users import Users
from classes.mapping import Mapping


class Parser():
    def __init__(self, mappings=dict(), sqlite=None, crypt=None):
        self.mappings = mappings
        self.users = Users(sqlite)
        self.mapping = Mapping(sqlite)
        self.crypt = crypt
        self.headersIgnoreList = ['Content-Length']
        super(Parser, self).__init__()

    def headers(self, header):
        returnHeaders = dict()
        for h in header.keys():
            if h not in self.headersIgnoreList:
                returnHeaders[h] = header.get(h)
        return returnHeaders

    def mappedValue(self, value, destination):

        explodeDestination = destination.split(':')
        primary_value = explodeDestination.pop(0)
        return_value = None
        if primary_value not in self.mappings:
            return
        mapping = self.mappings[primary_value]

        if value in mapping:
            return_value = mapping[value]

        for x in range(len(explodeDestination)):
            mapKey = explodeDestination.pop(0)
            try:
                mapping = mapping[mapKey]
            except:
                mapping = dict()
            if value in mapping:
                return_value = mapping[value]

        return return_value

    def userMappedValue(self, user, destination):

        explodeDestination = destination.split(':')
        primary_value = explodeDestination[0]
        if primary_value not in self.mappings:
            return
        use_default = False
        if 'use_default' in self.mappings[primary_value]:
            use_default = self.mappings[primary_value]['use_default']
        return_value = dict()
        if use_default:
            default_user_information = self.users.get_user_id_by_name(
                'default')
            if len(default_user_information) == 1:
                default_user_id = default_user_information[0][0]
                all_mappings = self.mapping.get_map(
                    default_user_id, primary_value, '')
                if len(all_mappings) == 1:
                    if len(all_mappings[0][4]) > 0:
                        return_value['token'] = self.crypt.decrypt(
                            all_mappings[0][4])
                    if len(all_mappings[0][5]) > 0:
                        return_value['user'] = self.crypt.decrypt(
                            all_mappings[0][5])
                    if len(all_mappings[0][6]) > 0:
                        return_value['password'] = self.crypt.decrypt(
                            all_mappings[0][6])
        if user is not None:
            user_information = self.users.get_user_id_by_name(user)
            if len(user_information) == 1:
                user_id = user_information[0][0]
                all_mappings = self.mapping.get_map(
                    user_id, primary_value, '')
                if len(all_mappings) == 1:
                    if len(all_mappings[0][4]) > 0:
                        return_value['token'] = self.crypt.decrypt(
                            all_mappings[0][4])
                    if len(all_mappings[0][5]) > 0:
                        return_value['user'] = self.crypt.decrypt(
                            all_mappings[0][5])
                    if len(all_mappings[0][6]) > 0:
                        return_value['password'] = self.crypt.decrypt(
                            all_mappings[0][6])
        return return_value

    def endpoint(self, destination, requestUrl):
        explodeDestination = destination.split(':')
        protocol = None
        host = None
        port = None
        mapping = self.mappings
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

        endpoint = "{}://{}".format(protocol, host)
        if port is not None:
            endpoint = "{}:{}".format(endpoint, port)

        explodeUrl = requestUrl.split('/')
        for x in range(3):
            explodeUrl.pop(0)
        theRestOfTheURL = "/".join(explodeUrl)
        if len(theRestOfTheURL) > 0:
            endpoint = "{}/{}".format(endpoint, theRestOfTheURL)

        return endpoint

    def url(self, endpoint):
        explodeUrl = endpoint.split('/')
        for x in range(3):
            explodeUrl.pop(0)
        return "/".join(explodeUrl)

    def base64_decode(self, encoded):
        base64_bytes = encoded.encode('ascii')
        encoded_bytes = base64.b64decode(base64_bytes)
        return encoded_bytes.decode('ascii')
