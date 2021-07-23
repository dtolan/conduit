
from bottle import request, response, auth_basic
from bottle import post, get, put, delete
#from bottle import auth_basic
from bottle import run
# from bottle import template
import yaml
from pprint import pprint
from classes.requester import Requester
from classes.parser import Parser
from classes.salt import Salt
from classes.sqlite import Sqlite
from classes.crypt import Crypt
from classes.vcdlogin import VcdLogin
import sys

_names = set()                    # the set of names

config_file = '../conf/server.yaml'
try:
    with open(config_file) as mainConfig:
        config = yaml.load(mainConfig, Loader=yaml.FullLoader)
    host = config['server']['host']
    port = config['server']['port']
except:
    print("Error: No Configuration File ({})".format(config_file))
    sys.exit()


try:
    database = config['sqlite']['database']
except:
    print("Error: No SQLite Database Defined in ({})".format(config_file))
    sys.exit()

try:
    authentication = config['authentication']
except:
    authentication = None
try:
    hash_key = config['hashkey']
except:
    print("Error: No valid Hash key found in servier config ({})".format(config_file))
    sys.exit()

try:
    with open(r'../conf/destinations.yaml') as mappingsConfig:
        mappings = yaml.load(mappingsConfig, Loader=yaml.FullLoader)
except:
    mappings = dict()

sqlite = Sqlite(database)
conn = sqlite.connect()
requester = Requester()
salt = Salt(mappings=mappings)
crypt = Crypt(hash_key)
parser = Parser(mappings=mappings, sqlite=sqlite, crypt=crypt)


def is_authenticated_user(user=None, password=None):
    print("here")
    return True


def get_user(headers):
    try:
        return headers['User']
    except:
        return None


@post("<:re:.+>")
# @auth_basic(is_authenticated_user)
def post_handler():
    '''Handles post requests'''
    headers = parser.headers(request.headers)
    user = get_user(headers)
    endpoint = parser.endpoint(headers['Destination'], request.url)
    auth = parser.mappedValue('auth', headers['Destination'])
    auth_values = parser.userMappedValue(
        user, headers['Destination'])
    if auth == 'salt':
        salt.login(auth_values, headers['Destination'])
        return salt.request(request.body.read())
    elif auth == 'header':
        header_key = parser.mappedValue('header', headers['Destination'])
        if 'token' in auth_values:
            headers[header_key] = auth_values['token']
    data = requester.post(endpoint, headers=headers, body=request.body.read())

    return data


@get("<:re:.+>")
# @auth_basic(is_authenticated_user)
def get_handler():
    '''Handles get requests'''
    headers = parser.headers(request.headers)
    user = get_user(headers)
    endpoint = parser.endpoint(headers['Destination'], request.url)
    auth = parser.mappedValue('auth', headers['Destination'])
    auth_values = parser.userMappedValue(
        user, headers['Destination'])
    if auth == 'salt':
        salt.login(headers['Destination'])
        return
    elif auth == 'header':
        header_key = parser.mappedValue(auth, headers['Destination'])
        if 'token' in auth_values:
            headers[header_key] = auth_values['token']
    elif auth == 'vcd':
        host = parser.mappedValue('host', headers['Destination'])
        print(host)
        pprint(auth_values)
        vcd = VcdLogin(host, auth_values['user'], auth_values['password'])
        vcd.login()
        return
    else:
        print(auth)
        response.status = 400
        return {"message": "invalid request type"}

    data = requester.get(endpoint, headers=headers)
    response.status = data.status_code
    if data.status_code > 299:
        return {"message": response.status_line}

    return data


@put("<:re:.+>")
# @auth_basic(is_authenticated_user)
def put_handler():
    '''Handles put requests'''
    headers = parser.headers(request.headers)
    user = get_user(headers)
    endpoint = parser.endpoint(headers['Destination'], request.url)
    auth = parser.mappedValue('auth', headers['Destination'])
    auth_values = parser.userMappedValue(
        user, headers['Destination'])
    if auth == 'salt':
        salt.login(auth_values, headers['Destination'])
        return salt.request(request.body.read())
    elif auth == 'header':
        header_key = parser.mappedValue('header', headers['Destination'])
        if 'token' in auth_values:
            headers[header_key] = auth_values['token']

    data = requester.put(endpoint, headers=headers, body=request.body.read())

    return data


@delete("<:re:.+>")
# @auth_basic(is_authenticated_user)
def delete_handler():
    '''Handles name deletions'''
    pass


def main():

    global destinations
    run(host=host, port=port)


if __name__ == "__main__":
    main()