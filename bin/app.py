
#from bottle import request, response, auth_basic
#from bottle import post, get, put, delete
#from bottle import auth_basic
#from bottle import run
import bottle
import jwt
#from bottle_jwt import (JWTProviderPlugin, jwt_auth_required)
# from bottle import template
import yaml
from pprint import pprint
from classes.requester import Requester
from classes.parser import Parser
from classes.salt import Salt
from classes.sqlite import Sqlite
from classes.crypt import Crypt
from classes.vcdlogin import VcdLogin
from classes.users import Users
import sys
import time
import datetime
import json

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
    jwt_secret = config['jwt_secret']
except:
    jwt_secret = "PleaseEnterAJWTSecretInTheConfig"

try:
    jwt_expires = int(config['jwt_expires'])
except:
    jwt_expires = 86400  # One Day in Seconds

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
users = Users(sqlite=sqlite, crypt=crypt)

broken_header_keys = ['Transfer-Encoding', 'Connection', 'Content-Encoding']
# server_secret = hash_key
app = bottle.Bottle()


def authenticate_user(headers):
    login_information = None
    if 'Destination' not in headers:
        return login_information

    if 'Authorization' in headers:
        bearer, token = headers['Authorization'].split()
        current_epoch_date = datetime.datetime.utcnow().timestamp()
        if bearer == 'Basic' and headers['Destination'] == 'user':
            user_and_password = parser.base64_decode(token).split(':')
            user_name = user_and_password.pop(0)
            user_password = ":".join(user_and_password)
            if (users.verify_user_and_password(
                    user_name, user_password)):
                user_id = users.get_user_id_by_name(user_name)[0][0]
                current_epoch_date = datetime.datetime.utcnow().timestamp()
                token_create_string = datetime.datetime.fromtimestamp(
                    current_epoch_date).strftime('%Y-%m-%d %H:%M:%S')
                login_information = dict()
                login_information['action'] = 'return'
                login_information['user_name'] = user_name
                login_information['id'] = user_id
                login_information['created'] = current_epoch_date
                login_information['readable_created'] = token_create_string
        elif bearer == 'Bearer':
            jwt_token = read_jwt(token)
            if ('id' not in jwt_token or 'created' not in jwt_token) or (jwt_token['created'] + jwt_expires) < current_epoch_date:
                return login_information
            user_info = users.get_user_by_id(jwt_token['id'])
            try:
                last_update = user_info[0][5]
                if last_update is None:
                    last_update_ts = 0
                else:
                    datetime_object = datetime.datetime.strptime(
                        last_update, '%Y-%m-%d %H:%M:%S')
                    last_update_ts = datetime.datetime.timestamp(
                        datetime_object)
            except:
                return login_information
            if last_update_ts > jwt_token['created']:
                return login_information

            login_information = jwt_token

    return login_information


def create_jwt(payload):
    return jwt.encode(payload, jwt_secret, algorithm='HS256')


def read_jwt(payload):
    return jwt.decode(payload, jwt_secret, algorithms=['HS256'])


def get_user(headers):
    try:
        return headers['User']
    except:
        return None


def reset_headers(headers):
    valid_headers = dict()
    for key in headers:
        if key not in broken_header_keys:
            value = headers[key]
            valid_headers[key] = value
    return valid_headers


@app.post("<:re:.+>")
# @jwt_auth_required
def post_handler():
    headers = parser.headers(bottle.request.headers)
    authenticated_user = authenticate_user(headers)
    if authenticated_user is None:
        bottle.response.status = 401
        bottle.response.add_header("Content-Type", "application/json")
        return {"message": "Invalid Login"}
    elif 'action' in authenticated_user and authenticated_user['action'] == 'return':
        authenticated_user.pop('action')
        jwt_token = create_jwt(authenticated_user)
        bottle.response.status = 200
        bottle.response.add_header(
            "Content-Type", "application/json;charset=utf-8")
        return {"status": True, "token": jwt_token}

    '''Handles post requests'''
    user = authenticated_user['user_name']
    endpoint = parser.endpoint(headers['Destination'], bottle.request.url)
    auth = parser.mappedValue('auth', headers['Destination'])
    auth_values = parser.userMappedValue(
        user, headers['Destination'])
    if auth == 'salt':
        salt.login(auth_values, headers['Destination'])
        return salt.request(bottle.response.body.read())
    elif auth == 'vcd':
        host = parser.mappedValue('host', headers['Destination'])
        vcd = VcdLogin(host)
        login = vcd.login(auth_values['user'], auth_values['password'])
        valid_headers = reset_headers(login['headers'])
        for key in valid_headers:
            value = valid_headers[key]
            bottle.response.add_header(key, value)
        return login['text']
    elif auth == 'header':
        header_key = parser.mappedValue('header', headers['Destination'])
        if 'token' in auth_values:
            headers[header_key] = auth_values['token']
    elif headers['Destination'] == 'user':
        try:
            data = bottle.request.body.read().decode()
            json_data = json.loads(data)
            return_data = users.manage_user(authenticated_user, json_data)
        except:
            bottle.response.status = 400
            bottle.response.add_header("Content-Type", "application/json")
            return_data = {"message": "invalid request type"}
        if 'status' in return_data and return_data['status']:
            bottle.response.status = 200
        else:
            bottle.response.status = 400

        return return_data
    else:
        data = bottle.request.body.read().decode()
        bottle.response.status = 400
        bottle.response.add_header("Content-Type", "application/json")
        return {"message": "invalid request type"}

    data = requester.post(endpoint, headers=headers,
                          body=bottle.request.body.read())
    valid_headers = reset_headers(data.headers)
    for key in valid_headers:
        value = valid_headers[key]
        bottle.response.add_header(key, value)
    return data


@app.get("<:re:.+>")
# @auth_basic(is_authenticated_user)
# @jwt_auth_required
def get_handler():
    '''Handles get requests'''
    headers = parser.headers(bottle.request.headers)
    authenticated_user = authenticate_user(headers)
    if authenticated_user is None:
        bottle.response.status = 401
        bottle.response.add_header("Content-Type", "application/json")
        return {"message": "Invalid Login"}
    elif 'action' in authenticated_user and authenticated_user['action'] == 'return':
        authenticated_user.pop('action')
        jwt_token = create_jwt(authenticated_user)
        bottle.response.status = 200
        bottle.response.add_header(
            "Content-Type", "application/json;charset=utf-8")
        return {"status": True, "token": jwt_token}

    user = authenticated_user['user_name']
    endpoint = parser.endpoint(headers['Destination'], bottle.request.url)
    auth = parser.mappedValue('auth', headers['Destination'])
    auth_values = parser.userMappedValue(
        user, headers['Destination'])
    if auth == 'salt':
        salt.login(headers['Destination'])
        return
    elif auth == 'vcd':
        host = parser.mappedValue('host', headers['Destination'])
        vcd = VcdLogin(host)
        login = vcd.login(auth_values['user'], auth_values['password'])
        valid_headers = reset_headers(login['headers'])
        for key in valid_headers:
            value = valid_headers[key]
            bottle.response.add_header(key, value)
        return login['text']
    elif auth == 'header':
        header_key = parser.mappedValue(auth, headers['Destination'])
        if 'token' in auth_values:
            headers[header_key] = auth_values['token']
    else:
        bottle.response.status = 400
        return {"message": "invalid request type"}

    data = requester.get(endpoint, headers=headers)
    valid_headers = reset_headers(data.headers)
    for key in valid_headers:
        value = valid_headers[key]
        bottle.response.add_header(key, value)

    return data


@app.put("<:re:.+>")
# @auth_basic(is_authenticated_user)
def put_handler():
    '''Handles put requests'''
    headers = parser.headers(bottle.request.headers)
    authenticated_user = authenticate_user(headers)
    if authenticated_user is None:
        bottle.response.status = 401
        bottle.response.add_header("Content-Type", "application/json")
        return {"message": "Invalid Login"}
    elif 'action' in authenticated_user and authenticated_user['action'] == 'return':
        authenticated_user.pop('action')
        jwt_token = create_jwt(authenticated_user)
        bottle.response.status = 200
        bottle.response.add_header(
            "Content-Type", "application/json;charset=utf-8")
        return {"status": True, "token": jwt_token}
    user = authenticated_user['user_name']
    endpoint = parser.endpoint(headers['Destination'], bottle.request.url)
    auth = parser.mappedValue('auth', headers['Destination'])
    auth_values = parser.userMappedValue(
        user, headers['Destination'])
    if auth == 'header':
        header_key = parser.mappedValue('header', headers['Destination'])
        if 'token' in auth_values:
            headers[header_key] = auth_values['token']
    else:
        bottle.response.status = 400
        return {"message": "invalid request type"}
    data = requester.put(endpoint, headers=headers,
                         body=bottle.request.body.read())

    return data


@app.delete("<:re:.+>")
# @auth_basic(is_authenticated_user)
def delete_handler():
    '''Handles name deletions'''
    headers = parser.headers(bottle.request.headers)
    authenticated_user = authenticate_user(headers)
    if authenticated_user is None:
        bottle.response.status = 401
        bottle.response.add_header("Content-Type", "application/json")
        return {"message": "Invalid Login"}
    elif 'action' in authenticated_user and authenticated_user['action'] == 'return':
        authenticated_user.pop('action')
        jwt_token = create_jwt(authenticated_user)
        bottle.response.status = 200
        bottle.response.add_header(
            "Content-Type", "application/json;charset=utf-8")
        return {"status": True, "token": jwt_token}
    pass


def main():

    global destinations
    bottle.run(app=app, port=port, host=host, reloader=True)
    #run(host=host, port=port)


if __name__ == "__main__":
    main()
