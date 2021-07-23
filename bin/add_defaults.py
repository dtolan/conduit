import yaml

from classes.sqlite import Sqlite
from classes.users import Users
import sys
from pprint import pprint
from classes.crypt import Crypt
from classes.mapping import Mapping


def main():
    try:
        with open(r'../conf/server.yaml') as mainConfig:
            config = yaml.load(mainConfig, Loader=yaml.FullLoader)
        database = config['sqlite']['database']
        hash_value = config['hashkey']
    except:
        print("Requires sqlite: database defined in server.yaml")
        sys.exit()

    crypt = Crypt(hash_value)
    try:
        with open(r'../conf/defaults.yaml') as mappingsConfig:
            mappings = yaml.load(mappingsConfig, Loader=yaml.FullLoader)
    except:
        mappings = dict()

    # IF NOT EXISTS
    sqlite = Sqlite(database)
    conn = sqlite.connect()
    users = Users(sqlite)
    mapping = Mapping(sqlite)

    user_information = users.get_user_id_by_name('default')
    user_id = user_information[0][0]

    for types in mappings:
        if 'auth' in mappings[types]:
            map_type = types  # mappings[types]['auth']
        else:
            map_type = 'none'
        if 'defaults' in mappings[types]:
            default_map = mappings[types]['defaults']
            if 'token' in default_map:
                token = crypt.encrypt(default_map['token'])
            else:
                token = ''
            if 'user' in default_map:
                user = crypt.encrypt(default_map['user'])
            else:
                user = ''
            if 'password' in default_map:
                password = crypt.encrypt(default_map['password'])
            else:
                password = ''
            host = ''
            check_for_mapping = mapping.get_map(user_id, map_type, host)
            if len(check_for_mapping) == 0:
                print("Inserting Default Map for {}".format(map_type))
                id = mapping.create_map(
                    user_id, map_type, host, token, user, password)

    print("Finished")


if __name__ == '__main__':
    main()
