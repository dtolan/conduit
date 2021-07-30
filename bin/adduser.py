import sqlite3
from sqlite3 import Error
import yaml
import bcrypt
import os
import sys
import getpass
from pprint import pprint
from classes.sqlite import Sqlite
from classes.users import Users


def main():
    print("Current user name : {}".format(getpass.getuser()))

    username = input("Input User ID : ")

    try:
        with open(r'../conf/server.yaml') as mainConfig:
            config = yaml.load(mainConfig, Loader=yaml.FullLoader)
        database = config['sqlite']['database']
    except:
        print("Requires sqlite: database defined in server.yaml")
        sys.exit()

    # create a database connection
    sqlite = Sqlite(database)
    conn = sqlite.connect()
    users = Users(sqlite)
    user_id = None

    with conn:
        currentInfo = users.get_user_password_by_name(username)
        if len(currentInfo) == 1:
            user_id = currentInfo[0][0]
            current_password = currentInfo[0][1]
            verified_password = users.verify_password(current_password)
            if not verified_password:
                print("Error: Unable to verify current password")
                sys.exit()
        # Update Existing Password
        user_id = users.get_and_update_password(
            user_id=user_id, user_name=username)


if __name__ == '__main__':

    main()
