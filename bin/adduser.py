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


def create_user(conn, userInfo):
    """
    Create a new project into the projects table
    :param conn:
    :param project:
    :return: project id
    """
    sql = ''' INSERT INTO users(name,password,active,entry_date)
              VALUES(?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, userInfo)
    conn.commit()
    return cur.lastrowid


def update_user(conn, userId, password):
    """
    Create a new project into the projects table
    :param conn:
    :param project:
    :return: project id
    """
    sql = "UPDATE users set password = '{}' where id = {}".format(
        password, userId)
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()
    return cur.lastrowid


def get_current_user(conn, user):
    """
    Query tasks by priority
    :param conn: the Connection object
    :param priority:
    :return:
    """
    cur = conn.cursor()
    cur.execute("SELECT id,password FROM users WHERE name=?", (user,))

    rows = cur.fetchall()

    for row in rows:
        return row


def main():
    print(getpass.getuser())
    if 'linux' in sys.platform.lower():
        username = getpass.getuser()
    else:
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
        # create a new project
        user_id = users.get_and_update_password(
            user_id=user_id, user_name=username)


if __name__ == '__main__':

    main()
