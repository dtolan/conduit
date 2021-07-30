"""
handle user interaction 
"""
#import sqlite3
#from sqlite3 import Error
from base64 import encode
from pprint import pprint
import getpass
import bcrypt

from classes.mapping import Mapping
from classes.crypt import Crypt


class Users:
    def __init__(self, sqlite=None, crypt=None):
        self.sqlite = sqlite
        self.crypt = crypt
        self.maps = Mapping(sqlite)

    ''' Private Functions '''

    def __get_hashed_password__(self, password) -> str:
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        return hashed.decode('utf-8')

    def __update_existing_user__(self, user_id, password) -> bool:
        hashed_password = self.__get_hashed_password__(password)
        return self.update_user_password(user_id, hashed_password)

    def __create_new_user__(self, user, password):
        hashed_password = self.__get_hashed_password__(password)
        return self.create_user(user, hashed_password)

    def __ask_for_password__(self, message="Password : "):
        return getpass.getpass(message)

    ''' Database Functions '''

    def get_user_password_by_name(self, user_name):
        """
        :param user_name:
        :return: id (int)
        :return: password (byteString)
        """
        sql_statement = "SELECT id,password FROM users WHERE name='{}'".format(
            user_name)
        return self.sqlite.select_from_database(sql_statement)

    def get_user_id_by_name(self, user_name):
        """
        :param user_name:
        :return: id (int)
        :return: password (byteString)
        """
        sql_statement = "SELECT id FROM users WHERE name='{}'".format(
            user_name)
        return self.sqlite.select_from_database(sql_statement)

    def get_user_by_id(self, user_id):
        """
        :param name:
        :return: id (int)
        :return: password (byteString)
        """
        sql_statement = "SELECT * FROM users WHERE id={}".format(user_id)
        return self.sqlite.select_from_database(sql_statement)

    def update_user_password(self, user_id, password):
        """
        :param user_id:
        :param password:
        :return: id
        """
        sql = "UPDATE users set password = '{}' WHERE id = {}".format(
            password, user_id)
        return self.sqlite.update_database(sql)

    def create_user(self, user_name, user_password):
        """
        Create a new project into the projects table
        :param user_name:
        :param user_password:
        :return: user_id
        """
        sql = "INSERT INTO users(name,password) VALUES('{}','{}')".format(
            user_name, user_password)
        return self.sqlite.insert_into_database(sql)

    def delete_user(self, user_id):
        """
        Delete a user 
        :param user_id:
        :return: 
        """
        sql = "DELETE FROM users WHERE id = {}".format(
            user_id)
        return self.sqlite.update_database(sql)

    ''' Functions for User Management from local scripting '''

    def get_and_update_password(self, user_id=None, user_name=None):
        password = None
        confirm_password = None
        if user_id is not None:
            password_message = "New Password : "
        else:
            password_message = "Password : "
        while password is None or password != confirm_password:
            password = self.__ask_for_password__(password_message)
            confirm_password = self.__ask_for_password__("Confirm Password : ")

        if user_id is None:
            self.__create_new_user__(user_name, password)
        else:
            self.__update_existing_user__(user_id, password)

    def verify_password(self, current_password=None, retry_count=3) -> bool:
        correctPassword = False
        loop_count = 0
        encoded_password = current_password.encode('utf-8')
        while (loop_count < retry_count) and correctPassword == False:
            loop_count = loop_count + 1
            password = self.__ask_for_password__("Current Password :")
            try_password = password.encode('utf-8')
            if bcrypt.checkpw(try_password, encoded_password):
                correctPassword = True
            else:
                print(
                    "Invalid: current password did not match entered password - Try again !")
        if not correctPassword:
            print("Unable to verify your current password")

        return correctPassword

    def verify_user_and_password(self, user, password) -> bool:
        print(user)
        is_valid_user = False
        database_password = self.get_user_password_by_name(user)
        if len(database_password) == 1:
            encoded_password = database_password[0][1].encode('utf-8')
            try_password = password.encode('utf-8')
            if bcrypt.checkpw(try_password, encoded_password):
                is_valid_user = True
        return is_valid_user

    ''' Web Entry Point for Management of User Accounts'''

    def manage_user(self, jwt_info, data):
        status = True
        message = None
        if data['action'] == 'create':
            if 'item' in data and data['item'] == 'map':
                user_id_list = self.get_user_id_by_name(data['user'])
                user_id = user_id_list[0][0]
                hashed_token = None
                hashed_user = None
                hashed_password = None
                if data['token'] is None:
                    data['token'] = "None"
                if data['map_user'] is None:
                    data['map_user'] = "None"

                if data['password'] is None:
                    data['password'] = "None"

                hashed_token = self.crypt.encrypt(data['token'])
                hashed_user = self.crypt.encrypt(data['map_user'])
                hashed_password = self.crypt.encrypt(data['password'])
                message = self.maps.create_map(
                    user_id, data['type'], data['host'], hashed_token, hashed_user, hashed_password)
                if message is None:
                    status = False
            else:
                if 'password' not in data or 'user' not in data:
                    status = False
                    message = 'Invalid/Missing values (user,password)'
                verify_user = self.get_user_by_id(data['user'])
                if len(verify_user) == 0:
                    message = self.__create_new_user__(
                        data['user'], data['password'])
                    if message is None:
                        status = False
                else:
                    status = False
                    message = 'Unable to add User - User already Exists'
        elif data['action'] == 'report' or data['action'] == 'list':
            if 'item' in data and data['item'] == 'map':
                user_id_list = self.get_user_id_by_name(data['user'])
                user_id = user_id_list[0][0]
                message = self.maps.get_maps(user_id)
                status = True
            else:
                message = self.get_user_by_id(jwt_info['id'])
                if len(message) == 0:
                    status = False
        elif data['action'] == 'update':
            if 'password' not in data:
                status = False
                message = "Invalid/Missing values (password)"
            else:
                status = self.__update_existing_user__(
                    jwt_info['id'], data['password'])
        elif data['action'] == 'delete':
            if 'item' in data and data['item'] == 'map':
                user_id_list = self.get_user_id_by_name(data['user'])
                user_id = user_id_list[0][0]
                message = self.maps.delete_map(data['id'])
            else:
                status = self.delete_user(jwt_info['id'])
        return {'status': status, 'message': message}
