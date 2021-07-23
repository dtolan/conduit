"""
handle user interaction 
"""
#import sqlite3
#from sqlite3 import Error
#from pprint import pprint
import getpass
import bcrypt


class Users:
    def __init__(self, sqlite):
        self.sqlite = sqlite

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
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM users WHERE id=?", (user_id,))

        rows = cur.fetchall()

        for row in rows:
            return row

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
        cur = self.conn.cursor()
        cur.execute(sql)
        self.conn.commit()
        return cur.lastrowid

    def ask_for_password(self, message="Password : "):
        return getpass.getpass(message)

    def get_and_update_password(self, user_id=None, user_name=None):
        password = None
        confirm_password = None
        if user_id is not None:
            password_message = "New Password : "
        else:
            password_message = "Password : "
        while password is None or password != confirm_password:

            password = self.ask_for_password(password_message)
            confirm_password = self.ask_for_password("Confirm Password : ")
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        database_password = hashed.decode('utf-8')

        if user_id is None:
            self.create_user(user_name, database_password)
        else:
            self.update_user_password(user_id, database_password)

    def verify_password(self, current_password=None, retry_count=3) -> bool:
        correctPassword = False
        loop_count = 0
        encoded_password = current_password.encode('utf-8')
        while (loop_count < retry_count) and correctPassword == False:
            loop_count = loop_count + 1
            password = self.ask_for_password("Current Password :")
            try_password = password.encode('utf-8')
            if bcrypt.checkpw(try_password, encoded_password):
                correctPassword = True
            else:
                print(
                    "Invalid: current password did not match entered password - Try again !")
        if not correctPassword:
            print("Unable to verify your current password")

        return correctPassword
