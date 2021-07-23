"""
handle user interaction 
"""
import getpass
import bcrypt


class Mapping:
    def __init__(self, sqlite):
        self.sqlite = sqlite

    def get_map_by_id(self, map_id, ):
        """
        :param name:
        :return: id (int)
        :return: password (byteString)
        """
        sql = "SELECT * FROM Mapping WHERE id={}".format(map_id)
        return self.sqlite.select_from_database(sql)

    def get_map(self, user_id, map_type, host):
        """
        :param name:
        :return: id (int)
        :return: password (byteString)
        """
        sql = "SELECT * FROM Mapping WHERE User_ID = {} and Type='{}' and Host='{}'".format(
            user_id, map_type, host)
        return self.sqlite.select_from_database(sql)

    def update_user_password(self, user_id, password):
        """
        :param user_id:
        :param password:
        :return: id
        """
        sql = "UPDATE users set password = '{}' WHERE id = {}".format(
            password, user_id)
        return self.sqlite.update_database(sql)

    def create_map(self, user_id, map_type, host, token, user, password):
        """
        Create a new project into the projects table
        :param user_name:
        :param user_password:
        :return: user_id
        """
        sql = "INSERT INTO Mapping(User_ID,Type,Host,Token,User,Password) VALUES({},'{}','{}','{}','{}','{}')".format(
            user_id, map_type, host, token, user, password)

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
