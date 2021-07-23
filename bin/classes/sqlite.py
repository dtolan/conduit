import sqlite3
from sqlite3 import Error

class Sqlite:
    def __init__(self, database_file):
        self.database_file = database_file
        self.database_connection = None

    def connect(self):
        """ create a database connection to a SQLite database """
        try:
            self.database_connection = sqlite3.connect(self.database_file)
        except Error as e:
            print(e)

        return self.database_connection

    def update_database(self, sql_statement) -> bool:
        try:
            cursor = self.database_connection.cursor()
            cursor.execute(sql_statement)
            self.database_connection.commit()
        except Error as e:
            print("Error: {}".format(e))
            return False
        return True

    def select_from_database(self, sql_statement):
        try:
            cursor = self.database_connection.cursor()
            cursor.execute(sql_statement)
        except Error as e:
            print("Error: {}".format(e))
            return None
        rows = cursor.fetchall()
        return rows

    def insert_into_database(self, sql_statement):
        try:
            cursor = self.database_connection.cursor()
            cursor.execute(sql_statement)
            self.database_connection.commit()
        except Error as e:
            print("Error: {}".format(e))
            return None
        return cursor.lastrowid

    def disconnect(self):
        self.database_connection.close()
