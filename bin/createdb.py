import yaml
from sqlite3 import Error
import sqlite3
from classes.sqlite import Sqlite
import sys
from pprint import pprint


def main():
    try:
        with open(r'../conf/server.yaml') as mainConfig:
            config = yaml.load(mainConfig, Loader=yaml.FullLoader)
        database = config['sqlite']['database']
        hash_value = config['hashkey']
    except:
        print("Requires sqlite: database defined in server.yaml")
        sys.exit()
    # IF NOT EXISTS
    sql_create_user_table = """ CREATE TABLE IF NOT EXISTS Users (
                                        id INTEGER PRIMARY KEY,
                                        Name TEXT NOT NULL,
                                        Password TEXT NOT NULL,
                                        Active INTEGER DEFAULT 1,
                                        CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                        LastUpdate TIMESTAMP
                                    ); """
    sql_create_user_mappings = """ CREATE TABLE IF NOT EXISTS Mapping (
                                        id INTEGER PRIMARY KEY,
                                        User_ID INTEGER NOT NULL,
                                        Type TEXT NOT NULL,
                                        Host TEXT,
                                        Token TEXT,
                                        User TEXT,
                                        Password TEXT,
                                        CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                        LastUpdate TIMESTAMP
                                    ); """
    sql_create_update_trigger = """ CREATE TRIGGER IF NOT EXISTS [UpdateLastTime]
                                AFTER UPDATE
                                ON Users
                                FOR EACH ROW
                                BEGIN
                                UPDATE Users SET LastUpdate = CURRENT_TIMESTAMP WHERE id = old.id;
                                END"""

    sql_delete_statement_Users = """DROP TABLE IF EXISTS Users"""
    sql_delete_statement_Mapping = """DROP TABLE IF EXISTS Mapping"""
    sql_create_default_user = "INSERT INTO Users(name,password) VALUES('default','')"
    sqlite = Sqlite(database)
    conn = sqlite.connect()

    if conn is not None:
        sqlite.update_database(sql_delete_statement_Users)
        sqlite.update_database(sql_delete_statement_Mapping)
        sqlite.update_database(sql_create_user_table)
        sqlite.update_database(sql_create_update_trigger)
        sqlite.update_database(sql_create_user_mappings)
        defaultId = sqlite.insert_into_database(sql_create_default_user)
        sql_insert_defaults = "INSERT INTO Mapping(User_ID,Type,Host,) VALUES('default','')"
    else:
        print("Error! cannot create the database connection.")

    print("Finished")


if __name__ == '__main__':
    main()
