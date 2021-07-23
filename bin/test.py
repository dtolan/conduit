import mysql.connector
import sys
import yaml

try:
    with open(r'../conf/server.yaml') as mainConfig:
        config = yaml.load(mainConfig, Loader=yaml.FullLoader)
    host = config['database']['host']
    user = config['database']['user']
    password = config['database']['password']
    database = config['database']['database']
except:
    sys.exit()
cnx = mysql.connector.connect(user=user, password=password,
                              host=host,
                              database=database)
cnx.close()
