#!/usr/bin/env python3

import os
import sqlite3
import logging
import traceback

class Clients:
    def __init__(self) -> None:
        self.con = None
        self.db_client_filepath = os.path.join(
                os.path.dirname(__file__), '.db', 'clients.db')

        try:
            db_exist = self.__is_database__()
        except Exception as error:
            raise error

        if not db_exist:
            try:
                ''' options-
                1. create
                '''
                self.__create_db__()
                logging.debug('created db file')
            except Exception as error:
                raise error

            try:
                self.__create_db_tables__()
                logging.debug('tables created in db')

            except sqlite3.Warning as error:
                logging.warning(error)

            except Exception as error:
                raise error
        else:
            logging.debug('db file exist')

    def __create_db__(self):
        try:
            self.con = sqlite3.connect(self.db_client_filepath)
        except Exception as error:
            raise error
    
    def __create_db_tables__(self):
        try:
            cur = self.con.cursor()
            cur.execute('''CREATE TABLE clients
            (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            number TEXT NOT NULL,
            country TEXT NOT NULL,
            sim_imei TEXT NOT NULL UNIQUE,
            routes_online BOOLEAN NOT NULL,
            routes_offline BOOLEAN NOT NULL,
            instantiated_datetime DATETIME DEFAULT CURRENT_TIMESTAMP
            NOT NULL);''')
            
            self.con.commit()

        except sqlite3.Warning as error:
            # raise error
            logging.warning(error)

        except Exception as error:
            raise error

    def __is_database__(self):
        try:
            self.con = sqlite3.connect(
                    f"file:{self.db_client_filepath}?mode=rw",
                    uri=True)

        except sqlite3.OperationalError as error:
            # raise error
            return False
        except Exception as error:
            raise error

        return True

    def __read_clients_db__(self) -> list:
        cur = self.con.cursor()
        clients = list()

        try:
            for row in cur.execute(
                    'SELECT * FROM clients'):

                ''' database structure --- 

                + id:""
                + number:""
                + country:""
                + sim_imei:""
                + routes_online:""
                + routes_offline:""
                + instantiated_datetime:""
                '''

                client = {}
                client['id'] = row[0]
                client['number'] = row[1]
                client['country'] = row[2]
                client['sim_imei'] = row[3]
                client['routes_online'] = row[4]
                client['routes_offline'] = row[5]
                client['instantiated_datetime'] = row[6]

                clients.append(client)

        except sqlite3.Warning as error:
            logging.warning(error)

        except Exception as error:
            raise error

        return clients

    def get_list(self):

        ''' data format per object
        number: ""
        country: ""
        routes_online: bool
        routes_offline: bool
        '''

        try:
            clients = self.__read_clients_db__()
        except Exception as error:
            raise error

        return clients

    def create(self, data:dict) -> None:
        cur = self.con.cursor()
        data_values = (
                data['number'],
                data['country'],
                data['sim_imei'],
                data['routes_online'],
                data['routes_offline'])

        try:
            cur.execute(
                    'INSERT INTO clients(number, country, sim_imei, routes_online, routes_offline) VALUES(?,?,?,?,?)',
                    data_values)

            self.con.commit()

        except sqlite3.Warning as error:
            logging.warning(error)

        except Exception as error:
            raise error

    
    def __del__(self):
        self.con.close()

if __name__ == "__main__":
    logging.basicConfig(level='DEBUG')
    client = Clients()
