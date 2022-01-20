#!/usr/bin/env python3

import sqlite3
import logging
import traceback

class Clients:
    def __init__(self) -> None:
        self.con = None

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
            self.con = sqlite3.connect('.db/clients.db')
        except Exception as error:
            raise error
    
    def __create_db_tables__(self):
        try:
            cur = self.con.cursor()
            cur.execute('''CREATE TABLE clients
            (id INT PRIMARY KEY NOT NULL,
            number TEXT NOT NULL,
            country TEXT NOT NULL,
            routes_online BOOLEAN NOT NULL,
            routes_offline BOOLEAN NOT NULL,
            instantiated_datetime DATETIME NOT NULL,
            shared_key TEXT NOT NULL,
            public_key TEXT NOT NULL);''')
            
            self.con.commit()

        except sqlite3.Warning as error:
            # raise error
            logging.warning(error)

        except Exception as error:
            raise error

    def __is_database__(self):
        try:
            self.con = sqlite3.connect("file:.db/clients.db?mode=rw",
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

                + number:""
                + country:""
                + routes_online:""
                + routes_offline:""
                + instantiated_datetime:""
                + shared_key:""
                + public_key:""
                '''

                client = {}
                client['number'] = row[0]
                client['country'] = row[1]
                client['routes_online'] = row[2]
                client['routes_offline'] = row[3]
                client['instantiated_datetime'] = row[4]

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
    
    def __del__(self):
        self.con.close()

if __name__ == "__main__":
    logging.basicConfig(level='DEBUG')
    client = Clients()
