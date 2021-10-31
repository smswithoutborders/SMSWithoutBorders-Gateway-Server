#!/usr/bin/env python3


import os
import sys
import requests
import configparser

if __name__ == "__main__":
    """
    config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
    config.read(os.path.join(os.path.dirname(__file__), '../.configs', 'config.ini'))
    """

    print("usage: / [auth_id] [isp] [number] [country]")
    country=sys.argv[4]
    url=f'http://localhost:15673/sms/{country}'

    auth_id=sys.argv[1]
    data=[
            {"isp":sys.argv[2], "number":sys.argv[3], "text":"Test message from Deku API"}
    ]
    response = requests.post(url=url, json={"auth_id":auth_id, "data":data})
    # print(response.text)

    if response.status_code == 200:
        print("* sms request successful")
    else:
        print("* sms request failed", response.status_code, response.text)
