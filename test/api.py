#!/usr/bin/env python3


import os
import requests
import configparser

if __name__ == "__main__":
    config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
    config.read(os.path.join(os.path.dirname(__file__), '../.configs', 'config.ini'))

    # url='http://localhost:15673'
    # testing ISP deduction - using Cameroon values
    url = f"http://{config['API']['host']}:{config['API']['port']}"
    data = [
            {"text":"Hello world - MTN", "number":"+2376521", "expected": "MTN"},
            {"text":"Hello world - ORANGE", "number":"+2376921", "expected": "ORANGE"},
            {"text":"Hello world - INVALID", "number":"+2370921", "expected": "INVALID"}
            ]
    print("* Running on url -", url)
    print("* Deducing ISP...")

    results = requests.post(url=url + '/isp', json=data)
    if results.status_code != 200:
        print("* [error] request failed...", results, results.status_code)
        # return False
        exit(1)

    # print(results)
    results = results.json()
    for _data in results:
        if not "text" or not "number" or not "isp" in _data:
            print("* [error] missing key...\n", _data)
            exit(1)
        if _data['expected'].lower() != _data['isp'].lower():
            print("* [error] isp does not match...\n", _data)
        else:
            print("* [success] isp matches...\n", _data)
