#!/usr/bin/env python3



def deduce_isp(number): # E.164 standard required
    config = configparser.ConfigParser()
    config.read("isp.ini") # TODO use the relative paths

    country=None
    country_code=None

    cc = config['country_codes']
    for cntry, code in cc.items():
        if re.search(f'^\{code}', number):
            country = cntry
            country_code=code

    if country is None:
        return None

    # TODO put something here in case the country does not have operator ids in the config file
    operator_stds= _config[country]
    for isp, stds in operator_stds.items():
        stds = stds.split(',')

        for std in stds:
            #removing country code from number
            number = number.replace(country_code, '')
            if re.search(std, number):
                return isp

    return None
