"""
A module for matching Mobile Country Codes (MCC) and Mobile Network Codes (MNC) 
against a JSON dataset scraped from https://www.mcc-mnc.com/.

References:
    - Original codebase: https://github.com/jbjulia/mcc-mnc
        This module is based on the code from the GitHub repository linked above. 
        It provides functionality to match MCCs and MNCs against a JSON dataset 
        containing Public Land Mobile Network (PLMN) information scraped from the 
        MCC-MNC website.
"""

import json
import os
import sys
from urllib.error import URLError
from urllib.request import urlopen

from bs4 import BeautifulSoup
from tqdm import tqdm

MCC_MNC_URL = "https://www.mcc-mnc.com/"
JSON_PATH = os.path.join(os.path.dirname(__file__), "mccmnc.json")


def find_matches(
    user_cc=None, user_mcc=None, user_mnc=None, user_plmn=None, user_network=None
):
    """
    Match the given criteria against the JSON data.

    Args:
        user_cc (str, optional): User's desired Country Code (CC).
        user_mcc (str, optional): User's desired Mobile Country Code (MCC).
        user_mnc (str, optional): User's desired Mobile Network Code (MNC).
        user_plmn (str, optional): User's desired Public Land Mobile Network (PLMN).
        user_network (str, optional): User's desired Network.

    Returns:
        dict: Dictionary of matching PLMNs with their details.
    """
    match_list = {}

    with open(JSON_PATH, "r", encoding="utf-8") as json_file:
        json_data = json.load(json_file)

    for plmn, details in json_data.items():
        if user_plmn and user_plmn != plmn:
            continue
        if user_cc and str(user_cc) != details["CC"]:
            continue
        if user_mcc and str(user_mcc) != details["MCC"]:
            continue
        if user_mnc and str(user_mnc) != details["MNC"]:
            continue
        if user_network and user_network != details["NETWORK"].lower():
            continue
        match_list[plmn] = details

    return match_list


def update():
    """
    Update the JSON data by scraping the MCC-MNC website.

    Returns:
        None
    """
    try:
        with urlopen(MCC_MNC_URL) as raw:
            print(f"Decoding raw HTML from {MCC_MNC_URL}")
            soup = BeautifulSoup(raw, features="html.parser")

        if os.path.exists(JSON_PATH):
            print(f"Removing old JSON dictionary {JSON_PATH}.")
            os.remove(JSON_PATH)

        print(f"Creating new JSON dictionary {JSON_PATH}.")
        json_data = {}
        table = soup.find("table")
        rows = table.find_all("tr")[1:]  # Skip the header
        total_rows = len(rows)
        progress_bar = tqdm(
            total=total_rows,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}",
            colour="blue",
        )

        for i, row in enumerate(rows, start=1):
            cols = row.find_all("td")
            mcc = cols[0].text
            mnc = cols[1].text
            plmn = mcc + mnc  # MCC + MNC
            json_data[plmn] = {
                "MCC": mcc,
                "MNC": mnc,
                "ISO": cols[2].text,
                "COUNTRY": cols[3].text,
                "CC": cols[4].text,
                "NETWORK": cols[5].text.strip() if cols[5].text else "unknown",
            }
            progress_bar.set_description(f"Processing row {i}/{total_rows}")
            progress_bar.update(1)

        progress_bar.close()

        with open(JSON_PATH, "w+", encoding="utf-8") as json_file:
            print(f"\nSaving JSON dictionary to {JSON_PATH}.")
            json.dump(json_data, json_file, indent=4, sort_keys=True)

    except URLError as e:
        print(f"Error downloading file: {e}")
        sys.exit(1)
