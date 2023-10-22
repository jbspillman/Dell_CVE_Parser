import os
import datetime
from downloader import download_advisories, download_dsa_articles
from parse_advisories import create_advisories_products, parse_dsa_articles

current_time_stamp = datetime.datetime.now()
date_stamp = current_time_stamp.strftime("%Y%m%d")
script_path = os.path.dirname(os.path.realpath(__file__))
data_folder = os.path.join(script_path, 'data')
advisory_folder = os.path.join(data_folder, 'advisories', date_stamp)
os.makedirs(data_folder, exist_ok=True)
os.makedirs(advisory_folder, exist_ok=True)


def main():

    download_advisories()  # gets the data on the date of running script.
    create_advisories_products()  # ensures the advisories and products json files exist.
    download_dsa_articles()  # gets the printer friend DSA articles and stores them.
    # parse_dsa_articles()  # make usable files out of the details.


if __name__ == '__main__':
    main()





