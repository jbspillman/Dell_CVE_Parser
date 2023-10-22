import os
from multiprocessing.pool import ThreadPool
import time
import datetime
import json
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

current_time_stamp = datetime.datetime.now()
date_stamp = current_time_stamp.strftime("%Y%m%d")
script_path = os.path.dirname(os.path.realpath(__file__))
data_folder = os.path.join(script_path, 'data')
advisory_folder = os.path.join(data_folder, 'advisories', date_stamp)
os.makedirs(data_folder, exist_ok=True)
os.makedirs(advisory_folder, exist_ok=True)


def download_advisories():
    print("entered:".ljust(30), "download_advisories")

    dell_dsa_json = os.path.join(advisory_folder, date_stamp + "_dell_dsa.json")
    if os.path.exists(dell_dsa_json):
        with open(dell_dsa_json, 'r', encoding="utf-8") as file_in:
            dsa_data = json.loads(file_in.read())
    else:
        dds_article_url = "https://www.dell.com/support/security/en-us/Security/DdsArticle"
        dsa_data = post_url(dds_article_url)
        json_string = json.dumps(dsa_data, indent=4, sort_keys=False)
        with open(dell_dsa_json, "w", encoding="utf-8") as json_out:
            json_out.write(json_string)

    all_products_json = os.path.join(data_folder, "all_products.json")
    all_products = []
    for item in dsa_data:
        a_combined_product_list = item["CombinedProductList"]
        if not isinstance(a_combined_product_list, type(None)):
            try:
                app_list = a_combined_product_list.split(",")
                for product in app_list:
                    all_products.append(product)
            except Exception as e:
                print(type(a_combined_product_list))
                print(e, a_combined_product_list)
                exit(1)

    all_products = sorted(list(set(all_products)))
    json_string = json.dumps(all_products, indent=4, sort_keys=False)
    with open(all_products_json, "w", encoding="utf-8") as json_out:
        json_out.write(json_string)

    applications_json = os.path.join(data_folder, "applications.json")
    if os.path.exists(applications_json):
        print("exited:".ljust(30), "download_advisories")
        return dsa_data
    else:
        print("Choose your products from:", all_products_json)
        print("Need to place your applications in list in:", applications_json)
        exit(1)


def post_url(url):
    payload = {
        "selection": 1234,
        "recordsPerPage": 25000,
        "pageNumber": 1,
        "isFirstCall": True,
        "Notices": False,
        "Information": False,
        "Advisory": True,
        "ProprietaryComponent": False,
        "ThirdpartyComponent": False
    }
    r = requests.post(url, data=payload, verify=False)
    if r.status_code != 200:
        print("error:", r.status_code, r.text)
        exit(1)

    else:
        data = r.json()
        advisory_data = data["AdvisoriesModelData"]
        return advisory_data


def download_url(args):
    t0 = time.time()
    dell_kb_url, file_name = args[0], args[1]
    if not os.path.exists(file_name):
        try:
            r = requests.get(dell_kb_url, verify=False)
            with open(file_name, 'wb') as f:
                f.write(r.content)
            return 200, dell_kb_url, time.time() - t0
        except Exception as e:
            print("Error with download_url():", dell_kb_url, e)
            return 404, dell_kb_url, time.time() - t0
    else:
        return 200, dell_kb_url, time.time() - t0


def download_parallel(args):
    print("entered:".ljust(30), "download_parallel")
    total_threads = 4
    results = ThreadPool(total_threads - 1).imap_unordered(download_url, args)
    z = 0
    for result in results:
        z += 1
        err_code = result[0]
        url_tried = result[1]
        elapsed_time = result[2]

        if err_code != 200:
            print(str(z).ljust(10), "code:", err_code, "url:", url_tried, 'time (s):', elapsed_time)
    print("exited:".ljust(30), "download_parallel")


def download_dsa_articles():
    print("entered:".ljust(30), "download_dsa_articles")
    number_of_bulletins, dsa_files, dsa_links = get_dsa_pages()

    inputs = zip(dsa_files, dsa_links)
    download_parallel(inputs)

    print("exited:".ljust(30), "download_dsa_articles")


def get_dsa_pages():
    print("entered:".ljust(30), "get_dsa_pages")

    dsa_potentials_json = os.path.join(advisory_folder, date_stamp + "_dsa_potentials.json")
    with open(dsa_potentials_json, 'r', encoding="utf-8") as file_in:
        dsa_potentials = json.loads(file_in.read())

    json_links = []
    local_links = []
    links = 0
    for item in dsa_potentials:
        links += 1
        dsa_article = item["article_id"]
        dsa_title = item["title"]
        dsa_number = dsa_title.split(": ")[0].upper()
        url_link = item["kb_print_url"]

        html_file = dsa_number + "_" + dsa_article + ".html"
        url_save = os.path.join(advisory_folder, html_file)
        json_links.append(url_link)
        local_links.append(url_save)

    json_string = json.dumps(json_links, indent=4, sort_keys=False)
    dsa_urls = os.path.join(advisory_folder, "dsa_urls.json")
    with open(dsa_urls, "w", encoding="utf-8") as json_out:
        json_out.write(json_string)
    print("exited:".ljust(30), "get_dsa_pages")
    return links, json_links, local_links









    # for link in files:
    #     if len(link.attrs["href"]) > 5:
    #         url_link = data_feed + link.attrs["href"]
    #         url_save = os.path.join(ntap_folder, link.attrs["href"])
    #         json_links.append(url_link)
    #         local_links.append(url_save)
    #         links += 1

    # json_string = json.dumps(json_links, indent=4, sort_keys=False)
    # with open(ntap_urls, "w", encoding="utf-8") as json_out:
    #     json_out.write(json_string)
    # print("exited:".ljust(30), "get_dsa_pages")
    # return links, json_links, local_links

