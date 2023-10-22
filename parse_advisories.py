import os
import re
import json
from datetime import datetime
import bs4
import pandas as pd

current_time_stamp = datetime.now()
date_stamp = current_time_stamp.strftime("%Y%m%d")
script_path = os.path.dirname(os.path.realpath(__file__))
data_folder = os.path.join(script_path, 'data')
advisory_folder = os.path.join(data_folder, 'advisories', date_stamp)
os.makedirs(data_folder, exist_ok=True)
os.makedirs(advisory_folder, exist_ok=True)


def create_advisories_products():
    print("entered:".ljust(30), "create_advisories_products")

    applications_json = os.path.join(data_folder, "applications.json")
    with open(applications_json, 'r', encoding="utf-8") as file_in:
        application_list = json.loads(file_in.read())

    dell_dsa_json = os.path.join(advisory_folder, date_stamp + "_dell_dsa.json")
    with open(dell_dsa_json, 'r', encoding="utf-8") as file_in:
        dsa_data = json.loads(file_in.read())

    dsa_potentials_json = os.path.join(advisory_folder, date_stamp + "_dsa_potentials.json")
    dsa_potential_list = []
    x = 0
    dsa_counter = 0
    for item in dsa_data:
        x += 1

        a_severity = item["Severity"]
        a_severity_order = item["SeverityOrder"]
        a_redirect_url = item["RedirectUrl"]
        a_type = item["Type"]
        a_dell_proprietary_code = item["DellProprietaryCode"]
        a_combined_product_list = item["CombinedProductList"]
        a_access_level = item["AccessLevel"]
        a_cve_identifier = item["CVEIdentifier"]
        a_article_id = item["ArticleId"]
        a_title = item["Title"]
        a_first_publish = item["FirstPublished"]
        a_last_publish = item["LastPublished"]
        a_url_name = item["UrlName"]

        check_cve = False
        if not isinstance(a_combined_product_list, type(None)):
            try:
                app_list = a_combined_product_list.split(",")
                for product in app_list:
                    if product in application_list:
                        check_cve = True
            except Exception as e:
                print(a_article_id, e)
                exit(2)

        dsa_url = a_redirect_url.split("href=")[1].split(">")[0].replace('"', "")
        kb_print_url = "https://www.dell.com/support/kbdoc/en-us/article/lkbprint?ArticleNumber=" + \
                       str(a_article_id) + "&AccessLevel=10&Lang=en"
        if check_cve:
            dsa_counter += 1
            a_cve_identifier = a_cve_identifier.upper().replace("  ", ",").replace(" ", "").replace("\u00a0", "")
            a_cve_identifier = a_cve_identifier.replace(":", "").replace("CVE", ",CVE").replace("SEE", " ").replace("\n", "")
            dsa_cve_list = []
            for cve in a_cve_identifier.split(","):
                cve = cve.rstrip()
                if cve:
                    if "CVE" in cve:
                        for word in cve.split(" "):
                            if cve.startswith("CVE"):
                                dsa_cve_list.append(word)
            dsa_cve_list = sorted(list(set(dsa_cve_list)))

            key = {
                "article_id": a_article_id,
                "title": a_title,
                "severity": a_severity,
                "publish_first": a_first_publish,
                "publish_last": a_last_publish,
                "dsa_url": dsa_url,
                "kb_print_url": kb_print_url,
                "cve_ids": dsa_cve_list
            }
            dsa_potential_list.append(key)

    json_string = json.dumps(dsa_potential_list, indent=4, sort_keys=False)
    with open(dsa_potentials_json, "w", encoding="utf-8") as json_out:
        json_out.write(json_string)
    print("exited:".ljust(30), "create_advisories_products")


def parse_dsa_articles():
    print("entered:".ljust(30), "parse_dsa_articles")

    dsa_potentials_json = os.path.join(advisory_folder, date_stamp + "_dsa_potentials.json")
    with open(dsa_potentials_json, 'r', encoding="utf-8") as file_in:
        dsa_potentials = json.loads(file_in.read())

    formatted_list = []
    all_advisories = os.path.join(script_path, 'data', 'advisories')
    for dated_folder in sorted(os.listdir(all_advisories)):
        dsa_dated_folder = os.path.join(all_advisories, dated_folder)

        z = 0
        for dsa_html in sorted(os.listdir(dsa_dated_folder)):
            if dsa_html.startswith("DSA-") and dsa_html.endswith(".html"):

                dsa_number = dsa_html.split("_")[0]
                dsa_article = dsa_html.split("_")[1].replace(".html", "")
                z += 1
                for entry in dsa_potentials:
                    article_id = entry["article_id"]
                    if dsa_article == article_id:

                        title = entry["title"]
                        severity = entry["severity"]
                        publish_first = entry["publish_first"]
                        publish_last = entry["publish_last"]
                        dsa_url = entry["dsa_url"]
                        kb_print_url = entry["kb_print_url"]
                        cve_ids = entry["cve_ids"]

                        dsa_release_date = publish_first.split("T")[0].replace("-", "")
                        dsa_last_update = publish_last.split("T")[0].replace("-", "")

                        dsa_days_open = days_active(date_stamp, int(dsa_release_date))
                        dsa_days_since_update = days_active(date_stamp, int(dsa_last_update))

                        start_keep = False
                        content = ""
                        dsa_html_path = os.path.join(dsa_dated_folder, dsa_html)
                        with open(dsa_html_path, 'r', encoding="utf-8") as html_in:
                            html = html_in.read()
                            for row in html.split("\n"):
                                row = row.replace("&nbsp;", "\n").replace("</b>", "\n").replace("\r", "")
                                row = row.replace("<b>", "\n").replace(" \n", "").strip()
                                if row:
                                    if "<!-- Article Content -->" in row:
                                        start_keep = True
                                    if "<!-- Severity Disclaimer Tab Content -->" in row:
                                        break
                                    if start_keep:
                                        if row:
                                            content += row + "\n"

                        tmp_content_file = os.path.join(dsa_dated_folder, dsa_html + ".tmp")
                        print(tmp_content_file)
                        with open(tmp_content_file, "w", encoding="utf-8") as tmp_out:
                            tmp_out.write(content)

                        affected_versions_list = []
                        affected_content = str(content).split("Affected products:")[1]
                        affected_content = affected_content.split("Remediation:")[0]
                        for af_ver in affected_content.split("<br>"):
                            af_ver = af_ver.strip()
                            af_ver = cleanhtml(af_ver).strip()
                            if af_ver:
                                affected_versions_list.append(af_ver)

                        remediation_list = []
                        remediation_content = str(content).split("Remediation:")[1]
                        try:
                            remediation_content = str(remediation_content).split("Link to Remedies:")[0]
                        except IndexError:
                            remediation_content = str(remediation_content).split("Related Information")[0]

                        try:
                            remediation_uo_list = remediation_content.split("<ul>")[1]
                            remediation_uo_list = remediation_uo_list.split("</ul>")[0]
                        except IndexError:
                            remediation_uo_list = remediation_content.split("<br>")[1]

                        for release_ver in remediation_uo_list.split("<br>"):
                            release_ver = release_ver.replace("\r", "").replace("\n", " ")
                            release_ver = cleanhtml(release_ver).strip()
                            if release_ver:
                                remediation_list.append(release_ver)

                        my_key = {
                            "dsa_number": dsa_number,
                            "dsa_release_date": dsa_release_date,
                            "dsa_days_open": dsa_days_open,
                            "dsa_last_update": dsa_last_update,
                            "dsa_days_since_update": dsa_days_since_update,
                            "dsa_article": dsa_article,
                            "dsa_title": title,
                            "dsa_severity": severity,
                            "dsa_url": dsa_url,
                            "dsa_total_cve": len(cve_ids),
                            "dsa_cve": cve_ids,
                            "dsa_affected_versions": affected_versions_list,
                            "dsa_remediation": remediation_list
                        }
                        formatted_list.append(my_key)
                        os.remove(tmp_content_file)
                        #
                        # print()
                        # print("item:".ljust(30), z)
                        # print("dsa_number:".ljust(30), dsa_number)
                        # print("dsa_article:".ljust(30), dsa_article)
                        # print("dsa_release_date:".ljust(30), dsa_release_date)
                        # print("dsa_days_open:".ljust(30), dsa_days_open)
                        # print("dsa_last_update:".ljust(30), dsa_last_update)
                        # print("dsa_days_since_update:".ljust(30), dsa_days_since_update)
                        # print("title:".ljust(30), title)
                        # print("severity:".ljust(30), severity)
                        # print("dsa_url:".ljust(30), dsa_url)
                        # print("kb_print_url:".ljust(30), kb_print_url)
                        # print("cve_ids:".ljust(30), cve_ids)
                        # print("affected_versions_list:".ljust(30), affected_versions_list)
                        # print("remediation_list:".ljust(30), remediation_list)
                        # print()
                        # print()
                        # print()

        formatted_open_json = os.path.join(dsa_dated_folder, "APP_" + "OneFS" + "_formatted.json")
        json_string = json.dumps(formatted_list, indent=4, sort_keys=False)
        with open(formatted_open_json, "w", encoding="utf-8") as json_out:
            json_out.write(json_string)
        csv_out = formatted_open_json.replace(".json", ".csv")
        with open(formatted_open_json, encoding='utf-8') as input_file:
            df = pd.read_json(input_file)
        df.to_csv(csv_out, encoding='utf-8', index=False)
    print("exited:".ljust(30), "parse_dsa_articles")


def days_active(date_one, date_two):
    date_one = datetime.strptime(str(date_one), "%Y%m%d")
    date_two = datetime.strptime(str(date_two), "%Y%m%d")
    if date_two > date_one:
        return (date_two-date_one).days
    else:
        return (date_one-date_two).days


def cleanhtml(raw_html):
    clean_html_regex = re.compile('<.*?>|&([a-z0-9]+|#[0-9]{1,6}|#x[0-9a-f]{1,6});')
    clean_text = re.sub(clean_html_regex, '', raw_html)
    return clean_text
