import requests
from bs4 import BeautifulSoup
import json

# ----------------------------- Write page on index.html -----------------------------

url = "https://nvd.nist.gov/"

headers = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0"
}

req = requests.get(url, headers=headers)
src = req.text
print(src)

with open("index.html", "w") as file:
    file.write(src)

# ----------------------------- Write information on JSON -----------------------------

with open("index.html") as file:
    src = file.read()

soup = BeautifulSoup(src, "lxml")
all_cve_info = soup.find_all(class_="col-lg-9")

count = 0
list_cve_id = []
cve_list = {}

while count < 20:
    cve_id = f"cveDetailAnchor-{count}"
    list_cve_id.insert(count, cve_id)
    count += 1

for item in list_cve_id:
    cve_data = soup.find_all(id=f"{item}")
    for data in cve_data:
        data_text = data.text
        data_href = "https://nvd.nist.gov" + data.get("href")
        cve_list[data_text] = data_href

with open("cve_list.json", "w") as file:
    json.dump(cve_list, file, indent=4, ensure_ascii=False)

# ----------------------------- Create JSON and Write CVE details on JSON -----------------------------

with open("cve_list.json") as file:
    cve_list = json.load(file)

count = 0

for cve_name, cve_href in cve_list.items():
    req = requests.get(url=cve_href, headers=headers)
    src = req.text

    with open(f"data/{cve_name}.html", "w", encoding="utf-8") as file:
        file.write(src)

    with open(f"data/{cve_name}.html", encoding="utf-8") as file:
        src = file.read()

    soup = BeautifulSoup(src, "lxml")

    # Collecting information about vulnerabilities

    all_about_cve = soup.find(id="vulnDetailPanel").find_all("td")

    cve_info = []

    for item in all_about_cve:
        title_of_cve = soup.find(id="vulnDetailPanel").find("h2").find_all("span")
        description_of_cve = soup.find(class_="col-lg-9 col-md-7 col-sm-12").find_all("p")
        title = title_of_cve[0].text
        description = description_of_cve[0].text

        cve_info.append(
            {
                "Title": title,
                "Description": description
            }
        )

    # Write data to JSON
    with open(f"data/{cve_name}.json", "w", encoding="utf-8") as file:
        json.dump(cve_info[0], file, indent=4, ensure_ascii=False)
