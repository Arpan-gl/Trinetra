import urllib.request
import re
import json

urls_to_test = {
    "CTU_42": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/",
    "IoT_23": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/",
    "ExtraHop_DGA": "https://raw.githubusercontent.com/ExtraHop/DGA-Detection-Training-Dataset/master/README.md",
    "CIC_IDS2017": "https://www.unb.ca/cic/datasets/ids-2017.html",
    "UNSW_NB15_Official": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
    "MAWI": "https://mawi.wide.ad.jp/mawi/",
    "UGR16": "https://nesg.ugr.es/nesg-ugr16/"
}

opener = urllib.request.build_opener()
opener.addheaders = [('User-Agent', 'Mozilla/5.0')]
urllib.request.install_opener(opener)

results = {}
for name, url in urls_to_test.items():
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=8) as resp:
            content = resp.read(2048).decode('utf-8', errors='ignore')
            results[name] = {"status": "ONLINE", "http_code": resp.status, "snippet": content[:150].strip()}
    except Exception as e:
        results[name] = {"status": "ERROR", "error": str(e)}

print(json.dumps(results, indent=2))
