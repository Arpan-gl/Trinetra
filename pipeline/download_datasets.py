"""
SIH PS 26145 - Raw Dataset Acquisition Module
Downloads public datasets listed in SIH_PS_26145_Dataset_Links.md:
- UNSW-NB15 sample flow dataset (real DoS, Recon, Backdoor, Exploits, Benign)
- DGA domains dataset (real malware DGA families: Gozi, Corebot, Ranbyus, Symmi, etc.)
"""

import os
import urllib.request
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
os.makedirs(RAW_DIR, exist_ok=True)

DATASETS = {
    "dga_domains": {
        "url": "https://raw.githubusercontent.com/chrmor/DGA_domains_dataset/master/dga_domains_sample.csv",
        "dest": os.path.join(RAW_DIR, "dga_domains_sample.csv"),
    },
    "unsw_nb15": {
        "url": "https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_testing-set.csv",
        "dest": os.path.join(RAW_DIR, "unsw_nb15_sample.csv"),
    }
}

def download_file(url: str, dest: str) -> None:
    if os.path.exists(dest) and os.path.getsize(dest) > 1000:
        logging.info(f"File already exists: {dest} ({os.path.getsize(dest):,} bytes), skipping.")
        return
    logging.info(f"Downloading from {url} to {dest}...")
    opener = urllib.request.build_opener()
    opener.addheaders = [('User-Agent', 'Mozilla/5.0')]
    urllib.request.install_opener(opener)
    urllib.request.urlretrieve(url, dest)
    logging.info(f"Successfully downloaded: {dest} ({os.path.getsize(dest):,} bytes)")

def main():
    logging.info("Starting dataset acquisition for SIH PS 26145...")
    for name, item in DATASETS.items():
        try:
            download_file(item["url"], item["dest"])
        except Exception as e:
            logging.error(f"Failed to download {name}: {e}")
    logging.info("Dataset acquisition completed.")

if __name__ == "__main__":
    main()
