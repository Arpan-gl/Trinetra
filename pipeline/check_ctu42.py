import urllib.request

url = "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/capture20110810.binetflow"
req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
with urllib.request.urlopen(req) as resp:
    headers = dict(resp.getheaders())
    print("Content-Length:", headers.get('Content-Length'), "bytes")
    # Read first 10 lines
    lines = [resp.readline().decode('utf-8', errors='ignore') for _ in range(10)]
    print("\nFirst 5 lines:")
    for l in lines[:5]:
        print(l.strip())
