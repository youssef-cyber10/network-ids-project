"""
Download NSL-KDD dataset - a commonly used dataset for Network Intrusion Detection (NIDS).
Source: GitHub mirror of the NSL-KDD Dataset.
"""
import os
import urllib.request

RAW_BASE = "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master"
FILES = {
    "KDDTrain+.txt": f"{RAW_BASE}/KDDTrain+.txt",
    "KDDTest+.txt": f"{RAW_BASE}/KDDTest+.txt",
}

OUT_DIR = os.path.dirname(os.path.abspath(__file__))


def download_all():
    for filename, url in FILES.items():
        out_path = os.path.join(OUT_DIR, filename)
        if os.path.exists(out_path):
            print(f"[exists] {filename}")
            continue
        print(f"[downloading] {filename} ...")
        urllib.request.urlretrieve(url, out_path)
        size_kb = os.path.getsize(out_path) / 1024
        print(f"[done] {filename} ({size_kb:.1f} KB)")


if __name__ == "__main__":
    download_all()
