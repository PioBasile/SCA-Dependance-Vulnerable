import csv
import html
import json
import re
from pathlib import Path

LABEL_MAPS = {
    "attackVector":          {"N": 0, "A": 1, "L": 2, "P": 3},
    "attackComplexity":      {"L": 0, "H": 1},
    "privilegesRequired":    {"N": 0, "L": 1, "H": 2},
    "userInteraction":       {"N": 0, "R": 1},
    "scope":                 {"U": 0, "C": 1},
    "confidentialityImpact": {"N": 0, "L": 1, "H": 2},
    "integrityImpact":       {"N": 0, "L": 1, "H": 2},
    "availabilityImpact":    {"N": 0, "L": 1, "H": 2},
}

def get_english_description(descriptions):
    for entry in descriptions:
        if entry.get("lang") == "en":
            value = entry.get("value", "")
            value = value.replace("\n", " ").replace("\r", " ").replace("\t", " ")

            return value.strip()

    return None

def extract_cvss_rows(metrics):
    rows = []
    required_fields = ("attackVector", "attackComplexity", "privilegesRequired", "userInteraction", "scope", "confidentialityImpact", "integrityImpact", "availabilityImpact",)

    for key in ("cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key, []):
            if (m.get("type") != "Primary"):
                continue

            d = m.get("cvssData", {})
            if (any(field not in d or d.get(field) is None for field in required_fields)):
                continue

            rows.append({
                "attackVector": LABEL_MAPS["attackVector"][d.get("attackVector")[0]],
                "attackComplexity": LABEL_MAPS["attackComplexity"][d.get("attackComplexity")[0]],
                "privilegesRequired": LABEL_MAPS["privilegesRequired"][d.get("privilegesRequired")[0]],
                "userInteraction": LABEL_MAPS["userInteraction"][d.get("userInteraction")[0]],
                "scope": LABEL_MAPS["scope"][d.get("scope")[0]],
                "confidentialityImpact": LABEL_MAPS["confidentialityImpact"][d.get("confidentialityImpact")[0]],
                "integrityImpact": LABEL_MAPS["integrityImpact"][d.get("integrityImpact")[0]],
                "availabilityImpact": LABEL_MAPS["availabilityImpact"][d.get("availabilityImpact")[0]],
            })

        if rows:
            break

    return rows

def pretreat_desc(text: str) -> str:
    if not isinstance(text, str): return ""

    text = text.lower()
    text = html.unescape(text)

    months = r"(january|february|march|april|may|june|july|august|september|october|november|december)"
    text = re.sub(rf'\b{months}\s?(\d{{1,2}},)?\s?\d{{4}}\b', ' date_token ', text)
    text = re.sub(r'\b\d{4}-\d{2}-\d{2}\b', ' date_token ', text)

    text = re.sub(r'cve-\d{4}-\d+', ' cve_id_token ', text)
    text = re.sub(r'\bv?\d+(\.\d+|\.x|-[a-z0-9\.]+)+\b', ' version_token ', text)
    text = re.sub(r'(/[a-z0-9._-]+)+|([a-z]:\\[\w._-]+)+', ' file_path_token ', text)
    text = re.sub(r'0x[0-9a-fA-F]+', ' mem_addr_token ', text)
    text = re.sub(r'http[s]?://\S+', ' url_token ', text)
    text = re.sub(r'\S+@\S+', ' email_token ', text)

    text = re.sub(r'[^a-z0-9\s.,;_]', ' ', text)
    text = re.sub(r',+', ',', text)
    text = re.sub(r';+', ';', text)
    text = " ".join(text.split())

    return text

def process_and_append(file_path, output_csv):
    import pandas as pd  # offline-only dependency

    data_to_write = []

    with open(file_path, 'r', encoding='utf-8') as f:
        content = json.load(f)

        for vuln in content.get('vulnerabilities', []):
            cve = vuln.get('cve', {})
            desc = get_english_description(cve.get("descriptions", []))

            if not desc: continue

            pre_treated_desc = pretreat_desc(desc)

            metrics = extract_cvss_rows(cve.get("metrics", {}))

            if metrics:
                data_to_write.append({ "description": pre_treated_desc, **metrics[0] })

    if data_to_write:
        df = pd.DataFrame(data_to_write)
        df.dropna()

        file_exists = Path(output_csv).exists()
        df.to_csv(output_csv, mode='a', index=False, header=not file_exists, quoting=csv.QUOTE_ALL)

if __name__ == "__main__":
    json_files = sorted(Path("./data").glob("nvdcve-2.0-*.json"))

    for f in json_files:
        print(f"Processing [{f.name}]")
        process_and_append(f, "data/dataset_cvss.csv")