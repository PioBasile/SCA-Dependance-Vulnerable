import logging as _logging
from pathlib import Path
import torch
import torch.nn as nn
from transformers import DistilBertTokenizerFast, DistilBertModel, logging
from cvss import CVSS3
from cvss_prediction.parse_nvd_json_to_csv import pretreat_desc

logging.set_verbosity_error()
_logger = _logging.getLogger(__name__)

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
MODEL_PATH = Path(__file__).resolve().parent / "model" / "cvss_model.pt"

METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
HEAD_SIZES = [4, 2, 3, 2, 2, 3, 3, 3]
MAPS = {
    "AV": {0: "N", 1: "A", 2: "L", 3: "P"},
    "AC": {0: "L", 1: "H"},
    "PR": {0: "N", 1: "L", 2: "H"},
    "UI": {0: "N", 1: "R"},
    "S":  {0: "U", 1: "C"},
    "C":  {0: "N", 1: "L", 2: "H"},
    "I":  {0: "N", 1: "L", 2: "H"},
    "A":  {0: "N", 1: "L", 2: "H"}
}

class Model(nn.Module):
    def __init__(self):
        super().__init__()
        self.bert = DistilBertModel.from_pretrained("distilbert-base-uncased")
        self.dropout = nn.Dropout(0.3)
        self.heads = nn.ModuleList(nn.Linear(768, n) for n in HEAD_SIZES)

    def forward(self, input_ids, attention_mask):
        out = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        cls = self.dropout(out.last_hidden_state[:, 0, :])
        return [head(cls) for head in self.heads]

tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")
model = Model().to(DEVICE)
model.load_state_dict(torch.load(MODEL_PATH, map_location=DEVICE))
model.eval()

_logger.info("CVSS prediction model loaded")

def predict_cvss(description: str) -> float:
    if not description:
        raise ValueError("description must not be empty")

    enc = tokenizer(
        pretreat_desc(description),
        max_length=256,
        padding="max_length",
        truncation=True,
        return_tensors="pt",
    ).to(DEVICE)

    with torch.no_grad():
        logits = model(enc["input_ids"], enc["attention_mask"])

    m = {name: MAPS[name][logit.argmax(1).item()] for name, logit in zip(METRICS, logits)}
    vec = "CVSS:3.1/" + "/".join(f"{name}:{m[name]}" for name in METRICS)
    return CVSS3(vec).base_score