import os
import json
import glob
import pandas as pd
from pathlib import Path

evidence_dir = Path('dataset/evidence')

file_types = {}
for p in evidence_dir.rglob('*'):
    if p.is_file():
        ext = p.suffix.lower()
        file_types[ext] = file_types.get(ext, 0) + 1

print("File types in evidence/:", file_types)
