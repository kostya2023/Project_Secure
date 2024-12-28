import sys
sys.path.append(".")
import yaml

def read(file_path: str):
    with open(file_path, "r") as file:
        data = yaml.safe_load(file)
    return data