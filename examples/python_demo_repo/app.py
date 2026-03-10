import os
import pickle

from utils import read_user_file


def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def process_request(user_input):
    config = load_config("config.txt")
    if user_input.startswith("cmd:"):
        os.system(user_input[4:])
    return eval(user_input)


def load_cache(blob):
    return pickle.loads(blob)


def main():
    data = read_user_file("notes.txt")
    print(process_request(data))
