"""含多类漏洞的待扫描样本。"""
import os
import pickle
import subprocess
import sys

import requests

PASSWORD = "supersecret123"


def run_command(user_input):
    # 命令注入：shell=True 且拼接外部输入
    subprocess.call("ping " + user_input, shell=True)
    os.system("ls " + user_input)


def read_file(filename):
    # 路径穿越：外部输入直接拼接进 open
    path = "/data/" + filename
    with open(path) as fh:
        return fh.read()


def load_blob(blob):
    # 不安全反序列化
    return pickle.loads(blob)


def fetch(url):
    # SSRF：外部 URL 直接请求
    return requests.get(url).text


def main():
    user_input = sys.argv[1]
    run_command(user_input)
    read_file(user_input)
    fetch(user_input)
