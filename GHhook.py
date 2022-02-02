#!/usr/bin/python3
# -*- coding: utf-8 -*-

from flask import Flask, Response, request
from requests import get
from pathlib import Path
from os import mkdir, path
from ipaddress import ip_address
import datetime
import logging
import sys
import argparse
import json
import iptools
try:
    from LIFOtimer import refresh
except ImportError:
    from .LIFOtimer import refresh
try:
    from reporeader import pull
except ImportError:
    from .reporeader import pull


#---- Initial configuration ----#
def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "repository_url",
        help="Repository to pull from",
        type=lambda s: str(s),
    )
    parser.add_argument(
        "-ip",
        help="IP address of this server",
        type=lambda s: ip_address(s).__str__(),
        default="127.0.0.1"
    )
    parser.add_argument(
        "-port",
        "-p",
        help="Bind this server to this PORT",
        type=lambda s: int(s),
        default=443
    )
    parser.add_argument(
        "-save_rep_path",
        "-save",
        help="Path where the repository will be saved",
        type=lambda s: str(s),
        default="data"
    )
    parser.add_argument(
        "-wait_until_pull",
        "-wait",
        "-w",
        help="Wait time until the pull request is made",
        type=lambda s: float(s),
        default=5
    )
    parser.add_argument(
        "--fetch_meta",
        "--fetch",
        "--meta",
        help="On start, ¿fetch github meta?",
        action="store_true",
        default=False
    )

    return parser.parse_args()

args = parse()

logs_file = "logs/"

if not path.isdir("logs"):
    if not path.exists("logs"):
        mkdir("logs")
    else:
        logs_file = ""

app_logging = logging.getLogger("")
app_logging.setLevel(logging.DEBUG)

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
stdout_handler.setFormatter(formatter)

now = datetime.datetime.now()
now = now.strftime("%d.%m.%Y-%H.%M.%S")
file_handler = logging.FileHandler("%s%sGHW.log" % (logs_file,now), "w", encoding="UTF-8")
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app_logging.addHandler(stdout_handler)
app_logging.addHandler(file_handler)

SERVER_IP = args.ip
SERVER_PORT = args.port
REMOTE_URL = args.repository_url
DIR_NAME = args.save_rep_path
WAIT_FOR_EVENTS = args.wait_until_pull
UPDATE_META = args.fetch_meta

META = "https://api.github.com/meta"
META_FILE = ".%s" % Path(META).stem

AVAILABLE_METHOD = "push"
#---- End of Initial configuration ----#

app = Flask(__name__)

@app.after_request
def request_in(response) -> str:
    status = response.status_code
    try:
        sender_ip = request.headers["X-Forwarded-For"]
    except KeyError:
        sender_ip = request.remote_addr
    method = request.method
    path = request.path
    app_logging.info("%d - %s - %s %s" % (status, sender_ip, method, path))
    return response

@app.post("/")
def hook():
    request.get_json(force=True)

    try:
        from_repo = request.json["repository"]["html_url"]
    except KeyError:
        return Response(status=400)

    try:
        sender_ip = request.headers["X-Forwarded-For"]
    except KeyError:
        sender_ip = request.remote_addr

    for ip in ips:
        range = iptools.IpRangeList(ip)

        if not sender_ip in range:
            continue

        if not REMOTE_URL.find(from_repo) == -1:
            refresh(pull, WAIT_FOR_EVENTS, DIR_NAME, REMOTE_URL)
            return Response(status=200)

        break

    return Response(status=400)

if __name__ == "__main__":

    try:
        if not UPDATE_META: raise KeyError()
        meta = get(META).json()
        ips = meta["hooks"]
        with open(META_FILE, "w") as fp:
            json.dump(meta, fp)
    except KeyError:
        if not Path(META_FILE).is_file():
            print("If running for the first time enable --fetch")
            exit()
        with open(META_FILE, "r") as fp:
            meta = json.load(fp)

    ips = meta["hooks"]

    refresh(pull, WAIT_FOR_EVENTS, DIR_NAME, REMOTE_URL)

    app_logging.info("Server running on address https://%s:%d/" % (SERVER_IP, SERVER_PORT))

    app.run(
        host=               SERVER_IP,
        port=               SERVER_PORT,
        ssl_context=        "adhoc"
    )
