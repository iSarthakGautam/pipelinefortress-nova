# Test targets for scanners/semgrep/rules/python-shell-injection.yaml. Deliberately vulnerable; never imported.
import os
import shlex
import subprocess

from flask import request


def process_payment():
    data = request.get_json() or {}
    amount = data.get("amount", 0.0)
    receipt_id = data.get("receipt_id", "default_receipt")
    cmd = f"echo 'Transaction for {amount}' > /tmp/{receipt_id}.log"
    # ruleid: pf-python-flask-shell-injection
    subprocess.run(cmd, shell=True, capture_output=True, text=True)


def other_sinks():
    name = request.args.get("name")
    # ruleid: pf-python-flask-shell-injection
    os.system("ping " + name)
    # ruleid: pf-python-flask-shell-injection
    subprocess.Popen("ls " + request.form["dir"], shell=True)


def safe_forms():
    name = request.args.get("name")
    # argument list, no shell
    # ok: pf-python-flask-shell-injection
    subprocess.run(["ping", "-c", "1", name])
    # quoted
    # ok: pf-python-flask-shell-injection
    subprocess.run("ping -c 1 " + shlex.quote(name), shell=True)
    # constant command, no request data
    # ok: pf-python-flask-shell-injection
    subprocess.run("uptime", shell=True)
