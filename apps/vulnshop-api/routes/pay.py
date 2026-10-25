"""Payment processing route module for vulnshop-api.
Handles checkout transactions and receipt generation.
WARNING: Contains intentionally planted Command Injection vulnerability (CWE-78).
"""
import os
import subprocess
from flask import Blueprint, jsonify, request

pay_bp = Blueprint("pay", __name__, url_prefix="/api/pay")


@pay_bp.route("/process", methods=["POST"])
def process_payment():
    """Vulnerable payment verification executing shell commands (CWE-78)."""
    data = request.get_json() or {}
    card_number = data.get("card_number", "")
    amount = data.get("amount", 0.0)
    receipt_id = data.get("receipt_id", "default_receipt")

    # [PLANTED VULN: CWE-78] Shell command injection via unsanitized receipt_id
    cmd = f"echo 'Transaction for {amount}' > /tmp/{receipt_id}.log"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    return jsonify({
        "status": "APPROVED",
        "receipt_id": receipt_id,
        "amount": amount,
        "log_output": proc.stdout
    })

