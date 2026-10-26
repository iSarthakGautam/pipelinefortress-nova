# Test targets for scanners/semgrep/rules/python-hardcoded-credential.yaml. Never imported.
# Values are built to look like credentials without being real ones.
import os

# ruleid: pf-python-hardcoded-credential
AWS_KEY = "AKIAEXAMPLEEXAMPLE00"
# ruleid: pf-python-hardcoded-credential
AWS_SECRET = "not-a-real-secret-value-0000"
# ruleid: pf-python-hardcoded-credential
SECRET_KEY = "dev-insecure-flask-secret-key"
# ruleid: pf-python-hardcoded-credential
db_password = "hunter2hunter2"


class Settings:
    def __init__(self):
        # ruleid: pf-python-hardcoded-credential
        self.api_key = "key-kept-in-source-code"


def connect(client):
    # ruleid: pf-python-hardcoded-credential
    return client.login(user="svc", password="s3rvice-pass")


# ok: pf-python-hardcoded-credential
AWS_KEY_FROM_ENV = os.getenv("AWS_KEY")
# too short to be a credential
# ok: pf-python-hardcoded-credential
PASSWORD_MIN = "8"
# placeholder
# ok: pf-python-hardcoded-credential
API_KEY = "<your-api-key>"
# ok: pf-python-hardcoded-credential
DB_PASSWORD = "changeme"
# not a credential name
# ok: pf-python-hardcoded-credential
JWT_ALGORITHM = "HS256-algorithm"
