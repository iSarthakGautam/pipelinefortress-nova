# redaction_fixtures.py
# Adversarial redaction fixtures (PLAN §4.5). Every secret below is FAKE and assembled from parts at import
# time so that secret scanners (gitleaks, GitHub push protection) do not flag this repo.
# POSITIVES: (name, text, secret) where `secret` must not survive redaction.
# BENIGN: code that contains nothing secret; anything redacted there counts as over-redaction.

import base64
import random
import string

_R = random.Random(1337)


def _rand(alphabet: str, n: int) -> str:
    return "".join(_R.choice(alphabet) for _ in range(n))


ALNUM = string.ascii_letters + string.digits
AWS_ID = "AKIA" + _rand(string.ascii_uppercase + string.digits, 16)
AWS_ID2 = "ASIA" + _rand(string.ascii_uppercase + string.digits, 16)
AWS_SECRET = _rand(ALNUM + "/+", 40)
GH_CLASSIC = "ghp_" + _rand(ALNUM, 36)
GH_OAUTH = "gho_" + _rand(ALNUM, 36)
GH_FINE = "github_pat_" + _rand(ALNUM + "_", 40)
SLACK = "xox" + "b-" + _rand(string.digits, 11) + "-" + _rand(ALNUM, 24)
GCP = "AIza" + _rand(ALNUM + "-_", 35)
STRIPE = "sk_" + "live_" + _rand(ALNUM, 24)
OPENAI = "sk-" + _rand(ALNUM, 40)
JWT = "eyJ" + _rand(ALNUM, 20) + "." + "eyJ" + _rand(ALNUM, 30) + "." + _rand(ALNUM + "-_", 43)
PASSWORD = "Sup3r" + "Secret" + "Passw0rd!" + "2024"
PEM_BODY = _rand(ALNUM + "+/", 64)
HEX_TOKEN = _rand("0123456789abcdef", 40)


def _pem(kind: str = "RSA ") -> str:
    return f"-----BEGIN {kind}PRIVATE KEY-----\n{PEM_BODY}\n{PEM_BODY}\n-----END {kind}PRIVATE KEY-----"


def _homoglyph(s: str) -> str:
    return s.replace("I", "\u0406", 1).replace("A", "\u0410", 1)  # Cyrillic І and А


POSITIVES = [
    # AWS
    ("aws-id-assign", f"AWS_KEY = '{AWS_ID}'", AWS_ID),
    ("aws-id-env", f"export AWS_ACCESS_KEY_ID={AWS_ID}", AWS_ID),
    ("aws-id-yaml", f"access_key: {AWS_ID}", AWS_ID),
    ("aws-sts-id", f"key = \"{AWS_ID2}\"", AWS_ID2),
    ("aws-secret-quoted", f"aws_secret_access_key = \"{AWS_SECRET}\"", AWS_SECRET),
    ("aws-secret-env", f"AWS_SECRET_ACCESS_KEY={AWS_SECRET}", AWS_SECRET),
    ("aws-secret-bare", f"# rotate this: {AWS_SECRET}", AWS_SECRET),
    # GitHub / Slack / GCP / Stripe / OpenAI-style
    ("gh-classic", f"token = '{GH_CLASSIC}'", GH_CLASSIC),
    ("gh-classic-curl", f"curl -H 'Authorization: token {GH_CLASSIC}' https://api.github.com", GH_CLASSIC),
    ("gh-oauth", f"GITHUB_TOKEN={GH_OAUTH}", GH_OAUTH),
    ("gh-fine-grained", f"pat = \"{GH_FINE}\"", GH_FINE),
    ("slack-bot", f"SLACK_BOT_TOKEN = '{SLACK}'", SLACK),
    ("slack-inline", f"post(url, headers={{'x': '{SLACK}'}})", SLACK),
    ("gcp-key", f"const key = '{GCP}';", GCP),
    ("gcp-url", f"https://maps.googleapis.com/maps/api/js?key={GCP}", GCP),
    ("stripe-live", f"stripe.api_key = '{STRIPE}'", STRIPE),
    ("openai-style", f"OPENAI_API_KEY={OPENAI}", OPENAI),
    ("openai-inline", f"client = Client(api_key=\"{OPENAI}\")", OPENAI),
    # JWT / bearer
    ("jwt-assign", f"jwt = '{JWT}'", JWT),
    ("jwt-bearer", f"headers = {{'Authorization': 'Bearer {JWT}'}}", JWT),
    ("jwt-log", f"DEBUG token={JWT} expired", JWT),
    # PEM
    ("pem-rsa", _pem("RSA "), PEM_BODY),
    ("pem-ec", _pem("EC "), PEM_BODY),
    ("pem-plain", _pem(""), PEM_BODY),
    ("pem-in-string", f"key = \"\"\"{_pem('OPENSSH ')}\"\"\"", PEM_BODY),
    ("pem-truncated", f"-----BEGIN RSA PRIVATE KEY-----\n{PEM_BODY}", PEM_BODY),
    # passwords (quoted, unquoted, json, yaml, env)
    ("pw-quoted", f"password = \"{PASSWORD}\"", PASSWORD),
    ("pw-unquoted", f"password={PASSWORD}", PASSWORD),
    ("pw-yaml", f"db_password: {PASSWORD}", PASSWORD),
    ("pw-json", f"{{\"password\": \"{PASSWORD}\"}}", PASSWORD),
    ("pw-env", f"DB_PASSWORD={PASSWORD}", PASSWORD),
    ("pw-passwd", f"passwd: '{PASSWORD}'", PASSWORD),
    ("secret-assign", f"client_secret = '{PASSWORD}'", PASSWORD),
    ("apikey-assign", f"api_key = \"{_rand(ALNUM, 32)}\"", None),
    ("token-header", f"X-Auth-Token: {HEX_TOKEN}", HEX_TOKEN),
    # connection strings
    ("pg-conn", f"postgres://app:{PASSWORD}@db.example.org:5432/prod", PASSWORD),
    ("mysql-conn", f"mysql://root:{PASSWORD}@10.2.3.4/shop", PASSWORD),
    ("mongo-conn", f"mongodb+srv://svc:{PASSWORD}@cluster0.example.net/db", PASSWORD),
    ("redis-conn", f"redis://:{PASSWORD}@cache.example.org:6379", None),
    ("amqp-conn", f"amqp://guest:{PASSWORD}@mq.example.org//", PASSWORD),
    # base64-wrapped
    ("b64-aws", "blob = '" + base64.b64encode(f"key={AWS_ID}".encode()).decode() + "'", None),
    ("b64-gh", "cfg = '" + base64.b64encode(f"token={GH_CLASSIC}".encode()).decode() + "'", None),
    ("b64-pw", "data = '" + base64.b64encode(f"password={PASSWORD}".encode()).decode() + "'", None),
    # split across lines / concatenation
    ("split-concat", f"k = '{AWS_ID[:8]}' + \\\n    '{AWS_ID[8:]}'", AWS_ID),
    ("split-lines", f"k = (\n  \"{GH_CLASSIC[:20]}\"\n  \"{GH_CLASSIC[20:]}\"\n)", GH_CLASSIC),
    # homoglyph
    ("homoglyph-aws", f"key = '{_homoglyph(AWS_ID)}'", _homoglyph(AWS_ID)),
    # emails
    ("email-plain", "owner: jane.doe@acme-internal.example", "jane.doe@acme-internal.example"),
    ("email-comment", "# ping ops-oncall@payments.example.org on failure", "ops-oncall@payments.example.org"),
    ("email-url", "mailto:cto+alerts@corp.example", "cto+alerts@corp.example"),
    # private / context IPs
    ("ip-10", "db_host = '10.142.1.25'", "10.142.1.25"),
    ("ip-192", "connect to 192.168.1.5 on boot", "192.168.1.5"),
    ("ip-172", "proxy 172.16.4.9:3128", "172.16.4.9"),
    ("ip-metadata", "curl http://169.254.169.254/latest/meta-data/", "169.254.169.254"),
    ("ip-public-context", "server_ip = '203.0.113.77'", "203.0.113.77"),
    ("ip-public-at", "ssh deploy@198.51.100.23", "198.51.100.23"),
    ("ipv6-full", "bind 2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
    ("ipv6-short", "addr = fd00::1a2b:3c4d", "fd00::1a2b:3c4d"),
    # internal hostnames
    ("host-internal", "dsn = 'payments-db.internal.corp'", "payments-db.internal.corp"),
    ("host-local", "redis_host = cache-01.prod.local", "cache-01.prod.local"),
    ("host-cluster", "svc = orders.shop.svc.cluster.local", "orders.shop.svc.cluster.local"),
    ("host-lan", "nas = files-01.office.lan", "files-01.office.lan"),
    # entropy-only
    ("entropy-bare", f"x = '{_rand(ALNUM, 48)}'", None),
    ("entropy-hexish-mixed", f"signing = {_rand(ALNUM + '_-', 44)}", None),
]

BENIGN = [
    "def search_items(q):\n    return db.query(f'SELECT * FROM items WHERE name = {q}')",
    "cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))",
    "lodash 4.17.21.0",
    "requests==2.31.0\nflask>=2.3.2",
    "FROM node:20.11.1-alpine@sha256:" + _rand("0123456789abcdef", 64),
    "version: 1.2.3.4 # not an address",
    "password = os.environ['DB_PASSWORD']",
    "token = get_token()",
    "api_key = request.headers.get('X-Api-Key')",
    "secret = config.secrets.lookup('payments')",
    "DB_PASSWORD=${DB_PASSWORD}",
    "const user = await User.findOne({ email: req.body.email })",
    "id = '550e8400-e29b-41d4-a716-446655440000'",
    "commit 3f786850e387550fdab836ed7e6dc881de23001b",
    "securityContext:\n  runAsNonRoot: false",
    "app.use(helmet.frameguard({ action: 'deny' }))",
    "<div>Hello {{ username | safe }}</div>",
    "org.apache.logging.log4j:log4j-core:2.14.1",
    "ThisIsAVeryLongCamelCaseIdentifierNameForAClass = 1",
    "def calculate_total_with_tax_and_shipping_costs(items): pass",
    "timestamp = '12:30:45'",
    "mac = 'aa:bb:cc:dd:ee:ff'",
    "url = 'https://example.com/docs/getting-started'",
    "see RFC 1918 and CWE-89 for details",
    "x = [1, 2, 3, 4]  # 10 20 30 40",
    "import os\nimport sys\nprint('hello world')",
    "ENV NODE_ENV=production",
    "mock_key = 'test_token_1234567890'",
    "path = '/usr/local/lib/python3.13/site-packages/flask/app.py'",
    "assert response.status_code == 200",
]


def random_secret_cases(n: int = 400, seed: int = 99):
    """Property-test generator: random benign code with a random secret embedded. Yields (text, secret)."""
    r = random.Random(seed)
    makers = [
        lambda: "AKIA" + "".join(r.choice(string.ascii_uppercase + string.digits) for _ in range(16)),
        lambda: "ghp_" + "".join(r.choice(ALNUM) for _ in range(36)),
        lambda: "eyJ" + "".join(r.choice(ALNUM) for _ in range(20)) + "." + "eyJ" + "".join(r.choice(ALNUM) for _ in range(30)) + "." + "".join(r.choice(ALNUM) for _ in range(40)),
        lambda: "xox" + "b-" + "".join(r.choice(string.digits) for _ in range(11)) + "-" + "".join(r.choice(ALNUM) for _ in range(24)),
        lambda: "AIza" + "".join(r.choice(ALNUM + "-_") for _ in range(35)),
    ]
    templates = ["x = '{s}'", "TOKEN={s}", "call(\"{s}\")", "# {s}", "headers['k'] = '{s}'", "{{\"k\": \"{s}\"}}"]
    code = ["def f(a, b):\n    return a + b\n", "import json\n", "class A:\n    pass\n", ""]
    for _ in range(n):
        s = r.choice(makers)()
        yield r.choice(code) + r.choice(templates).format(s=s) + "\n" + r.choice(code), s
