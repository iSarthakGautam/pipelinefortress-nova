"""Configuration module for vulnshop-api.
Contains application settings and environment variables.
WARNING: Planted security vulnerabilities for DevSecOps testing.
"""
import os

DEBUG = True
APP_PORT = 3000
DATABASE_PATH = os.getenv("DB_PATH", "/tmp/vulnshop.db")
SECRET_KEY = "dev-insecure-flask-secret-key"
# [PLANTED VULN: CWE-798] Hardcoded AWS key
AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'
AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
AWS_REGION = 'us-east-1'

JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24
ALLOWED_HOSTS = ["*"]
CORS_ORIGIN_WHITELIST = ["*"]
