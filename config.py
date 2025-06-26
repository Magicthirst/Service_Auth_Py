import os


def generate_key():
    import sys
    import base64

    sys.stderr.write('WARNING generated key is used\n')
    return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')


protocol = 'http'
host = os.environ.get("IP") or '0.0.0.0'
port = os.environ.get("PORT") or 8000

run_url = f'{protocol}://{host}:{port}'

db_path = os.environ.get("DB") or 'users.db'

auth_key = os.environ.get("AUTH_KEY") or generate_key()
auth_algorithm = 'HS256'
auth_token_lifespan_seconds = 7 * 24 * 60 * 60
