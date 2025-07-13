import os


def generate_key():
    import sys
    import base64

    sys.stderr.write('WARNING generated key is used\n')
    return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')


def not_found_env(variable_name):
    raise Exception(f'not found env: {variable_name=}')


protocol = 'http'
host = os.environ.get("IP") or not_found_env()
port = int(os.environ.get("PORT")) or not_found_env()

run_url = f'{protocol}://{host}:{port}'

db_path = os.environ.get("DB") or not_found_env()

auth_key = os.environ.get("AUTH_KEY") or generate_key()
auth_algorithm = 'HS256'
auth_token_lifespan_seconds = 7 * 24 * 60 * 60
