import sys
from typing import Annotated

import uvicorn
from fastapi import FastAPI, Header, status
from fastapi.responses import JSONResponse, Response
from pydantic import create_model

from auth import Auth, Claims
import users_repository as users

from config import *


app = FastAPI()
auth = Auth(auth_key, auth_algorithm, run_url, token_lifespan_seconds=auth_token_lifespan_seconds)


@app.post('/')
def register() -> create_model('RegisteredUuid', uuid=(str, None)):
    return {'uuid': users.new_user()}


@app.get('/login/{uuid}')
def login(uuid: str) -> create_model('LoginToken', token=(str, None)):
    uuid = uuid.upper()

    print(f'{uuid=}')
    if not users.exists(uuid):
        return JSONResponse(
            content={'message': 'This user does not exists'},
            status_code=404
        )

    return {'token': auth.jwe(uuid)}


@app.get('/renew')
def renew(authorisation: Annotated[str | None, Header()] = None) -> str:
    if authorisation is None:
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)

    if authorisation.startswith('Bearer '):
        authorisation = authorisation.replace('Bearer ', '')
    result = auth.validate(authorisation)
    if isinstance(result, str):
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={'message': result})

    claims: Claims = result
    return login(claims.sub)['token']


@app.head('/{uuid}')
def validate_by_jwt(
        uuid: str,
        authorisation: Annotated[str | None, Header()] = None
):
    uuid = uuid.upper()

    if authorisation is None:
        print('401 No authentication token provided', file=sys.stderr)
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)

    validation_error_message = auth.validate(authorisation.replace('Bearer ', ''), uuid)

    if isinstance(validation_error_message, str):
        print(401, validation_error_message)
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)

    return Response(status_code=200)


if __name__ == '__main__':
    users.init()
    uvicorn.run(app, host=host, port=port, log_level='trace')
