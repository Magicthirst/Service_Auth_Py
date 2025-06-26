from datetime import datetime, UTC

from jwcrypto import jwk, jwe
from jwcrypto.common import json_encode, json_decode
from attrs import define


@define
class Claims:
    iss: str  # issuer
    sub: str  # subject
    aud: str  # audience
    exp: int  # expiration time (utc seconds)
    iat: int  # issued at (utc seconds)
    jti: int  # jwt id

    def to_dict(self):
        return {
            'iss': self.iss,
            'sub': self.sub,
            'aud': self.aud,
            'exp': self.exp,
            'iat': self.iat,
            'jti': self.jti
        }


class Auth:
    def __init__(self, key: str, algorithm: str, issuer: str, token_lifespan_seconds: int = 900):
        self.key = key
        self.jwk_key = jwk.JWK(kty='oct', k=key)
        self.algorithm = algorithm
        self.issuer = issuer
        self.token_lifespan_seconds = token_lifespan_seconds
        self.claims_count = 0

    def jwe(self, subject: str) -> str:
        protected_header = {
            'alg': 'A256KW',   # AES Key Wrap with 256-bit key
            'enc': 'A256GCM',  # AES GCM with 256-bit key
            'iss': self.issuer,
            'sub': subject,
            'aud': subject
        }
        payload = Claims(
            iss=self.issuer,
            sub=subject,
            aud=subject,
            exp=int(datetime.now(UTC).timestamp()) + self.token_lifespan_seconds,
            iat=int(datetime.now(UTC).timestamp()),
            jti=self._next_jti()
        ).to_dict()

        jwe_token = jwe.JWE(
            plaintext=json_encode(payload).encode('utf-8'),
            protected=protected_header,
            recipient=self.jwk_key
        )

        return jwe_token.serialize(compact=True)

    def validate(self, token: str, owner: str | None = None) -> str | Claims:
        try:
            jwe_token = jwe.JWE()
            jwe_token.deserialize(token, key=self.jwk_key)

            payload = json_decode(jwe_token.payload.decode('utf-8'))
            claims = Claims(**payload)

            if claims.exp < int(datetime.now(UTC).timestamp()):
                return 'Timeout'

            if owner is not None and claims.aud != owner:
                return 'Impersonation is bad'

            return claims

        except jwe.InvalidJWEData:
            return 'Invalid token data'
        except jwe.InvalidJWEOperation:
            return 'Invalid JWE operation'

    def _next_jti(self) -> str:
        self.claims_count = self.claims_count + 1
        return str(hash(str(self.claims_count)))
