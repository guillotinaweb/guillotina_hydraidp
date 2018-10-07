from pytest_docker_fixtures.containers._base import BaseImage
from time import sleep


class Hydra(BaseImage):
    label = 'hydra'
    name = 'hydra'
    port = 4444

    paylods = {
        'client': {
            "client_id": "auth-code-client",
            "client_name": "",
            "redirect_uris": [
                # "http://localhost:8080/@callback/hydra"
            ],
            "grant_types": [
                "authorization_code",
                "refresh_token"
            ],
            "response_types": [
                "code",
                "id_token"
            ],
            "scope": "openid offline",
            "owner": "",
            "policy_uri": "",
            "allowed_cors_origins": [],
            "tos_uri": "",
            "client_uri": "",
            "logo_uri": "",
            "contacts": [],
            "client_secret_expires_at": 0,
            "subject_type": "public",
            "jwks": {
                "keys": None
            },
            "token_endpoint_auth_method": "client_secret_post",
            "userinfo_signed_response_alg": "none"
        }
    }

    def __init__(self, dsn, app_url):
        self.dsn = dsn
        self.app_url = app_url.rstrip('/')

    def get_image_options(self):
        image_options = super().get_image_options()
        image_options.update(dict(
            cap_add=['IPC_LOCK'],
            mem_limit='200m',
            ports={
                f'4444/tcp': '4444',
                f'4445/tcp': '4445',
            },
            environment={
                'OAUTH2_ISSUER_URL': 'http://localhost:4444',
                'OAUTH2_CONSENT_URL': '{}/@consent'.format(self.app_url),
                'OAUTH2_LOGIN_URL': '{}/@login'.format(self.app_url),
                'DATABASE_URL': self.dsn,
                'SYSTEM_SECRET': 'youReallyNeedToChangeThis',
                'OAUTH2_SHARE_ERROR_DEBUG': '1',
                'OIDC_SUBJECT_TYPES_SUPPORTED': 'public,pairwise',
                'OIDC_SUBJECT_TYPE_PAIRWISE_SALT': 'youReallyNeedToChangeThis'
            }
        ))
        return image_options

    def check(self):
        sleep(1)
        return True


def start_hydra(dsn, app_url):
    image = Hydra(dsn, app_rul)
    image.run()
    return image
