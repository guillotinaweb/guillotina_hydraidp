import requests


# setup
# - create client
# - create user


CLIENT_DATA = {
    "client_id": "auth-code-client",
    "client_name": "",
    "client_secret": "secret",
    "redirect_uris": [
        "http://localhost:8080/@callback/hydra"
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


def test_auth_flow():

    # setup #1: client
    resp = requests.put('http://localhost:4445/clients/auth-code-client',
                        json=CLIENT_DATA)
    if resp.status_code == 404:
        resp = requests.post('http://localhost:4445/clients',
                             json=CLIENT_DATA)
        assert resp.status_code == 201

    # setup #2: user/password
    requests.delete('http://localhost:8080/@users/foobar',
                    auth=('root', 'root'))
    requests.post('http://localhost:8080/@users',
                  json={
                      'id': 'foobar',
                      'username': 'foobar',
                      'password': 'foobar',
                      'allowed_scopes': ['cms:role:guillotina.Member'],
                      'data': {
                          'foo': 'bar'
                      }
                  },
                  auth=('root', 'root'))

    # start test now
    session = requests.Session()
    resp = session.get('http://localhost:8080/@authenticate/hydra')

    # should then be redirects to @hydra-login
    assert resp.status_code == 200
    assert resp.url.startswith('http://localhost:8080/@hydra-login')

    data = resp.json()
    data.update({
        'username': 'foobar',
        'password': 'foobar'
    })
    resp = session.post('http://localhost:8080/@hydra-login', json=data)

    # should then redirect to @hydra-consent
    assert resp.status_code == 200
    assert resp.url.startswith('http://localhost:8080/@hydra-consent')

    data = resp.json()
    resp = session.post('http://localhost:8080/@hydra-consent', json={
        "challenge": data["challenge"],
        "requested_scope": data['requested_scope'],
        "subject": data["subject"],
        "csrf": data['csrf']
    })

    assert resp.status_code == 200
    data = resp.json()
    assert 'token' in data

    resp = session.get(
        'http://localhost:8080/@user', headers={
            'Authorization': 'Bearer {}'.format(data['token'])
        })
    assert resp.status_code == 200
    data = resp.json()
    assert 'guillotina.Authenticated' in data['foobar']['roles']
