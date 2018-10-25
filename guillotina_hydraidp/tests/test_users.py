import json

from aioresponses import aioresponses


async def test_create_user(guillotina_hydraidp_requester):
    requester = guillotina_hydraidp_requester
    resp, status = await requester('POST', '/@users', data=json.dumps({
        'id': 'foobar',
        'username': 'foobar',
        'password': 'foobar'
    }))
    assert status == 200

    resp, status = await requester('GET', '/@users/foobar')
    assert status == 200

    resp, status = await requester('GET', '/@users')
    assert len(resp) == 1


async def test_create_user_invalid_data(guillotina_hydraidp_requester):
    requester = guillotina_hydraidp_requester
    resp, status = await requester('POST', '/@users', data=json.dumps({
        'id': 'foobar',
        'username': 'foobar'
    }))
    assert status == 412


async def test_delete_user(guillotina_hydraidp_requester):
    requester = guillotina_hydraidp_requester
    resp, status = await requester('POST', '/@users', data=json.dumps({
        'id': 'foobar',
        'username': 'foobar',
        'password': 'foobar'
    }))
    assert status == 200

    resp, status = await requester('DELETE', '/@users/foobar')
    assert status == 200

    resp, status = await requester('GET', '/@users/foobar')
    assert status == 404


async def test_join(guillotina_hydraidp_requester):
    requester = guillotina_hydraidp_requester

    with aioresponses(passthrough=["http://127.0.0.1"]) as m:
        m.post(
            "https://www.google.com/recaptcha/api/siteverify",
            payload={"success": True},
        )
        resp, status = await requester('POST', '/@hydra-join', data=json.dumps({
            'username': 'foobar',
            'password': 'foobar',
            'recaptcha': 'foobar'
        }))
        assert status == 200

        resp, status = await requester('GET', '/@users')
        assert len(resp) == 1


async def test_join_jwe(guillotina_hydraidp_requester):
    requester = guillotina_hydraidp_requester

    from guillotina_hydraidp import utils
    from Crypto.PublicKey import RSA
    from guillotina import jose

    key = RSA.generate(2048)
    pub_jwk = key.publickey().exportKey('PEM')
    priv_jwk = key.exportKey('PEM')
    utils.REGISTRATION_KEY = {'k': priv_jwk}

    payload = {
        'username': 'foobar',
        'password': 'foobar'
    }

    jwe = jose.encrypt(payload, {'k': pub_jwk})
    token = jose.serialize_compact(jwe).decode('utf-8')

    resp, status = await requester('POST', '/@hydra-join', data=json.dumps(
        {'encrypted': token}))
    assert status == 200

    resp, status = await requester('GET', '/@users')
    assert len(resp) == 1
