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
