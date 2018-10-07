import json


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
