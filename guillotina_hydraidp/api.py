import json
import os
import uuid

import aiohttp
import argon2
from guillotina import app_settings, configure
from guillotina.response import (HTTPBadRequest, HTTPFound, HTTPNotFound,
                                 HTTPUnauthorized, Response)
from guillotina_hydraidp import utils
from pypika import PostgreSQLQuery as Query
from pypika import Table

users_table = Table('hydra_users')
ph = argon2.PasswordHasher()


async def get_csrf(request):
    try:
        data = await request.json()
        if 'csrf' in data:
            return data['csrf']
    except Exception:
        pass
    if 'oauth2_authentication_csrf' in request.cookies:
        return request.cookies['oauth2_authentication_csrf']


async def get_csrf_cookie_str(request):
    csrf = await get_csrf(request)
    if csrf:
        return 'oauth2_authentication_csrf={}'.format(csrf)


async def hydra_admin_request(method, path, **kwargs):
    async with aiohttp.ClientSession() as session:
        func = getattr(session, method.lower())
        url = '{}/oauth2/auth/requests/{}'.format(
            app_settings['hydra_admin_url'].rstrip('/'),
            path.strip('/')
        )
        async with func(url, **kwargs) as resp:
            if resp.status < 200 or resp.status > 302:
                try:
                    content = await resp.json()
                except Exception:
                    content = {
                        'reason': await resp.text()
                    }
                if resp.status == 404:
                    content['reason'] = 'Invalid configuration'
                raise Response(content=content, status=resp.status)
            return await resp.json()


@configure.service(method='POST', name='@login',
                   allow_access=True)
async def post_login(context, request):
    '''
    After challenge initiated, use this to actually login!
    '''
    if 'hydra_admin_url' not in app_settings:
        raise HTTPBadRequest(content={
            'reason': 'hydra_admin_url not configured'
        })

    data = await request.json()
    pw = data['password']
    username = data.get('username', data.get('login'))
    challenge = data['challenge']
    remember = data.get('remember') or False

    query = Query.from_(users_table).select(
        users_table.id, users_table.username,
        users_table.password
    ).where(
        users_table.username == username
    )
    db = await utils.get_db()
    async with db.acquire() as conn:
        result = await conn.fetch(str(query))
        if len(result) == 0:
            raise HTTPUnauthorized(content={
                'text': 'login failed'
            })
        user = result[0]

    if ph.verify(user['password'], pw):
        csrf_cookie = await get_csrf_cookie_str(request)
        accept_request = await hydra_admin_request(
            'put', os.path.join('login', challenge, 'accept'),
            json={
                'subject': user['id'],
                'remember': remember,
                'remember_for': 3600,

                # acr is a value to represent level of authentication.
                # this can be used with 2-factor auth schemes
                'acr': "0"
            },
            headers={
                'Set-Cookie': csrf_cookie
            }
        )
        return HTTPFound(
            accept_request['redirect_to'],
            headers={
                'Set-Cookie': csrf_cookie
            })
    else:
        raise HTTPUnauthorized(content={
            'text': 'login failed'
        })


@configure.service(method='GET', name='@login',
                   allow_access=True)
async def get_login(context, request):
    '''
    start login challenge from hydra
    '''
    challenge = request.url.query.get('login_challenge')
    if not challenge:
        raise HTTPBadRequest(content={
            'reason': 'login_challenge not present'
        })

    if 'hydra_admin_url' not in app_settings:
        raise HTTPBadRequest(content={
            'reason': 'hydra_admin_url not configured'
        })

    login_request = await hydra_admin_request(
        'get', os.path.join('login', challenge),
        headers={
            'Set-Cookie': await get_csrf_cookie_str(request)
        })

    if login_request['skip']:
        # already authenticated! skip and return token immediately
        accept_request = await hydra_admin_request(
            'put', os.path.join('login', challenge, 'accept'),
            json={
                'subject': login_request['subject']
            },
            headers={
                'Set-Cookie': await get_csrf_cookie_str(request)
            }
        )
        return HTTPFound(
            accept_request['redirect_to'],
            headers={
                'Set-Cookie': await get_csrf_cookie_str(request)
            })
    return {
        'type': 'login',
        'challenge': challenge,
        'csrf': await get_csrf(request)
    }


@configure.service(method='GET', name='@consent',
                   allow_access=True)
async def consent(context, request):
    if 'hydra_admin_url' not in app_settings:
        raise HTTPBadRequest(content={
            'reason': 'hydra_admin_url not configured'
        })

    challenge = request.url.query.get('consent_challenge')
    if not challenge:
        raise HTTPBadRequest(content={
            'reason': 'consent_challenge not present'
        })

    consent_request = await hydra_admin_request(
        'get', os.path.join('consent', challenge),
        headers={
            'Set-Cookie': await get_csrf_cookie_str(request)
        })
    if consent_request['skip']:
        # already authenticated! skip and return token immediately
        accept_request = await hydra_admin_request(
            'put', os.path.join('consent', challenge, 'accept'),
            json={
                'grant_scope': consent_request['requested_scope'],
                # The session allows us to set session data for id
                # and access tokens
                'session': {
                    # This data will be available when introspecting the token.
                    # Try to avoid sensitive information here,
                    # unless you limit who can introspect tokens.
                    # access_token: { foo: 'bar' },
                }
            },
            headers={
                'Set-Cookie': await get_csrf_cookie_str(request)
            }
        )
        return HTTPFound(
            accept_request['redirect_to'],
            headers={
                'Set-Cookie': await get_csrf_cookie_str(request)
            })
    return {
        'type': 'consent',
        'challenge': challenge,
        'requested_scope': consent_request['requested_scope'],
        'subject': consent_request['subject'],
        'client': consent_request['client'],
        'csrf': await get_csrf(request)
    }


@configure.service(method='POST', name='@consent',
                   allow_access=True)
async def post_consent(context, request):
    if 'hydra_admin_url' not in app_settings:
        raise HTTPBadRequest(content={
            'reason': 'hydra_admin_url not configured'
        })

    data = await request.json()
    remember = data.get('remember') or False

    query = Query.from_(users_table).select(
        users_table.id, users_table.username,
        users_table.email, users_table.phone,
        users_table.data, users_table.password
    ).where(
        users_table.id == data['subject']
    )

    db = await utils.get_db()
    async with db.acquire() as conn:
        result = await conn.fetch(str(query))
        if len(result) == 0:
            raise HTTPUnauthorized(content={
                'text': 'login failed'
            })
        user = result[0]

    accept_request = await hydra_admin_request(
        'put', os.path.join('consent', data['challenge'], 'accept'),
        json={
            'grant_scope': data['requested_scope'],
            # The session allows us to set session data for id
            # and access tokens
            'session': {
                'access_token': {
                    'username': user['username'],
                },
                'id_token': {
                    'username': user['username'],
                    'email': user['email'],
                    'phone': user['phone'],
                    'data': json.loads(user['data']),
                }
            },
            'remember': remember,
            'remember_for': 3600
        },
        headers={
            'Set-Cookie': await get_csrf_cookie_str(request)
        }
    )
    return HTTPFound(
        accept_request['redirect_to'],
        headers={
            'Set-Cookie': await get_csrf_cookie_str(request)
        })


@configure.service(method='DELETE', name='@consent',
                   allow_access=True)
async def deny_consent(context, request):
    if 'hydra_admin_url' not in app_settings:
        raise HTTPBadRequest(content={
            'reason': 'hydra_admin_url not configured'
        })

    data = await request.json()
    consent_request = await hydra_admin_request(
        'put', os.path.join('consent', data['challenge'], 'reject'),
        headers={
            'Set-Cookie': await get_csrf_cookie_str(request)
        })
    return consent_request


@configure.service(
    method='POST', name='@users',
    permission='guillotina.ManageAddons')
async def add_user(context, request):
    data = await request.json()
    if 'id' not in data:
        data['id'] = str(uuid.uuid4())
    data['password'] = ph.hash(
        data['password'].encode('utf-8'))
    db = await utils.get_db()
    query = Query.into(users_table).columns(
        'id', 'username', 'password', 'email', 'phone', 'data')
    query = query.insert(
        data['id'], data['username'], data['password'],
        data.get('email') or '',
        data.get('phone') or '',
        json.dumps(data.get('data') or {}),
    )
    async with db.acquire() as conn:
        await conn.execute(str(query))

    del data['password']
    return data


@configure.service(
    method='DELETE', name='@users/{userid}',
    permission='guillotina.ManageAddons')
async def delete_user(context, request):
    user_id = request.matchdict['userid']
    query = Query.from_(users_table).where(
        users_table.id == user_id
    )
    db = await utils.get_db()
    async with db.acquire() as conn:
        await conn.execute(str(query.delete()))


@configure.service(
    method='GET', name='@users',
    permission='guillotina.ManageAddons')
async def get_users(context, request):
    query = Query.from_(users_table).select(
        users_table.id, users_table.username).limit(1000)
    db = await utils.get_db()
    async with db.acquire() as conn:
        result = await conn.fetch(str(query))

    output = []
    for item in result:
        output.append({
            'id': item['id'],
            'username': item['username']
        })
    return output


@configure.service(
    method='GET', name='@users/{userid}',
    permission='guillotina.ManageAddons')
async def get_user(context, request):
    db = await utils.get_db()
    user_id = request.matchdict['userid']
    query = Query.from_(users_table).select(
        users_table.id, users_table.username,
        users_table.email, users_table.phone,
        users_table.data
    ).where(
        users_table.id == user_id
    )
    async with db.acquire() as conn:
        results = await conn.fetch(str(query))
        if len(results) > 0:
            item = dict(results[0])
            item['data'] = json.loads(item['data'])
            return item
    raise HTTPNotFound(content={
        'reason': f'{user_id} does not exit'
    })
