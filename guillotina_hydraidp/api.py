import os
from guillotina.event import notify
from guillotina.events import UserLogin
from guillotina.auth import authenticate_user

import aiohttp
import asyncpg
import jsonschema
from guillotina import app_settings, configure
from guillotina.auth.validators import check_password
from guillotina.interfaces import IApplication
from guillotina.response import (HTTPBadRequest, HTTPConflict, HTTPFound,
                                 HTTPNotFound, HTTPPreconditionFailed,
                                 HTTPUnauthorized, Response)
from guillotina.utils import get_authenticated_user_id
from guillotina_authentication import utils as auth_utils
from guillotina_hydraidp import utils
from yarl import URL


async def hydra_admin_request(method, path, **kwargs):
    async with aiohttp.ClientSession() as session:
        func = getattr(session, method.lower())
        url = '{}/oauth2/auth/requests/{}'.format(
            app_settings['hydra']['admin_url'].rstrip('/'),
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


@configure.service(method='POST', name='@hydra-challenge',
                   context=IApplication, allow_access=True)
async def get_challenge(context, request):
    client = auth_utils.get_client('hydra')
    callback_url = str(request.url.with_path('@callback/hydra'))
    url = URL(await auth_utils.get_authorization_url(
        client, callback=callback_url,
        scope=' '.join(app_settings['hydra']['granted_scopes'])))
    async with aiohttp.ClientSession() as session:
        while 'login_challenge' not in url.query:
            async with session.get(url, allow_redirects=False) as resp:
                if resp.status not in (200, 301, 302):
                    return HTTPBadRequest(content={
                        'reason': 'configuration error',
                        'extra': await resp.text()
                    })
                if resp.status not in (301, 302):
                    break
                url = URL(resp.headers['Location'])
    csrf = await utils.get_csrf(resp)
    return {
        'csrf': csrf,
        'challenge': url.query.get('login_challenge')
    }


@configure.service(method='POST', name='@hydra-login',
                   context=IApplication, allow_access=True)
async def post_login(context, request):
    '''
    After challenge initiated, use this to actually login!
    '''
    if 'admin_url' not in app_settings['hydra']:
        raise HTTPBadRequest(content={
            'reason': 'hydra admin_url not configured'
        })

    data = await request.json()
    pw = data['password']
    username = data.get('username', data.get('login', ''))
    email = data.get('email')
    challenge = data['challenge']
    remember = data.get('remember') or False

    if email is None and '@' in username:
        # username entered as email
        email = username

    if email is not None:
        user = await utils.find_user(email=email.lower())
    else:
        user = await utils.find_user(username=username)
    if user is None:
        raise HTTPUnauthorized(content={
            'text': 'login failed'
        })

    if check_password(user['password'], pw):
        csrf_cookie = await utils.get_csrf_cookie_str(request)
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
        if not data.get('auto_grant', False):
            return {
                'url': accept_request['redirect_to'],
                'user': user
            }
        else:
            return await _login_user(
                request, accept_request, user)
    else:
        raise HTTPUnauthorized(content={
            'text': 'login failed'
        })


async def _login_user(request, accept_data, user):
    # log user in directly now
    async with aiohttp.ClientSession() as session:
        csrf = await utils.get_csrf_cookie_str(request)
        async with session.get(accept_data['redirect_to'], headers={
                    'Cookie': csrf
                }, allow_redirects=False) as resp:
            assert resp.status == 302
            url = URL(resp.headers['Location'])
            challenge = url.query['consent_challenge']
            consent = await _get_consent(challenge)

            accept_request = await hydra_admin_request(
                'put', os.path.join('consent', challenge, 'accept'),
                json={
                    'grant_scope': consent['requested_scope'],
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
                            'data': user['data'],
                            'allowed_scopes': user['allowed_scopes'],
                        }
                    },
                    'remember': False,
                    'remember_for': 3600
                }
            )

            auth_url = URL(accept_request['redirect_to'])
            async with session.get(auth_url, headers={
                        'Cookie': csrf
                    }, allow_redirects=False) as resp:
                url = URL(resp.headers['Location'])
                assert 'code' in url.query
                code = url.query['code']
                client = auth_utils.get_client('hydra')
                callback = auth_url.query['redirect_uri']

                otoken, _ = await client.get_access_token(
                    code, redirect_uri=callback)

                client_args = dict(access_token=otoken)
                user, user_data = await client.user_info()

                jwt_token, data = authenticate_user(user.id, {
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'email': user.email,
                    'username': user.username,
                    'client': 'hydra',
                    'client_args': client_args,
                    'allowed_scopes': user_data.get('allowed_scopes'),
                    'scope': consent['requested_scope'],
                })

                await notify(UserLogin(user, jwt_token))

                return {
                    'exp': data['exp'],
                    'token': jwt_token
                }


async def _get_consent(challenge):
    return await hydra_admin_request(
        'get', os.path.join('consent', challenge))


@configure.service(method='GET', name='@hydra-login',
                   context=IApplication, allow_access=True)
async def get_login(context, request):
    '''
    start login challenge from hydra
    '''
    challenge = request.url.query.get('login_challenge')
    if not challenge:
        raise HTTPBadRequest(content={
            'reason': 'login_challenge not present'
        })

    if 'admin_url' not in app_settings['hydra']:
        raise HTTPBadRequest(content={
            'reason': 'hydra admin_url not configured'
        })

    login_request = await hydra_admin_request(
        'get', os.path.join('login', challenge),
        headers={
            'Set-Cookie': await utils.get_csrf_cookie_str(request)
        })

    if login_request['skip']:
        # already authenticated! skip and return token immediately
        accept_request = await hydra_admin_request(
            'put', os.path.join('login', challenge, 'accept'),
            json={
                'subject': login_request['subject']
            },
            headers={
                'Set-Cookie': await utils.get_csrf_cookie_str(request)
            }
        )
        return HTTPFound(
            accept_request['redirect_to'],
            headers={
                'Set-Cookie': await utils.get_csrf_cookie_str(request)
            })
    return {
        'type': 'login',
        'challenge': challenge,
        'csrf': await utils.get_csrf(request)
    }


@configure.service(method='GET', name='@hydra-consent',
                   context=IApplication, allow_access=True)
async def consent(context, request):
    if 'admin_url' not in app_settings['hydra']:
        raise HTTPBadRequest(content={
            'reason': 'hydra admin_url not configured'
        })

    challenge = request.url.query.get('consent_challenge')
    if not challenge:
        raise HTTPBadRequest(content={
            'reason': 'consent_challenge not present'
        })

    consent_request = await hydra_admin_request(
        'get', os.path.join('consent', challenge),
        headers={
            'Set-Cookie': await utils.get_csrf_cookie_str(request)
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
                'Set-Cookie': await utils.get_csrf_cookie_str(request)
            }
        )
        return HTTPFound(
            accept_request['redirect_to'],
            headers={
                'Set-Cookie': await utils.get_csrf_cookie_str(request)
            })

    return {
        'type': 'consent',
        'challenge': challenge,
        'requested_scope': consent_request['requested_scope'],
        'subject': consent_request['subject'],
        'client': consent_request['client'],
        'csrf': await utils.get_csrf(request),
        'user': await utils.find_user(id=consent_request['subject'])
    }


@configure.service(method='POST', name='@hydra-consent',
                   context=IApplication, allow_access=True)
async def post_consent(context, request):
    if 'admin_url' not in app_settings['hydra']:
        raise HTTPBadRequest(content={
            'reason': 'hydra admin_url not configured'
        })

    data = await request.json()
    remember = data.get('remember') or False

    user = await utils.find_user(id=data['subject'])
    if user is None:
        raise HTTPUnauthorized(content={
            'text': 'login failed'
        })

    # XXX check valid scopes

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
                    'data': user['data'],
                    'allowed_scopes': user['allowed_scopes'],
                }
            },
            'remember': remember,
            'remember_for': 3600
        },
        headers={
            'Set-Cookie': await utils.get_csrf_cookie_str(request)
        }
    )
    return {
        'url': accept_request['redirect_to'],
        'user': user
    }


@configure.service(method='DELETE', name='@hydra-consent',
                   context=IApplication, allow_access=True)
async def del_consent(context, request):
    if 'admin_url' not in app_settings['hydra']:
        raise HTTPBadRequest(content={
            'reason': 'hydra admin_url not configured'
        })

    challenge = request.url.query.get('consent_challenge')
    consent_request = await hydra_admin_request(
        'put', os.path.join('consent', challenge, 'reject'),
        headers={
            'Set-Cookie': await utils.get_csrf_cookie_str(request)
        })
    return consent_request


@configure.service(
    method='POST', name='@users',
    permission='guillotina.ManageAddons',
    context=IApplication,
    summary='Create user',
    parameters=[{
        "name": "body",
        "in": "body",
        "schema": {
            "$ref": "#/definitions/HydraUser"
        }
    }],
    responses={
        "200": {
            "schema": {
                "$ref": "#/definitions/HydraUser"
            }
        }
    })
async def post_user(context, request):
    data = await request.json()
    try:
        jsonschema.validate(
            data, app_settings['json_schema_definitions']['HydraUser'])
    except (jsonschema.ValidationError,
            jsonschema.SchemaError) as e:
        raise HTTPPreconditionFailed(content={
            'message': e.message
        })

    try:
        data = await utils.create_user(**data)
    except asyncpg.exceptions.UniqueViolationError:
        raise HTTPConflict(content={
            'reason': 'user already exists'
        })
    del data['password']
    data['@id'] = str(request.url.with_path(f'/@users/{data["id"]}'))
    return data


@configure.service(
    context=IApplication, method='POST', allow_access=True,
    permission='guillotina.AccessContent', name='@hydra-join',
    summary='Join hydra',
    parameters=[{
        "name": "body",
        "in": "body",
        "schema": {
            "type": "object",
            "properties": {
                "username": {
                    "type": "string"
                },
                "password": {
                    "type": "string"
                },
                "email": {
                    "type": "string"
                },
                "phone": {
                    "type": "string"
                },
                "data": {
                    "type": "object"
                },
                "allowed_scopes": {
                    "type": "array"
                },
                "recaptcha": {
                    "type": "string"
                },
                "encrypted": {
                    "type": "string"
                }
            },
            "required": ["username", "password", "email"]
        }
    }])
async def join(context, request):
    if not app_settings['hydra']['allow_registration']:
        raise HTTPPreconditionFailed(content={
            'reason': 'registration is not allowed'
        })
    data = await request.json()
    validated = False
    if 'encrypted' in data and data['encrypted']:
        data = await utils.validate_payload(data['encrypted'].encode('utf-8'))
        if data:
            validated = True
    elif app_settings['recaptcha']['private']:
        if data['recaptcha'] not in (None, '') and \
                await utils.validate_recaptcha(data['recaptcha']):
            validated = True

    if not(validated):
        raise HTTPPreconditionFailed(content={
            'reason': 'invalid client validation'
        })
    if 'id' in data:
        del data['id']
    data = await utils.create_user(**data)
    del data['password']
    data['@id'] = str(request.url.with_path(f'/@users/{data["id"]}'))
    return data


@configure.service(
    method='PATCH', name='@users/{id}',
    permission='guillotina.ManageAddons',
    context=IApplication,
    summary='Update user',
    parameters=[{
        "name": "body",
        "in": "body",
        "schema": {
            "$ref": "#/definitions/HydraUser"
        }
    }],
    responses={
        "200": {
            "schema": {
                "$ref": "#/definitions/HydraUser"
            }
        }
    })
async def update_user(context, request):
    data = await request.json()
    data['id'] = request.matchdict['id']
    data = await utils.update_user(**data)
    if 'password' in data:
        del data['password']
    data['@id'] = str(request.url.with_path(f'/@users/{data["id"]}'))
    return data


@configure.service(
    method='DELETE', name='@users/{userid}',
    permission='guillotina.ManageAddons',
    context=IApplication,
    summary='Delete user',
    parameters=[{
        "name": "userid",
        "in": "path"
    }])
async def delete_user(context, request):
    await utils.remove_user(request.matchdict['userid'])


@configure.service(
    method='GET', name='@users',
    permission='guillotina.ManageAddons',
    context=IApplication,
    summary='Get users',
    responses={
        "200": {
            "schema": {
                "type": "array",
                "items": {
                    "type": "object",
                    "$ref": "#/definitions/HydraUser"
                }
            }
        }
    })
async def get_users(context, request):
    output = []
    for item in await utils.find_users():
        output.append({
            'id': item['id'],
            'username': item['username'],
            '@id': str(request.url.with_path(f'/@users/{item["id"]}'))
        })
    return output


@configure.service(
    method='GET', name='@users/{userid}',
    permission='guillotina.ManageAddons',
    context=IApplication,
    summary='Get user',
    parameters=[{
        "name": "userid",
        "in": "path"
    }],
    responses={
        "200": {
            "description": "Get user",
            "schema": {
                "$ref": "#/definitions/HydraUser"
            }
        }
    })
async def get_user(context, request):
    userid = request.matchdict['userid']
    user = await utils.find_user(id=userid)
    if user is not None:
        del user['password']
        user['@id'] = str(request.url.with_path(f'/@users/{user["id"]}'))
        return user
    raise HTTPNotFound(content={
        'reason': f'{userid} does not exit'
    })


@configure.service(
    method='GET', name='@hydra-user',
    context=IApplication, allow_access=True,
    permission='guillotina.AccessContent',
    summary='GET user data',
    parameters=[{
        "name": "body",
        "in": "body",
        "schema": {
            "type": "object",
            "properties": {
                "password": {
                    "type": "string"
                },
                "email": {
                    "type": "string"
                },
                "phone": {
                    "type": "string"
                },
                "data": {
                    "type": "object"
                },
                "allowed_scopes": {
                    "type": "array"
                }
            },
            "required": ["username", "password", "email"]
        }
    }])
async def get_user_info(context, request):
    userid = get_authenticated_user_id(request)
    if userid == 'root':
        raise HTTPBadRequest(content={
            'reason': 'not a valid user'
        })

    user = await utils.find_user(id=userid)
    if user is None:
        raise HTTPPreconditionFailed(content={
            'reason': 'Not a valid user'
        })

    if 'password' in user:
        del user['password']
    return user


@configure.service(
    method='PATCH', name='@hydra-user',
    context=IApplication, allow_access=True,
    permission='guillotina.AccessContent',
    summary='Modify current user preferences',
    parameters=[{
        "name": "body",
        "in": "body",
        "schema": {
            "type": "object",
            "properties": {
                "password": {
                    "type": "string"
                },
                "email": {
                    "type": "string"
                },
                "phone": {
                    "type": "string"
                },
                "data": {
                    "type": "object"
                },
                "allowed_scopes": {
                    "type": "array"
                }
            },
            "required": ["username", "password", "email"]
        }
    }])
async def edit_user(context, request):
    data = await request.json()

    userid = get_authenticated_user_id(request)
    if userid == 'root':
        raise HTTPBadRequest(content={
            'reason': 'not a valid user'
        })

    user = await utils.find_user(id=userid)
    if user is None:
        raise HTTPPreconditionFailed(content={
            'reason': 'Not a valid user'
        })

    data['id'] = userid
    for key in ('@id', 'username'):
        if key in data:
            del data[key]
    await utils.update_user(**data)
