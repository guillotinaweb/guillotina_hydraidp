import os

import aiohttp
import jsonschema
from guillotina import app_settings, configure
from guillotina.auth.validators import check_password
from guillotina.interfaces import IApplication
from guillotina.response import (HTTPBadRequest, HTTPFound, HTTPNotFound,
                                 HTTPPreconditionFailed, HTTPUnauthorized,
                                 Response)
from guillotina_hydraidp import utils


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


@configure.service(method='POST', name='@hydra-login',
                   context=IApplication, allow_access=True)
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
        return HTTPFound(
            accept_request['redirect_to'],
            headers={
                'Set-Cookie': csrf_cookie
            })
    else:
        raise HTTPUnauthorized(content={
            'text': 'login failed'
        })


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

    if 'hydra_admin_url' not in app_settings:
        raise HTTPBadRequest(content={
            'reason': 'hydra_admin_url not configured'
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
        'csrf': await utils.get_csrf(request)
    }


@configure.service(method='POST', name='@hydra-consent',
                   context=IApplication, allow_access=True)
async def post_consent(context, request):
    if 'hydra_admin_url' not in app_settings:
        raise HTTPBadRequest(content={
            'reason': 'hydra_admin_url not configured'
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
    return HTTPFound(
        accept_request['redirect_to'],
        headers={
            'Set-Cookie': await utils.get_csrf_cookie_str(request)
        })


@configure.service(method='DELETE', name='@hydra-consent',
                   context=IApplication, allow_access=True)
async def del_consent(context, request):
    if 'hydra_admin_url' not in app_settings:
        raise HTTPBadRequest(content={
            'reason': 'hydra_admin_url not configured'
        })

    data = await request.json()
    consent_request = await hydra_admin_request(
        'put', os.path.join('consent', data['challenge'], 'reject'),
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
