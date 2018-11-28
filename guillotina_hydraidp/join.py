from guillotina.event import notify

from guillotina import app_settings, configure
from guillotina.interfaces import IApplication
from guillotina.response import HTTPPreconditionFailed
from guillotina_hydraidp import utils
from guillotina_hydraidp.events import UserJoinEvent


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
                "name": {
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
            "required": ["password", "email"]
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
        data = utils.validate_payload(data['encrypted'].encode('utf-8'))
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

    if 'id' not in data:
        data['id'] = data['email']

    validate_token = utils.encrypt_internal_payload(data)
    await notify(UserJoinEvent(
        data['id'],
        data.get('email', ''),
        data.get('name', ''),
        data.get('data', {}),
        data.get('allowed_scopes', []),
        validate_token,
    ))

    return {
        'status': 'ok'
    }

