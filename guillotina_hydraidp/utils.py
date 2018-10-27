import json
import logging
import uuid

import aiohttp
import argon2
import asyncpg
from guillotina import app_settings, configure
from guillotina.auth.validators import hash_password
from guillotina.component import get_utility
from guillotina.interfaces import (IApplication, IPasswordChecker,
                                   IPasswordHasher)
from pypika import PostgreSQLQuery as Query
from pypika import Table
from Crypto.PublicKey import RSA
from guillotina import jose
from guillotina.event import notify
from guillotina_hydraidp.events import UserCreatedEvent
from guillotina_hydraidp.events import UserModifiedEvent
from guillotina_hydraidp.events import UserRemovedEvent


logger = logging.getLogger(__name__)

users_table = Table('hydra_users')
ph = argon2.PasswordHasher()

DB_ATTR = '_hydraidp_db_pool'
REGISTRATION_KEY = None


@configure.utility(provides=IPasswordHasher, name='argon2')
def argon_pw_hasher(pw, salt):
    return ph.hash(pw + salt)


@configure.utility(provides=IPasswordChecker, name='argon2')
def argon_pw_checker(token, pw):
    split = token.split(':')
    try:
        return ph.verify(split[-1], pw + split[-2])
    except (argon2.exceptions.InvalidHash,
            argon2.exceptions.VerifyMismatchError):
        return False


async def get_db(loop=None):
    db_config = app_settings['hydra']['db']
    if db_config is None:
        return
    if not db_config.get('dsn'):
        return
    root = get_utility(IApplication, name='root')
    if not hasattr(root, DB_ATTR):
        setattr(root, DB_ATTR, await asyncpg.create_pool(
            dsn=db_config['dsn'],
            loop=loop,
            max_size=db_config.get('pool_size', 20),
            min_size=2))
    return getattr(root, DB_ATTR)


async def get_conn(loop=None):
    db_config = app_settings['hydra']['db']
    if db_config is None:
        return
    if not db_config.get('dsn'):
        return
    return await asyncpg.connect(db_config.get('dsn'), loop=loop)


async def get_csrf(request):
    try:
        data = await request.json()
        if 'csrf' in data:
            return data['csrf']
    except Exception:
        pass
    if 'oauth2_authentication_csrf' in request.cookies:
        val = request.cookies['oauth2_authentication_csrf']
        try:
            val = val.value
        except AttributeError:
            pass
        return val
    return ''


async def get_csrf_cookie_str(request):
    csrf = await get_csrf(request)
    if csrf:
        return 'oauth2_authentication_csrf={}'.format(csrf)
    return ''


async def create_user(**data):
    if 'id' not in data:
        data['id'] = str(uuid.uuid4())
    data['password'] = hash_password(data['password'], algorithm='argon2')

    if data.get('email'):
        data['email'] = data['email'].lower()

    db = await get_db()
    query = Query.into(users_table).columns(
        'id', 'username', 'password', 'email', 'phone',
        'data', 'allowed_scopes')
    query = query.insert(
        data['id'], data['username'], data['password'],
        data.get('email') or '',
        data.get('phone') or '',
        json.dumps(data.get('data') or {}),
        json.dumps(data.get('allowed_scopes') or []),
    )
    async with db.acquire() as conn:
        await conn.execute(str(query))

    await notify(UserCreatedEvent(
        data['id'],
        data.get('email', ''),
        data['username'],
        data.get('data', {}),
        data.get('allowed_scopes', [])
    ))
    return data


async def update_user(**data):
    userid = data['id']
    if data.get('password'):
        data['password'] = hash_password(
            data['password'], algorithm='argon2')

    if data.get('email'):
        data['email'] = data['email'].lower()

    db = await get_db()
    query = Query.update(users_table).where(
        users_table.id == userid
    )
    for key, value in data.items():
        if key in ('id', '@id'):
            continue
        if key in ('data', 'allowed_scopes'):
            value = json.dumps(value)
        try:
            query = query.set(getattr(users_table, key), value)
        except AttributeError:
            pass
    async with db.acquire() as conn:
        await conn.execute(str(query))

    await notify(UserModifiedEvent(userid, data))
    return data


async def remove_user(user_id=None, username=None):
    if user_id is not None:
        query = Query.from_(users_table).where(
            users_table.id == user_id
        )
    else:
        query = Query.from_(users_table).where(
            users_table.username == username
        )
    db = await get_db()
    async with db.acquire() as conn:
        await conn.execute(str(query.delete()))
    await notify(UserRemovedEvent(user_id, username))


async def find_users(limit=1000, **filters):
    query = Query.from_(users_table).select(
        users_table.id, users_table.username).limit(1000)
    for key, value in filters.items():
        query = query.where(
            getattr(users_table, key) == value
        )
    db = await get_db()
    async with db.acquire() as conn:
        return await conn.fetch(str(query))


async def find_user(**filters):
    query = Query.from_(users_table).select(
        users_table.id, users_table.username,
        users_table.email, users_table.phone,
        users_table.password, users_table.data,
        users_table.allowed_scopes
    ).limit(1)
    for key, value in filters.items():
        query = query.where(
            getattr(users_table, key) == value
        )
    db = await get_db()
    async with db.acquire() as conn:
        result = await conn.fetch(str(query))
        if len(result) > 0:
            data = dict(result[0])
            data['data'] = json.loads(data['data'])
            data['allowed_scopes'] = json.loads(data['allowed_scopes'])
            return data


async def validate_recaptcha(recaptcha_response):
    async with aiohttp.ClientSession() as session:
        async with await session.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data=dict(
                secret=app_settings["recaptcha"]["private"],
                response=recaptcha_response,
            ),
        ) as resp:
            try:
                data = await resp.json()
            except Exception:  # pragma: no cover
                logger.warning("Did not get json response", exc_info=True)
                return
            try:
                return data["success"]
            except Exception:  # pragma: no cover
                return False


async def validate_payload(payload):
    global REGISTRATION_KEY
    if REGISTRATION_KEY is None and app_settings['registration_key']:
        REGISTRATION_KEY = {'k': RSA.importKey(app_settings['registration_key'])}  # noqa
    try:
        jwt = jose.decrypt(
            jose.deserialize_compact(payload), REGISTRATION_KEY)
        return jwt.claims
    except jose.Expired:
        # expired token
        logger.warn(f'Expired token {payload}', exc_info=True)
        return
    except jose.Error:
        logger.warn(f'Error decrypting JWT token', exc_info=True)
        return
