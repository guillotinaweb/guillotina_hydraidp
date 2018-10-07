import json
import uuid

import argon2
import asyncpg
from guillotina import app_settings
from guillotina.auth.validators import (check_functions, hash_functions,
                                        hash_password)
from guillotina.component import get_utility
from guillotina.interfaces import IApplication
from pypika import PostgreSQLQuery as Query
from pypika import Table

users_table = Table('hydra_users')
ph = argon2.PasswordHasher()

DB_ATTR = '_hydraidp_db_pool'
hash_functions['argon2'] = ph.hash


def argon_check_func(token, pw):
    split = token.split(':')
    try:
        return ph.verify(split[-1], pw + split[-2])
    except (argon2.exceptions.InvalidHash,
            argon2.exceptions.VerifyMismatchError):
        return False


check_functions['argon2'] = argon_check_func


async def get_db():
    db_config = app_settings['hydra_db']
    if db_config is None:
        return
    if not db_config.get('dsn'):
        return
    root = get_utility(IApplication, name='root')
    if not hasattr(root, DB_ATTR):
        setattr(root, DB_ATTR, await asyncpg.create_pool(
            dsn=db_config['dsn'],
            max_size=db_config.get('pool_size', 20),
            min_size=2))
    return getattr(root, DB_ATTR)


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


async def create_user(**data):
    if 'id' not in data:
        data['id'] = str(uuid.uuid4())
    data['password'] = hash_password(data['password'], algorithm='argon2')
    db = await get_db()
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
        users_table.password, users_table.data
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
            return data
