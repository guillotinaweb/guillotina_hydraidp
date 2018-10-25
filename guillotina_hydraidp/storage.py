import logging

import asyncpg
from guillotina import configure
from guillotina.db.oid import MAX_OID_LENGTH
from guillotina.db.storages.utils import get_table_definition
from guillotina.interfaces import IApplicationInitializedEvent
from guillotina_hydraidp import utils

logger = logging.getLogger(__name__)


_users_schema = {
    'id': f'VARCHAR({MAX_OID_LENGTH}) NOT NULL PRIMARY KEY',
    'username': f'VARCHAR(255) NOT NULL UNIQUE',
    'password': f'VARCHAR(512) NOT NULL UNIQUE',
    'email': f'VARCHAR(255) NULL UNIQUE',
    'phone': f'VARCHAR(30) NULL',
    'allowed_scopes': f'JSONB',
    'data': 'JSONB'
}


_initialize_statements = [
    'CREATE INDEX IF NOT EXISTS user_id ON hydra_users (id);',
    'CREATE INDEX IF NOT EXISTS user_username ON hydra_users (username);',
    'CREATE INDEX IF NOT EXISTS user_email ON hydra_users (email);',
    'CREATE INDEX IF NOT EXISTS user_phone ON hydra_users (phone);',
    'CREATE INDEX IF NOT EXISTS user_gin_idx ON hydra_users USING gin (allowed_scopes jsonb_path_ops);',  # noqa
]


@configure.subscriber(for_=IApplicationInitializedEvent)
async def initialize(event):
    db = await utils.get_db(event.loop)
    if db is None:
        return

    statements = [
        get_table_definition('hydra_users', _users_schema)
    ]
    statements.extend(_initialize_statements)

    async with db.acquire() as connection:
        # Open a transaction.
        async with connection.transaction():
            for statement in statements:
                try:
                    await connection.execute(statement)
                except asyncpg.exceptions.UniqueViolationError:
                    # this is okay on creation
                    # # means 2 getting created at same time
                    pass
