import asyncpg
from guillotina import app_settings
from guillotina.component import get_utility
from guillotina.interfaces import IApplication

DB_ATTR = '_hydraidp_db_pool'


async def get_db():
    db_config = app_settings['hydra_db']
    if db_config is None:
        return
    root = get_utility(IApplication, name='root')
    if not hasattr(root, DB_ATTR):
        setattr(root, DB_ATTR, await asyncpg.create_pool(
            dsn=db_config['dsn'],
            max_size=db_config.get('pool_size', 20),
            min_size=2))
    return getattr(root, DB_ATTR)
