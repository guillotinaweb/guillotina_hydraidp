import pytest
from guillotina import testing
from guillotina.tests.fixtures import annotations
from guillotina_hydraidp import utils


def base_settings_configurator(settings):
    if 'applications' in settings:
        settings['applications'].append('guillotina_hydraidp')
    else:
        settings['applications'] = ['guillotina_hydraidp']

    settings['hydra_db'] = {
        'dsn': 'postgres://postgres:@{}:{}/guillotina'.format(
            annotations.get('pg_host', 'localhost'),
            annotations.get('pg_port', 5432),
        ),
        'pool_size': 10
    }


testing.configure_with(base_settings_configurator)


@pytest.fixture(scope='function')
async def guillotina_hydraidp_requester(guillotina):
    yield guillotina
    db = await utils.get_db()
    async with db.acquire() as conn:
        await conn.execute('drop table hydra_users')
