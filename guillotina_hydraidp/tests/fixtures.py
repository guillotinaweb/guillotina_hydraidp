import pytest
from guillotina import testing
from guillotina.tests.fixtures import annotations
from guillotina_hydraidp import utils


def base_settings_configurator(settings):
    if 'applications' in settings:
        settings['applications'].append('guillotina_hydraidp')
    else:
        settings['applications'] = ['guillotina_hydraidp']

    settings['hydra'] = {
        'db': {
            'dsn': 'postgres://postgres:secret@{}:{}/guillotina'.format(
                annotations.get('pg_host', 'localhost'),
                annotations.get('pg_port', 5432),
            ),
            'pool_size': 10
        },
        'allow_registration': True
    }
    settings['recaptcha'] = {
        'public': 'foobar',
        'private': 'foobar'
    }


testing.configure_with(base_settings_configurator)


@pytest.fixture(scope='function')
async def guillotina_hydraidp_requester(guillotina, loop):
    yield guillotina
    import asyncio
    conn = await utils.get_conn(asyncio.get_event_loop())
    await conn.execute('drop table hydra_users;')
    await conn.close()
