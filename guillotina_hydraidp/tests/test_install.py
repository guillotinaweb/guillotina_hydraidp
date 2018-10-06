import asyncio


async def test_install(guillotina_hydraidp_requester):  # noqa
    async with guillotina_hydraidp_requester as requester:
        response, _ = await requester('GET', '/db/guillotina/@addons')
        assert 'guillotina_hydraidp' in response['installed']
