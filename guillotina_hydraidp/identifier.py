import logging

from guillotina.auth.users import GuillotinaUser
from guillotina_rediscache import cache
from guillotina_hydraidp import utils
from guillotina_authentication.identifier import OAuthClientIdentifier

logger = logging.getLogger(__name__)

USER_CACHE_DURATION = 60 * 1
NON_IAT_VERIFY = {
    'verify_iat': False,
}


class HydraDBUserIdentifier(OAuthClientIdentifier):

    async def get_user(self, token):
        cache_key = self.get_user_cache_key(token['id'])
        store = cache.get_memory_cache()
        try:
            return store[cache_key]
        except KeyError:
            pass

        user_id = token.get('id')
        if user_id is None:
            return

        user_data = await utils.find_user(username=user_id)

        user = GuillotinaUser(
            user_id=user_data['username'],
            properties=user_data['data'])
        user.password = user_data['password']
        # in oauth context, user can choose to only grant subset of all
        # available. In this context, we give them access to everything
        # on the container
        self.apply_scope(user, {
            'allowed_scopes': user_data['allowed_scopes'],
            'scope': user_data['allowed_scopes'],
        })
        store[cache_key] = user
        return user
