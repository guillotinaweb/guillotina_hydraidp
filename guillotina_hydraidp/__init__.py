from guillotina import configure


app_settings = {
    'applications': ['guillotina_authentication'],
    # provide custom application settings here...
    'hydra_db': None,
    'hydra_admin_url': None,
    'auth_user_identifiers': [
        'guillotina_authentication.identifier.OAuthClientIdentifier',
        'guillotina_hydraidp.identifier.HydraDBUserIdentifier'
    ]
}


def includeme(root):
    """
    custom application initialization here
    """
    configure.scan('guillotina_hydraidp.api')
    configure.scan('guillotina_hydraidp.storage')
    configure.scan('guillotina_hydraidp.json_definitions')
