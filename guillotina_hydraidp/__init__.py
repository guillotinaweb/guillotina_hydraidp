from guillotina import configure


app_settings = {
    'applications': ['guillotina_authentication'],
    # provide custom application settings here...
    'auth_user_identifiers': [
        'guillotina_authentication.identifier.OAuthClientIdentifier',
        'guillotina_hydraidp.identifier.HydraDBUserIdentifier'
    ],
    'hydra': {
        'db': None,
        'admin_url': None,
        'allow_registration': False,
        'granted_scopes': []
    },
    'recaptcha': {
        'public': None,
        'private': None,
    },
    'registration_key': None
}


def includeme(root):
    """
    custom application initialization here
    """
    configure.scan('guillotina_hydraidp.api')
    configure.scan('guillotina_hydraidp.storage')
    configure.scan('guillotina_hydraidp.json_definitions')
