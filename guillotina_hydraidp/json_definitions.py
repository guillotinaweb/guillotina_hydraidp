from guillotina import configure


configure.json_schema_definition('HydraUser', {
    "type": "object",
    "title": "User data",
    "properties": {
        "id": {
            "type": "string"
        },
        "@id": {
            "type": "string"
        },
        "username": {
            "type": "string"
        },
        "password": {
            "type": "string"
        },
        "email": {
            "type": "string"
        },
        "phone": {
            "type": "string"
        },
        "data": {
            "type": "object"
        },
        "allowed_scopes": {
            "type": "array"
        }
    },
    'required': ['username', 'password']
})
