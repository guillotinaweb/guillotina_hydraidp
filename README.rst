guillotina_hydraidp
===================

This addon aims to provide an identity provider through guillotina
for hydra.

It also implements the login and consent flow for hydra.


Running tests
-------------

Tests require a hydra instance to be running with the following configuration:

    - OAUTH2_ISSUER_URL=http://localhost:4444
    - OAUTH2_CONSENT_URL=http://localhost:8080/@consent
    - OAUTH2_LOGIN_URL=http://localhost:8080/@login
    - DATABASE_URL=postgres://hydra:secret@postgresd:5432/hydra?sslmode=disable
    - SYSTEM_SECRET=youReallyNeedToChangeThis
    - OAUTH2_SHARE_ERROR_DEBUG=1
    - OIDC_SUBJECT_TYPES_SUPPORTED=public,pairwise
    - OIDC_SUBJECT_TYPE_PAIRWISE_SALT=youReallyNeedToChangeThis
