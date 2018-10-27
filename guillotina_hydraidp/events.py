from zope.interface import implementer
from guillotina_hydraidp.interfaces import IUserCreatedEvent
from guillotina_hydraidp.interfaces import IUserModifiedEvent
from guillotina_hydraidp.interfaces import IUserRemovedEvent


@implementer(IUserCreatedEvent)
class UserCreatedEvent:
    def __init__(self, id_, email, username, data, allowed_scopes):
        self.id = id_
        self.email = email
        self.username = username
        self.data = data
        self.allowed_scopes = allowed_scopes


@implementer(IUserModifiedEvent)
class UserModifiedEvent:
    def __init__(self, id_, data):
        self.id = id_
        self.data = data


@implementer(IUserRemovedEvent)
class UserRemovedEvent:
    def __init__(self, id_, username):
        self.id = id_
        self.username = username
