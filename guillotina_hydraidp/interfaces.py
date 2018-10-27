from zope.interface import Interface


class IUserCreatedEvent(Interface):
    pass

class IUserModifiedEvent(Interface):
    pass

class IUserRemovedEvent(Interface):
    pass
