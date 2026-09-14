#airecon2 offsec - offensive tools behind the authorization gate
from . import web, system
from .gate import check_target, NotAuthorized, AUDIT_LOG

SCHEMAS = web.SCHEMAS + system.SCHEMAS
DISPATCH = {**web.DISPATCH, **system.DISPATCH}
