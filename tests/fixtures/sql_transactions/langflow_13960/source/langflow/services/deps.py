from contextlib import asynccontextmanager
from lfx.services.deps import session_scope as lfx_session_scope

@asynccontextmanager
async def session_scope():
    """The Langflow wrapper delegates transaction behavior to LFX."""
    async with lfx_session_scope() as session:
        yield session
