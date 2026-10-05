from contextlib import asynccontextmanager

@asynccontextmanager
async def session_scope():
    """Auto-commit normal exits and rollback exceptional exits."""
    db_service = get_db_service()
    async with db_service._with_session() as session:
        try:
            yield session
            await session.commit()
        except HTTPException:
            if session.is_active:
                with suppress(InvalidRequestError):
                    await session.rollback()
            raise
        except Exception as e:
            await logger.aexception("An error occurred during the session scope.", exception=e)
            if session.is_active:
                with suppress(InvalidRequestError):
                    await session.rollback()
            raise
