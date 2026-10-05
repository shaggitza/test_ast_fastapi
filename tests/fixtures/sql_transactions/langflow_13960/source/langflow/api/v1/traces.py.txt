from fastapi import APIRouter
from sqlalchemy import delete
from langflow.services.database.models.traces.model import TraceTable
from langflow.services.deps import session_scope

router = APIRouter(prefix="/monitor/traces")

@router.delete("")
async def delete_traces_by_flow(flow_id, current_user):
    try:
        async with session_scope() as session:
            flow_stmt = select(Flow).where(Flow.id == flow_id).where(Flow.user_id == current_user.id)
            flow = (await session.exec(flow_stmt)).first()
            if not flow:
                raise HTTPException(status_code=404, detail="Flow not found")
            # Single statement avoids N+1 deletes when a flow has many traces.
            delete_stmt = delete(TraceTable).where(TraceTable.flow_id == flow_id)
            await session.execute(delete_stmt)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error deleting traces by flow")
        raise HTTPException(status_code=500, detail="Internal server error") from e
