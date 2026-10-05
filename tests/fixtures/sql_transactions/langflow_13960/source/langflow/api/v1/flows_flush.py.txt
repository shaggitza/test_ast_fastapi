async def delete_multiple_flows(db, flow_ids):
    async def _delete_operation():
        if not flow_ids:
            return 0
        flows_to_delete = (await db.exec(stmt)).all()
        for flow in flows_to_delete:
            await cascade_delete_flow(db, flow.id)
        await db.flush()
        return len(flows_to_delete)
