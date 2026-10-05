async def test_bulk_delete_of_trace_cascades_to_spans(session, flow):
    trace = TraceTable(name="t", flow_id=flow.id, session_id="s")
    session.add(trace)
    await session.commit()
    span = SpanTable(name="s", trace_id=trace.id)
    session.add(span)
    await session.commit()
    await session.execute(delete(TraceTable).where(TraceTable.flow_id == flow.id))
    await session.commit()
