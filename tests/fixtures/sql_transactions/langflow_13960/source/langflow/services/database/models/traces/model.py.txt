class SpanTable(SpanBase, table=True):
    __tablename__ = "span"
    trace_id: UUID = Field(
        foreign_key="trace.id",
        ondelete="CASCADE",
        index=True,
        description="Parent trace ID",
    )
