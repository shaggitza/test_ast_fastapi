def upgrade() -> None:
    conn = op.get_bind()
    if not migration.table_exists("span", conn):
        return
    fk = _find_trace_id_fk(conn)
    if fk is not None and (fk.get("options") or {}).get("ondelete", "").upper() == "CASCADE":
        return
    with op.batch_alter_table("span", schema=None, naming_convention=_NAMING_CONVENTION) as batch_op:
        if fk is not None:
            batch_op.drop_constraint(fk["name"] or _FK_NAME, type_="foreignkey")
        batch_op.create_foreign_key(
            _FK_NAME,
            "trace",
            ["trace_id"],
            ["id"],
            ondelete="CASCADE",
        )
