def test_db_connection(pg_conn):
    is_connected = bool(pg_conn and pg_conn.closed == 0)
    assert is_connected
