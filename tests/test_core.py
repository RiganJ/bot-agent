import sqlite3

import pytest
from app import core
from app.core import set_focus, read_state, paper_status


def test_focus_lock(monkeypatch, tmp_path):
    monkeypatch.setenv('DATABASE_PATH', str(tmp_path / 'test.db'))
    a = '0x0000000000000000000000000000000000000001'
    b = '0x0000000000000000000000000000000000000002'
    assert set_focus(a) == a
    assert read_state('scanner_enabled') is False
    with pytest.raises(ValueError):
        set_focus(b)
    assert paper_status()['mode'] == 'PAPER_ONLY'


def test_invalid_address(monkeypatch, tmp_path):
    monkeypatch.setenv('DATABASE_PATH', str(tmp_path / 'test.db'))
    with pytest.raises(ValueError):
        set_focus('not-a-wallet')


def test_v031_migration_preserves_existing_v03_sqlite_rows(monkeypatch, tmp_path):
    database = tmp_path / 'existing-v03.db'
    monkeypatch.setenv('DATABASE_PATH', str(database))
    with sqlite3.connect(database) as con:
        con.executescript('''
            CREATE TABLE analyses (id INTEGER PRIMARY KEY, ts TEXT,
                address TEXT, data TEXT);
            CREATE TABLE state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL
            );
            CREATE TABLE pools (
                id INTEGER PRIMARY KEY, protocol TEXT NOT NULL,
                factory_address TEXT NOT NULL, pool_address TEXT NOT NULL UNIQUE,
                token0_address TEXT NOT NULL, token1_address TEXT NOT NULL,
                quote_address TEXT, block_number INTEGER NOT NULL,
                block_hash TEXT NOT NULL, tx_hash TEXT,
                log_index INTEGER NOT NULL DEFAULT 0,
                canonical INTEGER NOT NULL DEFAULT 1, discovered_at TEXT NOT NULL,
                UNIQUE(factory_address, tx_hash, log_index)
            );
            INSERT INTO analyses(ts,address,data)
                VALUES ('2026-01-01T00:00:00+00:00','0xanalysis','{}');
            INSERT INTO state(key,value) VALUES ('scanner_enabled','true');
            INSERT INTO pools(protocol,factory_address,pool_address,
                token0_address,token1_address,block_number,block_hash,tx_hash,
                log_index,discovered_at)
                VALUES ('uniswap_v3','0x0000000000000000000000000000000000000001',
                '0x0000000000000000000000000000000000000002',
                '0x0000000000000000000000000000000000000003',
                '0x0000000000000000000000000000000000000004',
                100,'0xblock','0xtx',1,'2026-01-01T00:00:00+00:00');
        ''')

    with core.db_connect() as con:
        assert con.execute('SELECT COUNT(*) FROM analyses').fetchone()[0] == 1
        assert con.execute(
            "SELECT value FROM state WHERE key='scanner_enabled'"
        ).fetchone()[0] == 'true'
        assert con.execute('SELECT COUNT(*) FROM pools').fetchone()[0] == 1
        normalized = con.execute(
            'SELECT protocol,verification_status FROM discovered_pools'
        ).fetchone()
        assert normalized == ('uniswap_v3', 'verified_onchain')
