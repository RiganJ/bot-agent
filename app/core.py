"""Read-only Base inspection and non-destructive persistent scanner state."""
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from web3 import Web3
from .intelligence import build_analysis
from .intelligence_v033 import build_cluster, redact_sensitive

CHAIN_ID = 8453


def _utcnow():
    return datetime.now(timezone.utc).isoformat()


def _migrate_v3(con):
    """Add v0.3 tables without modifying or deleting existing rows."""
    con.executescript('''
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pools (
            id INTEGER PRIMARY KEY,
            protocol TEXT NOT NULL,
            factory_address TEXT NOT NULL,
            pool_address TEXT NOT NULL UNIQUE,
            token0_address TEXT NOT NULL,
            token1_address TEXT NOT NULL,
            quote_address TEXT,
            block_number INTEGER NOT NULL,
            block_hash TEXT NOT NULL,
            tx_hash TEXT,
            log_index INTEGER NOT NULL DEFAULT 0,
            canonical INTEGER NOT NULL DEFAULT 1,
            discovered_at TEXT NOT NULL,
            UNIQUE(factory_address, tx_hash, log_index)
        );
        CREATE INDEX IF NOT EXISTS idx_pools_block ON pools(block_number, canonical);
        CREATE TABLE IF NOT EXISTS tokens (
            address TEXT PRIMARY KEY,
            first_pool_address TEXT,
            first_seen_at TEXT NOT NULL,
            first_seen_block INTEGER,
            analysis_state TEXT NOT NULL DEFAULT 'PENDING',
            decision TEXT,
            risk_score INTEGER,
            evidence_confidence INTEGER,
            liquidity_usd TEXT,
            latest_analysis TEXT,
            analyzed_at TEXT,
            last_error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_tokens_seen ON tokens(first_seen_at DESC);
        CREATE TABLE IF NOT EXISTS developers (
            address TEXT PRIMARY KEY,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            deployment_count INTEGER NOT NULL DEFAULT 0,
            last_history_scan_at TEXT,
            source TEXT
        );
        CREATE TABLE IF NOT EXISTS developer_history (
            id INTEGER PRIMARY KEY,
            token_address TEXT NOT NULL,
            developer_address TEXT NOT NULL,
            role TEXT NOT NULL,
            source TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            evidence TEXT,
            UNIQUE(token_address, developer_address, role, source)
        );
        CREATE INDEX IF NOT EXISTS idx_dev_history_address
            ON developer_history(developer_address, observed_at DESC);
        CREATE TABLE IF NOT EXISTS funding_links (
            id INTEGER PRIMARY KEY,
            funded_address TEXT NOT NULL,
            funding_address TEXT NOT NULL,
            token_address TEXT,
            source TEXT NOT NULL,
            evidence TEXT,
            observed_at TEXT NOT NULL,
            UNIQUE(funded_address, funding_address, token_address, source)
        );
        CREATE TABLE IF NOT EXISTS watchlists (
            token_address TEXT PRIMARY KEY,
            reason TEXT NOT NULL,
            criteria TEXT,
            created_at TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS scan_checkpoints (
            scanner_name TEXT PRIMARY KEY,
            block_number INTEGER NOT NULL,
            block_hash TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            dedupe_key TEXT NOT NULL UNIQUE,
            token_address TEXT,
            alert_type TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            sent_at TEXT,
            error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_sent ON alerts(sent_at DESC);
        CREATE TABLE IF NOT EXISTS tracked_addresses (
            address TEXT PRIMARY KEY,
            added_at TEXT NOT NULL,
            label TEXT
        );
        CREATE TABLE IF NOT EXISTS rpc_usage (
            provider_host TEXT NOT NULL,
            usage_date TEXT NOT NULL,
            request_count INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(provider_host, usage_date)
        );
        CREATE TABLE IF NOT EXISTS discovery_metrics (
            name TEXT PRIMARY KEY,
            value INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS discovery_errors (
            id INTEGER PRIMARY KEY,
            occurred_at TEXT NOT NULL,
            stage TEXT NOT NULL,
            category TEXT NOT NULL,
            message TEXT,
            context TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_discovery_errors_time
            ON discovery_errors(occurred_at DESC);
    ''')
    con.execute(
        'INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES (?,?)',
        (3, _utcnow()),
    )


def _migrate_v4(con):
    con.executescript('''
        CREATE TABLE IF NOT EXISTS discovered_pools (
            pool_key TEXT PRIMARY KEY,
            chain_id INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            pool_address TEXT,
            pool_id TEXT,
            factory_address TEXT,
            token0_address TEXT NOT NULL,
            token1_address TEXT NOT NULL,
            currency0_address TEXT,
            currency1_address TEXT,
            hook_address TEXT,
            block_number INTEGER,
            block_hash TEXT,
            tx_hash TEXT,
            log_index INTEGER,
            source TEXT NOT NULL,
            verification_status TEXT NOT NULL,
            discovered_at TEXT NOT NULL,
            source_created_at TEXT,
            canonical INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_discovered_pools_block
            ON discovered_pools(block_number, canonical);
        CREATE INDEX IF NOT EXISTS idx_discovered_pools_tokens
            ON discovered_pools(token0_address, token1_address, canonical);
        CREATE TABLE IF NOT EXISTS protocol_scan_status (
            protocol TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            blocks_scanned INTEGER NOT NULL DEFAULT 0,
            events_detected INTEGER NOT NULL DEFAULT 0,
            decoding_failures INTEGER NOT NULL DEFAULT 0,
            last_successful_scan TEXT,
            cursor_block INTEGER,
            cursor TEXT,
            last_error TEXT
        );
    ''')
    con.execute('''
        INSERT OR IGNORE INTO discovered_pools(
            pool_key,chain_id,protocol,pool_address,factory_address,
            token0_address,token1_address,block_number,block_hash,tx_hash,
            log_index,source,verification_status,discovered_at,canonical
        )
        SELECT '8453:address:' || lower(pool_address),8453,protocol,pool_address,
            factory_address,token0_address,token1_address,block_number,block_hash,
            tx_hash,log_index,'base_factory_events','verified_onchain',
            discovered_at,canonical
        FROM pools
    ''')
    con.execute(
        'INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES (?,?)',
        (4, _utcnow()),
    )


def _migrate_v5(con):
    """Add v0.3.3 evidence graphs without rewriting existing scanner data."""
    con.executescript('''
        CREATE TABLE IF NOT EXISTS intelligence_evidence (
            id INTEGER PRIMARY KEY,
            subject_address TEXT NOT NULL,
            subject_type TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            source TEXT NOT NULL,
            provenance TEXT,
            observed_at TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            status TEXT NOT NULL,
            data TEXT NOT NULL,
            UNIQUE(subject_address,evidence_type,source,provenance)
        );
        CREATE INDEX IF NOT EXISTS idx_intel_subject
            ON intelligence_evidence(subject_address,observed_at DESC);
        CREATE TABLE IF NOT EXISTS wallet_relationships (
            id INTEGER PRIMARY KEY,
            from_address TEXT NOT NULL,
            to_address TEXT NOT NULL,
            relationship TEXT NOT NULL,
            token_address TEXT,
            source TEXT NOT NULL,
            provenance TEXT,
            observed_at TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            ownership_claim INTEGER NOT NULL DEFAULT 0,
            evidence TEXT NOT NULL,
            UNIQUE(from_address,to_address,relationship,token_address,source,provenance)
        );
        CREATE INDEX IF NOT EXISTS idx_wallet_edges_from
            ON wallet_relationships(from_address,observed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_wallet_edges_to
            ON wallet_relationships(to_address,observed_at DESC);
        CREATE TABLE IF NOT EXISTS social_evidence (
            id INTEGER PRIMARY KEY,
            token_address TEXT NOT NULL,
            url TEXT NOT NULL,
            platform TEXT,
            account_type TEXT NOT NULL,
            relationship TEXT NOT NULL,
            source TEXT NOT NULL,
            provenance TEXT,
            observed_at TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            verification_status TEXT NOT NULL,
            UNIQUE(token_address,url,source,provenance)
        );
        CREATE INDEX IF NOT EXISTS idx_social_token
            ON social_evidence(token_address,observed_at DESC);
        CREATE TABLE IF NOT EXISTS contract_fingerprints (
            token_address TEXT PRIMARY KEY,
            runtime_code_hash TEXT NOT NULL,
            bytecode_bytes INTEGER NOT NULL,
            source TEXT NOT NULL,
            observed_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_contract_fingerprint
            ON contract_fingerprints(runtime_code_hash);
    ''')
    columns = {row[1] for row in con.execute('PRAGMA table_info(discovered_pools)')}
    if 'hook_address' not in columns:
        con.execute('ALTER TABLE discovered_pools ADD COLUMN hook_address TEXT')
    con.execute(
        'INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES (?,?)',
        (5, _utcnow()),
    )


def db_connect():
    path = Path(os.getenv('DATABASE_PATH', 'sniper.db'))
    con = sqlite3.connect(path, timeout=10)
    con.execute('PRAGMA busy_timeout=10000')
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('CREATE TABLE IF NOT EXISTS analyses (id INTEGER PRIMARY KEY, ts TEXT, address TEXT, data TEXT)')
    con.execute('CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
    _migrate_v3(con)
    _migrate_v4(con)
    _migrate_v5(con)
    con.commit()
    return con


def read_state(key, default=None):
    with db_connect() as con:
        row = con.execute('SELECT value FROM state WHERE key=?', (key,)).fetchone()
    return json.loads(row[0]) if row else default


def write_state(key, value):
    with db_connect() as con:
        con.execute('INSERT INTO state(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, json.dumps(value)))


def inspect_contract(address, rpc_url=None):
    checksum = Web3.to_checksum_address(address)
    result = build_analysis(address, rpc_url)
    with db_connect() as con:
        con.execute('INSERT INTO analyses(ts,address,data) VALUES (?,?,?)',
                    (_utcnow(), checksum, json.dumps(redact_sensitive(result))))
    record_intelligence_evidence(result)
    return result


def paper_status():
    return {
        'mode': 'PAPER_ONLY',
        'start_balance_idr': int(os.getenv('PAPER_START_BALANCE_IDR', '100000')),
        'max_position_idr': int(os.getenv('MAX_POSITION_IDR', '20000')),
        'focused_developer': read_state('focused_developer'),
        'scanner_enabled': read_state('scanner_enabled', False),
    }


def set_focus(address):
    if not Web3.is_address(address):
        raise ValueError('Invalid EVM address')
    addr = Web3.to_checksum_address(address)
    current = read_state('focused_developer')
    if current and current != addr:
        raise ValueError('Another address is already locked. Use /unfocus first (no real positions exist).')
    write_state('focused_developer', addr)
    if read_state('scanner_enabled') is None:
        write_state('scanner_enabled', False)
    return addr


def save_checkpoint(scanner_name, block_number, block_hash):
    with db_connect() as con:
        con.execute('''
            INSERT INTO scan_checkpoints(scanner_name,block_number,block_hash,updated_at)
            VALUES (?,?,?,?) ON CONFLICT(scanner_name) DO UPDATE SET
            block_number=excluded.block_number, block_hash=excluded.block_hash,
            updated_at=excluded.updated_at
        ''', (scanner_name, int(block_number), block_hash, _utcnow()))


def save_scan_checkpoint(scanner_name, block_number, block_hash, protocol_updates,
                         backfill_state_key=None, backfill_cursor=None):
    """Commit a completed shared log range and its per-protocol cursors atomically."""
    now = _utcnow()
    with db_connect() as con:
        con.execute('''
            INSERT INTO scan_checkpoints(scanner_name,block_number,block_hash,updated_at)
            VALUES (?,?,?,?) ON CONFLICT(scanner_name) DO UPDATE SET
            block_number=excluded.block_number, block_hash=excluded.block_hash,
            updated_at=excluded.updated_at
        ''', (scanner_name, int(block_number), block_hash, now))
        for protocol, values in protocol_updates.items():
            con.execute('''
                INSERT INTO protocol_scan_status(
                    protocol,source,blocks_scanned,events_detected,
                    decoding_failures,last_successful_scan,cursor_block,
                    cursor,last_error
                ) VALUES (?,?,?,?,?,?,?,NULL,NULL)
                ON CONFLICT(protocol) DO UPDATE SET
                    source=excluded.source,
                    blocks_scanned=protocol_scan_status.blocks_scanned+
                        excluded.blocks_scanned,
                    events_detected=protocol_scan_status.events_detected+
                        excluded.events_detected,
                    decoding_failures=protocol_scan_status.decoding_failures+
                        excluded.decoding_failures,
                    last_successful_scan=excluded.last_successful_scan,
                    cursor_block=excluded.cursor_block,
                    last_error=NULL
            ''', (
                protocol, values.get('source', 'base_rpc'),
                int(values.get('blocks_scanned', 0)),
                int(values.get('events_detected', 0)),
                int(values.get('decoding_failures', 0)), now,
                int(block_number),
            ))
        if backfill_state_key:
            con.execute('''
                INSERT INTO state(key,value) VALUES (?,?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
            ''', (backfill_state_key, json.dumps(backfill_cursor)))


def record_protocol_scan_success(protocol, source, events_detected=0,
                                 cursor=None):
    now = _utcnow()
    with db_connect() as con:
        con.execute('''
            INSERT INTO protocol_scan_status(
                protocol,source,events_detected,last_successful_scan,cursor,
                last_error
            ) VALUES (?,?,?,?,?,NULL)
            ON CONFLICT(protocol) DO UPDATE SET
                source=excluded.source,
                events_detected=protocol_scan_status.events_detected+
                    excluded.events_detected,
                last_successful_scan=excluded.last_successful_scan,
                cursor=excluded.cursor,
                last_error=NULL
        ''', (str(protocol), str(source), int(events_detected), now, cursor))


def record_protocol_scan_attempt(protocol, source, cursor):
    with db_connect() as con:
        con.execute('''
            INSERT INTO protocol_scan_status(protocol,source,cursor)
            VALUES (?,?,?)
            ON CONFLICT(protocol) DO UPDATE SET
                source=excluded.source,cursor=excluded.cursor
        ''', (str(protocol), str(source), str(cursor)))


def record_protocol_scan_failure(protocol, source, events_detected=0,
                                 decoding_failures=0, error=None, cursor=None):
    with db_connect() as con:
        con.execute('''
            INSERT INTO protocol_scan_status(
                protocol,source,events_detected,decoding_failures,last_error,cursor
            ) VALUES (?,?,?,?,?,?)
            ON CONFLICT(protocol) DO UPDATE SET
                source=excluded.source,
                events_detected=protocol_scan_status.events_detected+
                    excluded.events_detected,
                decoding_failures=protocol_scan_status.decoding_failures+
                    excluded.decoding_failures,
                cursor=COALESCE(excluded.cursor,protocol_scan_status.cursor),
                last_error=excluded.last_error
        ''', (
            str(protocol), str(source), int(events_detected),
            int(decoding_failures), _sanitize_diagnostic(error), cursor,
        ))


def protocol_scan_status(protocols=()):
    with db_connect() as con:
        rows = con.execute('''
            SELECT protocol,source,blocks_scanned,events_detected,
                decoding_failures,last_successful_scan,cursor_block,cursor,last_error
            FROM protocol_scan_status
        ''').fetchall()
    stored = {
        row[0]: dict(zip((
            'protocol', 'source', 'blocks_scanned', 'events_detected',
            'decoding_failures', 'last_successful_scan', 'cursor_block',
            'cursor', 'last_error',
        ), row))
        for row in rows
    }
    result = []
    for protocol in dict.fromkeys(protocols):
        result.append(stored.pop(protocol, {
            'protocol': protocol,
            'source': ('dexscreener_api' if protocol == 'dexscreener'
                       else 'base_rpc'),
            'blocks_scanned': 0, 'events_detected': 0,
            'decoding_failures': 0, 'last_successful_scan': None,
            'cursor_block': None, 'cursor': None, 'last_error': None,
        }))
    result.extend(stored[name] for name in sorted(stored))
    return result


def get_checkpoint(scanner_name):
    with db_connect() as con:
        row = con.execute(
            'SELECT block_number,block_hash,updated_at FROM scan_checkpoints WHERE scanner_name=?',
            (scanner_name,),
        ).fetchone()
    return ({'block_number': row[0], 'block_hash': row[1], 'updated_at': row[2]}
            if row else None)


DISCOVERY_METRIC_NAMES = (
    'scanned_ranges', 'empty_ranges', 'pool_events_found', 'decoded_events',
    'decode_failures', 'tokens_discovered', 'tokens_queued', 'tokens_analyzed',
    'rejected_tokens', 'watchlist_filtered', 'unsupported_tokens',
    'persistence_failures', 'analysis_failures', 'worker_failures',
    'provider_failures', 'secondary_events_found', 'secondary_pairs_ignored',
    'secondary_provider_failures', 'alerts_sent',
)


def increment_discovery_metric(name, amount=1):
    if name not in DISCOVERY_METRIC_NAMES:
        raise ValueError(f'Unknown discovery metric: {name}')
    now = _utcnow()
    with db_connect() as con:
        con.execute('''
            INSERT INTO discovery_metrics(name,value,updated_at) VALUES (?,?,?)
            ON CONFLICT(name) DO UPDATE SET
                value=discovery_metrics.value+excluded.value,
                updated_at=excluded.updated_at
        ''', (name, int(amount), now))


def _sanitize_diagnostic(value):
    if value is None:
        return None
    text = re.sub(r'https?://[^\s"\']+', '[redacted-url]', str(value))
    text = re.sub(
        r'(?i)(api[_-]?key|token|authorization|bearer)(\s*[:=]\s*)[^\s,;]+',
        r'\1\2[redacted]', text,
    )
    text = re.sub(r'\b[A-Za-z0-9_-]{32,}\b', '[redacted-value]', text)
    return re.sub(r'[\x00-\x1f\x7f]+', ' ', text).strip()[:240] or None


def record_discovery_error(stage, category, message=None, context=None):
    safe_context = {}
    for key, value in (context or {}).items():
        if key.lower() in {'url', 'rpc_url', 'authorization', 'api_key', 'token'}:
            continue
        safe_context[str(key)[:64]] = (
            value if isinstance(value, (int, float, bool)) or value is None
            else _sanitize_diagnostic(value)
        )
    with db_connect() as con:
        con.execute('''
            INSERT INTO discovery_errors(occurred_at,stage,category,message,context)
            VALUES (?,?,?,?,?)
        ''', (_utcnow(), str(stage)[:64], str(category)[:64],
              _sanitize_diagnostic(message), json.dumps(safe_context)))
        # Bound diagnostic history without touching discovery or analysis records.
        con.execute('''
            DELETE FROM discovery_errors WHERE id NOT IN (
                SELECT id FROM discovery_errors ORDER BY id DESC LIMIT 200
            )
        ''')


def discovery_diagnostics(error_limit=8):
    with db_connect() as con:
        stored = dict(con.execute(
            'SELECT name,value FROM discovery_metrics'
        ).fetchall())
        counts = {
            'pools_persisted': con.execute(
                'SELECT COUNT(*) FROM discovered_pools WHERE canonical=1'
            ).fetchone()[0],
            'tokens_persisted': con.execute(
                'SELECT COUNT(*) FROM tokens'
            ).fetchone()[0],
            'watchlist_entries': con.execute(
                'SELECT COUNT(*) FROM watchlists WHERE active=1'
            ).fetchone()[0],
        }
        rows = con.execute('''
            SELECT occurred_at,stage,category,message,context
            FROM discovery_errors ORDER BY id DESC LIMIT ?
        ''', (max(1, min(int(error_limit), 25)),)).fetchall()
    metrics = {name: int(stored.get(name, 0)) for name in DISCOVERY_METRIC_NAMES}
    errors = []
    for occurred_at, stage, category, message, context in rows:
        errors.append({
            'occurred_at': occurred_at, 'stage': stage, 'category': category,
            'message': message, 'context': json.loads(context or '{}'),
        })
    return {'metrics': metrics, 'records': counts, 'recent_errors': errors}


def mark_reorg(from_block):
    """Keep forensic rows but remove orphaned pools from canonical results."""
    with db_connect() as con:
        orphaned_normalized = con.execute('''
            SELECT COUNT(*) FROM discovered_pools d
            WHERE d.block_number>=? AND d.canonical=1
                AND (d.pool_address IS NULL OR NOT EXISTS (
                    SELECT 1 FROM pools p WHERE lower(p.pool_address)=
                        lower(d.pool_address)
                ))
        ''', (int(from_block),)).fetchone()[0]
        cur = con.execute(
            'UPDATE pools SET canonical=0 WHERE block_number>=? AND canonical=1',
            (int(from_block),),
        )
        con.execute(
            'UPDATE discovered_pools SET canonical=0 '
            'WHERE block_number>=? AND canonical=1',
            (int(from_block),),
        )
        con.execute('''
            UPDATE tokens SET analysis_state='ORPHANED'
            WHERE NOT EXISTS (
                SELECT 1 FROM pools p WHERE p.canonical=1 AND
                (p.token0_address=tokens.address OR p.token1_address=tokens.address)
            ) AND NOT EXISTS (
                SELECT 1 FROM discovered_pools p WHERE p.canonical=1 AND
                (p.token0_address=tokens.address OR p.token1_address=tokens.address)
            )
        ''')
        con.execute('''
            UPDATE watchlists SET active=0 WHERE token_address IN (
                SELECT address FROM tokens WHERE analysis_state='ORPHANED'
            )
        '''        )
        con.execute('''
            UPDATE protocol_scan_status SET
                blocks_scanned=MAX(0,blocks_scanned-MAX(0,cursor_block-?)),
                cursor_block=MIN(cursor_block,?)
            WHERE cursor_block>=?
        ''', (int(from_block) - 1, int(from_block) - 1, int(from_block)))
    return cur.rowcount + orphaned_normalized


def _upsert_discovered_pool(con, event, now):
    chain_id = int(event.get('chain_id', CHAIN_ID))
    if chain_id != CHAIN_ID:
        raise ValueError(f'Unsupported discovery chain ID: {chain_id}')
    pool_id = event.get('pool_id')
    pool_address = event.get('pool_address')
    if pool_id:
        pool_id = str(pool_id).lower()
        if not re.fullmatch(r'0x[0-9a-f]{64}', pool_id):
            raise ValueError('Discovered pool ID must be bytes32')
        pool_key = f'{chain_id}:id:{pool_id}'
    elif pool_address and Web3.is_address(pool_address):
        pool_address = Web3.to_checksum_address(pool_address)
        pool_key = f'{chain_id}:address:{pool_address.lower()}'
    else:
        raise ValueError('Discovered pool must have a valid address or pool ID')
    token0 = Web3.to_checksum_address(event['token0_address'])
    token1 = Web3.to_checksum_address(event['token1_address'])
    factory = event.get('factory_address')
    factory = Web3.to_checksum_address(factory) if factory else None
    status = event.get('verification_status', 'verified_onchain')
    if status not in {'verified_onchain', 'reported_unverified'}:
        raise ValueError(f'Unsupported pool verification status: {status}')
    prior = con.execute(
        'SELECT canonical FROM discovered_pools WHERE pool_key=?', (pool_key,)
    ).fetchone()
    con.execute('''
        INSERT INTO discovered_pools(
            pool_key,chain_id,protocol,pool_address,pool_id,factory_address,
            token0_address,token1_address,currency0_address,currency1_address,
            hook_address,
            block_number,block_hash,tx_hash,log_index,source,
            verification_status,discovered_at,source_created_at,canonical
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)
        ON CONFLICT(pool_key) DO UPDATE SET
            protocol=CASE WHEN excluded.verification_status='verified_onchain'
                OR discovered_pools.verification_status!='verified_onchain'
                THEN excluded.protocol ELSE discovered_pools.protocol END,
            pool_address=COALESCE(excluded.pool_address,discovered_pools.pool_address),
            pool_id=COALESCE(excluded.pool_id,discovered_pools.pool_id),
            factory_address=COALESCE(excluded.factory_address,
                discovered_pools.factory_address),
            token0_address=CASE WHEN excluded.verification_status='verified_onchain'
                OR discovered_pools.verification_status!='verified_onchain'
                THEN excluded.token0_address ELSE discovered_pools.token0_address END,
            token1_address=CASE WHEN excluded.verification_status='verified_onchain'
                OR discovered_pools.verification_status!='verified_onchain'
                THEN excluded.token1_address ELSE discovered_pools.token1_address END,
            currency0_address=COALESCE(excluded.currency0_address,
                discovered_pools.currency0_address),
            currency1_address=COALESCE(excluded.currency1_address,
                discovered_pools.currency1_address),
            hook_address=COALESCE(excluded.hook_address,
                discovered_pools.hook_address),
            block_number=COALESCE(excluded.block_number,discovered_pools.block_number),
            block_hash=COALESCE(excluded.block_hash,discovered_pools.block_hash),
            tx_hash=COALESCE(excluded.tx_hash,discovered_pools.tx_hash),
            log_index=COALESCE(excluded.log_index,discovered_pools.log_index),
            source=CASE WHEN excluded.verification_status='verified_onchain'
                THEN excluded.source ELSE discovered_pools.source END,
            verification_status=CASE WHEN excluded.verification_status='verified_onchain'
                THEN excluded.verification_status
                ELSE discovered_pools.verification_status END,
            source_created_at=COALESCE(discovered_pools.source_created_at,
                excluded.source_created_at),
            canonical=1
    ''', (
        pool_key, chain_id, str(event['protocol']), pool_address, pool_id,
        factory, token0, token1, event.get('currency0_address'),
        event.get('currency1_address'), event.get('hook_address'),
        int(event['block_number']) if event.get('block_number') is not None else None,
        event.get('block_hash'), event.get('tx_hash'),
        int(event['log_index']) if event.get('log_index') is not None else None,
        str(event.get('source', 'base_rpc')), status,
        event.get('discovered_at') or now, event.get('source_created_at'),
    ))
    return prior


def record_discovered_pool(event, token_addresses, with_diagnostics=False):
    """Persist any source's normalized pool identity and discovered tokens."""
    now = _utcnow()
    with db_connect() as con:
        prior = _upsert_discovered_pool(con, event, now)
        new_tokens = 0
        for address in dict.fromkeys(token_addresses):
            checksum = Web3.to_checksum_address(address)
            existed = con.execute(
                'SELECT 1 FROM tokens WHERE address=?', (checksum,)
            ).fetchone() is not None
            con.execute('''
                INSERT INTO tokens(address,first_pool_address,first_seen_at,
                    first_seen_block,analysis_state) VALUES (?,?,?,?, 'PENDING')
                ON CONFLICT(address) DO UPDATE SET analysis_state=CASE
                    WHEN tokens.analysis_state='ORPHANED' THEN 'PENDING'
                    ELSE tokens.analysis_state END
            ''', (
                checksum, event.get('pool_address'), now,
                event.get('block_number'),
            ))
            if not existed:
                new_tokens += 1
    should_process = prior is None or prior[0] == 0
    if with_diagnostics:
        return {'should_process': should_process, 'new_tokens': new_tokens}
    return should_process


def record_pool(event, token_addresses, with_diagnostics=False):
    """Persist one verified factory event and return whether it needs processing."""
    now = _utcnow()
    pool = Web3.to_checksum_address(event['pool_address'])
    token0 = Web3.to_checksum_address(event['token0_address'])
    token1 = Web3.to_checksum_address(event['token1_address'])
    factory = Web3.to_checksum_address(event['factory_address'])
    quote = event.get('quote_address')
    quote = Web3.to_checksum_address(quote) if quote else None
    with db_connect() as con:
        prior = _upsert_discovered_pool(con, event, now)
        con.execute('''
            INSERT INTO pools(protocol,factory_address,pool_address,token0_address,
                token1_address,quote_address,block_number,block_hash,tx_hash,
                log_index,canonical,discovered_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,1,?)
            ON CONFLICT(pool_address) DO UPDATE SET
                protocol=excluded.protocol, factory_address=excluded.factory_address,
                token0_address=excluded.token0_address, token1_address=excluded.token1_address,
                quote_address=excluded.quote_address, block_number=excluded.block_number,
                block_hash=excluded.block_hash, tx_hash=excluded.tx_hash,
                log_index=excluded.log_index, canonical=1
        ''', (event['protocol'], factory, pool, token0, token1, quote,
              int(event['block_number']), event['block_hash'], event.get('tx_hash'),
              int(event.get('log_index', 0)), now))
        should_process = prior is None or prior[0] == 0
        new_tokens = 0
        for address in token_addresses:
            checksum = Web3.to_checksum_address(address)
            existed = con.execute(
                'SELECT 1 FROM tokens WHERE address=?', (checksum,)
            ).fetchone() is not None
            con.execute('''
                INSERT INTO tokens(address,first_pool_address,first_seen_at,
                    first_seen_block,analysis_state) VALUES (?,?,?,?, 'PENDING')
                ON CONFLICT(address) DO UPDATE SET analysis_state=CASE
                    WHEN tokens.analysis_state='ORPHANED' THEN 'PENDING'
                    ELSE tokens.analysis_state END
            ''', (checksum, pool, now, int(event['block_number'])))
            if not existed:
                new_tokens += 1
    if with_diagnostics:
        return {'should_process': should_process, 'new_tokens': new_tokens}
    return should_process


def update_token_analysis(address, result=None, error=None):
    checksum = Web3.to_checksum_address(address)
    now = _utcnow()
    if result is None:
        with db_connect() as con:
            con.execute('''
                INSERT INTO tokens(address,first_seen_at,analysis_state,decision,
                    analyzed_at,last_error) VALUES (?,?,'INCONCLUSIVE','WATCHLIST',?,?)
                ON CONFLICT(address) DO UPDATE SET
                    analysis_state='INCONCLUSIVE', decision='WATCHLIST',
                    analyzed_at=excluded.analyzed_at,last_error=excluded.last_error
            ''', (checksum, now, now, type(error).__name__ if error else
                  'analysis unavailable'))
        return
    risk = result.get('risk', {})
    market = result.get('market', {})
    state = result.get('risk', {}).get('assessment', 'INCONCLUSIVE')
    with db_connect() as con:
        con.execute('''
            INSERT INTO tokens(address,first_seen_at,analysis_state) VALUES (?,?,?)
            ON CONFLICT(address) DO UPDATE SET analysis_state=excluded.analysis_state,
                decision=?, risk_score=?, evidence_confidence=?, liquidity_usd=?,
                latest_analysis=?, analyzed_at=?, last_error=NULL
        ''', (checksum, now, state, result.get('decision'), risk.get('risk_score'),
              risk.get('evidence_confidence'), market.get('liquidity_usd'),
              json.dumps(redact_sensitive(result)), now))
    record_intelligence_evidence(result)


def record_intelligence_evidence(result):
    """Persist v0.3.3 evidence with explicit source, time and confidence."""
    address = result.get('address')
    if not address or not Web3.is_address(address):
        return
    token = Web3.to_checksum_address(address)
    now = result.get('analyzed_at') or _utcnow()
    developer = result.get('developer') or {}
    contract = result.get('contract') or {}
    role_specs = (
        ('DEPLOYER', developer.get('deployer'), developer.get('source'), 95),
        ('OWNER', developer.get('owner'), contract.get('owner_evidence'), 90),
        ('FACTORY', developer.get('factory'), developer.get('source'), 95),
        ('IMPLEMENTATION', contract.get('implementation'),
         contract.get('implementation_type'), 95),
        ('UPGRADE_AUTHORITY', contract.get('upgrade_authority'),
         contract.get('upgrade_authority_evidence'), 90),
    )
    with db_connect() as con:
        for role, related, source, confidence in role_specs:
            if not related or not Web3.is_address(related):
                continue
            related = Web3.to_checksum_address(related)
            provenance = str(source or 'analysis evidence')
            data = {'role': role, 'related_address': related,
                    'ownership_claim': role == 'OWNER'}
            con.execute('''
                INSERT INTO intelligence_evidence(subject_address,subject_type,
                    evidence_type,source,provenance,observed_at,confidence,status,data)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(subject_address,evidence_type,source,provenance)
                DO UPDATE SET observed_at=excluded.observed_at,
                    confidence=excluded.confidence,status=excluded.status,data=excluded.data
            ''', (token, 'TOKEN', role, provenance, provenance, now, confidence,
                  'PASS', json.dumps(data)))
            con.execute('''
                INSERT INTO wallet_relationships(from_address,to_address,relationship,
                    token_address,source,provenance,observed_at,confidence,
                    ownership_claim,evidence) VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(from_address,to_address,relationship,token_address,source,provenance)
                DO UPDATE SET observed_at=excluded.observed_at,
                    confidence=excluded.confidence,evidence=excluded.evidence
            ''', (related, token, role, token, provenance, provenance, now,
                  confidence, 1 if role == 'OWNER' else 0, json.dumps(data)))
        funding = developer.get('funding_wallet') or {}
        funded, funder = developer.get('deployer'), funding.get('address')
        if (funded and funder and Web3.is_address(funded) and Web3.is_address(funder)):
            provenance = funding.get('evidence') or 'observed funding transaction'
            con.execute('''
                INSERT OR IGNORE INTO wallet_relationships(from_address,to_address,
                    relationship,token_address,source,provenance,observed_at,
                    confidence,ownership_claim,evidence)
                VALUES (?,?,?,?,?,?,?,?,0,?)
            ''', (Web3.to_checksum_address(funder), Web3.to_checksum_address(funded),
                  'FUNDING_TRANSACTION', token, 'BaseScan', provenance, now, 75,
                  json.dumps({'ownership_claim': False})))
        social = result.get('social') or {}
        for item in (social.get('websites') or []) + (social.get('social_accounts') or []):
            url = item.get('url')
            if not url:
                continue
            con.execute('''
                INSERT INTO social_evidence(token_address,url,platform,account_type,
                    relationship,source,provenance,observed_at,confidence,
                    verification_status) VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(token_address,url,source,provenance) DO UPDATE SET
                    observed_at=excluded.observed_at,confidence=excluded.confidence,
                    verification_status=excluded.verification_status
            ''', (token, url, item.get('platform'), item.get('account_type', 'PROJECT'),
                  item.get('relationship', 'PROJECT_METADATA_LINK'),
                  item.get('source', 'metadata'), item.get('path'),
                  item.get('observed_at', now), int(item.get('confidence', 0)),
                  'VERIFIED_SOURCE_RELATIONSHIP'))
        static = contract.get('static_inspection') or {}
        code_hash = static.get('runtime_code_hash')
        if code_hash:
            con.execute('''
                INSERT INTO contract_fingerprints(token_address,runtime_code_hash,
                    bytecode_bytes,source,observed_at) VALUES (?,?,?,?,?)
                ON CONFLICT(token_address) DO UPDATE SET
                    runtime_code_hash=excluded.runtime_code_hash,
                    bytecode_bytes=excluded.bytecode_bytes,
                    source=excluded.source,observed_at=excluded.observed_at
            ''', (token, code_hash, int(static.get('bytecode_bytes', 0)),
                  'Base RPC runtime bytecode', now))


def record_developer_evidence(token_address, developer, contract=None):
    """Persist role evidence without asserting identity or common ownership."""
    token = Web3.to_checksum_address(token_address)
    now = _utcnow()
    contract = contract or {}
    roles = (
        ('deployer', developer.get('deployer'), developer.get('source')),
        ('token_owner', developer.get('owner'), 'on-chain owner()'),
        ('factory', developer.get('factory'), developer.get('source')),
        ('proxy_admin', contract.get('proxy_admin'), 'EIP-1967 admin slot'),
        ('upgrade_authority', contract.get('upgrade_authority'),
         contract.get('upgrade_authority_evidence')),
    )
    with db_connect() as con:
        for role, address, source in roles:
            if not address or not Web3.is_address(address):
                continue
            addr = Web3.to_checksum_address(address)
            source = source or 'analysis evidence'
            con.execute('''
                INSERT INTO developer_history(token_address,developer_address,role,
                    source,observed_at,evidence) VALUES (?,?,?,?,?,?)
                ON CONFLICT(token_address,developer_address,role,source) DO UPDATE SET
                    observed_at=excluded.observed_at
            ''', (token, addr, role, source, now, json.dumps({'ownership_claim': False})))
            con.execute('''
                INSERT INTO developers(address,first_seen_at,last_seen_at,source)
                VALUES (?,?,?,?) ON CONFLICT(address) DO UPDATE SET
                    last_seen_at=excluded.last_seen_at, source=excluded.source
            ''', (addr, now, now, source))
        funding = developer.get('funding_wallet') or {}
        funded = developer.get('deployer')
        funder = funding.get('address') if isinstance(funding, dict) else None
        if funded and funder and Web3.is_address(funded) and Web3.is_address(funder):
            con.execute('''
                INSERT OR IGNORE INTO funding_links(funded_address,funding_address,
                    token_address,source,evidence,observed_at) VALUES (?,?,?,?,?,?)
            ''', (Web3.to_checksum_address(funded), Web3.to_checksum_address(funder),
                  token, funding.get('evidence', 'observed funding transaction'),
                  json.dumps({'ownership_claim': False}), now))
        deployer = developer.get('deployer')
        if deployer and Web3.is_address(deployer):
            con.execute('''
                UPDATE developers SET deployment_count=(
                    SELECT COUNT(DISTINCT token_address) FROM developer_history
                    WHERE developer_address=? AND role='deployer'
                ) WHERE address=?
            ''', (Web3.to_checksum_address(deployer), Web3.to_checksum_address(deployer)))
    record_intelligence_evidence({
        'address': token, 'analyzed_at': now,
        'developer': developer, 'contract': contract,
    })


def add_previous_deployments(deployer, deployments, source='Etherscan V2 account history'):
    developer = Web3.to_checksum_address(deployer)
    now = _utcnow()
    with db_connect() as con:
        con.execute('''
            INSERT OR IGNORE INTO developers(address,first_seen_at,last_seen_at,source)
            VALUES (?,?,?,?)
        ''', (developer, now, now, source))
        for item in deployments:
            token = item.get('contract_address')
            if not token or not Web3.is_address(token):
                continue
            con.execute('''
                INSERT OR IGNORE INTO developer_history(token_address,developer_address,
                    role,source,observed_at,evidence) VALUES (?,?,?,?,?,?)
            ''', (Web3.to_checksum_address(token), developer, 'previous_deployment',
                  source, item.get('timestamp') or now, json.dumps(item)))
        con.execute('''
            UPDATE developers SET last_history_scan_at=?, deployment_count=(
                SELECT COUNT(DISTINCT token_address) FROM developer_history
                WHERE developer_address=? AND role IN ('deployer','previous_deployment')
            ) WHERE address=?
        ''', (now, developer, developer))


def recent_tokens(limit=10):
    with db_connect() as con:
        rows = con.execute('''
            SELECT address,first_seen_at,analysis_state,decision,risk_score,
                evidence_confidence,liquidity_usd FROM tokens
            ORDER BY first_seen_at DESC LIMIT ?
        ''', (max(1, min(int(limit), 50)),)).fetchall()
    keys = ('address','first_seen_at','analysis_state','decision','risk_score',
            'evidence_confidence','liquidity_usd')
    return [dict(zip(keys, row)) for row in rows]


def add_watchlist(address, reason, criteria):
    checksum = Web3.to_checksum_address(address)
    with db_connect() as con:
        con.execute('''
            INSERT INTO watchlists(token_address,reason,criteria,created_at,active)
            VALUES (?,?,?,?,1) ON CONFLICT(token_address) DO UPDATE SET
                reason=excluded.reason, criteria=excluded.criteria, active=1
        ''', (checksum, reason, json.dumps(criteria), _utcnow()))


def list_watchlist(limit=20):
    with db_connect() as con:
        rows = con.execute('''
            SELECT w.token_address,w.reason,w.created_at,t.risk_score,
                t.evidence_confidence,t.liquidity_usd FROM watchlists w
            LEFT JOIN tokens t ON t.address=w.token_address
            WHERE w.active=1 ORDER BY w.created_at DESC LIMIT ?
        ''', (max(1, min(int(limit), 50)),)).fetchall()
    keys = ('address','reason','created_at','risk_score','evidence_confidence','liquidity_usd')
    return [dict(zip(keys, row)) for row in rows]


def developer_summary(address):
    checksum = Web3.to_checksum_address(address)
    with db_connect() as con:
        developer = con.execute('''
            SELECT address,first_seen_at,last_seen_at,deployment_count,
                last_history_scan_at,source FROM developers WHERE address=?
        ''', (checksum,)).fetchone()
        history = con.execute('''
            SELECT token_address,role,source,observed_at FROM developer_history
            WHERE developer_address=? ORDER BY observed_at DESC LIMIT 20
        ''', (checksum,)).fetchall()
        funding = con.execute('''
            SELECT funded_address,funding_address,token_address,source,observed_at
            FROM funding_links WHERE funded_address=? OR funding_address=?
            ORDER BY observed_at DESC LIMIT 20
        ''', (checksum, checksum)).fetchall()
    return {
        'developer': dict(zip(
            ('address','first_seen_at','last_seen_at','deployment_count',
             'last_history_scan_at','source'), developer
        )) if developer else None,
        'history': [dict(zip(('token_address','role','source','observed_at'), row))
                    for row in history],
        'funding_links': [dict(zip(
            ('funded_address','funding_address','token_address','source','observed_at'), row
        )) for row in funding],
    }


def wallet_summary(address):
    checksum = Web3.to_checksum_address(address)
    with db_connect() as con:
        rows = con.execute('''
            SELECT from_address,to_address,relationship,token_address,source,
                provenance,observed_at,confidence,ownership_claim,evidence
            FROM wallet_relationships
            WHERE from_address=? OR to_address=? ORDER BY observed_at DESC LIMIT 100
        ''', (checksum, checksum)).fetchall()
    keys = ('from','to','relationship','token_address','source','provenance',
            'observed_at','confidence','ownership_claim','evidence')
    edges = []
    for row in rows:
        item = dict(zip(keys, row))
        item['ownership_claim'] = bool(item['ownership_claim'])
        try:
            item['evidence'] = json.loads(item['evidence'])
        except (TypeError, ValueError):
            item['evidence'] = {}
        edges.append(item)
    return {'mode': 'PAPER_ONLY', 'address': checksum,
            'relationships': edges, 'ownership_status': 'UNKNOWN',
            'note': 'Public evidence relationships do not establish common ownership.'}


def cluster_summary(address):
    report = wallet_summary(address)
    edges = list(report['relationships'])
    checksum = report['address']
    with db_connect() as con:
        infrastructure = con.execute('''
            SELECT DISTINCT p2.token0_address,p2.token1_address,
                p1.factory_address,p1.hook_address
            FROM discovered_pools p1 JOIN discovered_pools p2
              ON (p1.factory_address=p2.factory_address OR
                  (p1.hook_address IS NOT NULL AND p1.hook_address=p2.hook_address))
            WHERE p1.canonical=1 AND p2.canonical=1
              AND (p1.token0_address=? OR p1.token1_address=?) LIMIT 100
        ''', (checksum, checksum)).fetchall()
        templates = con.execute('''
            SELECT other.token_address
            FROM contract_fingerprints seed JOIN contract_fingerprints other
              ON seed.runtime_code_hash=other.runtime_code_hash
            WHERE seed.token_address=? AND other.token_address!=? LIMIT 50
        ''', (checksum, checksum)).fetchall()
        role_peers = con.execute('''
            SELECT DISTINCT other.to_address,seed.relationship,seed.from_address,
                MIN(seed.confidence,other.confidence)
            FROM wallet_relationships seed JOIN wallet_relationships other
              ON seed.from_address=other.from_address
             AND seed.relationship=other.relationship
            WHERE seed.to_address=? AND other.to_address!=?
              AND seed.relationship IN ('OWNER','DEPLOYER','FACTORY','UPGRADE_AUTHORITY')
            LIMIT 100
        ''', (checksum, checksum)).fetchall()
    now = _utcnow()
    for token0, token1, factory, hook in infrastructure:
        for related in (token0, token1):
            if related == checksum:
                continue
            edges.append({
                'from': checksum, 'to': related,
                'relationship': 'SHARED_HOOK' if hook else 'SHARED_FACTORY',
                'source': 'verified on-chain pool event', 'confidence': 95,
                'observed_at': now,
                'evidence': {'infrastructure_address': hook or factory,
                             'ownership_claim': False},
            })
    for (related,) in templates:
        edges.append({
            'from': checksum, 'to': related, 'relationship': 'SHARED_TEMPLATE',
            'source': 'Base RPC runtime bytecode hash', 'confidence': 90,
            'observed_at': now, 'evidence': {'ownership_claim': False},
        })
    for related, role, shared_address, confidence in role_peers:
        edges.append({
            'from': checksum, 'to': related, 'relationship': f'SHARED_{role}',
            'source': 'persisted verified role evidence',
            'confidence': confidence, 'observed_at': now,
            'evidence': {'shared_address': shared_address,
                         'ownership_claim': False},
        })
    nodes = [report['address']]
    for edge in edges:
        nodes.extend((edge['from'], edge['to']))
    cluster = build_cluster(nodes, edges)
    cluster['mode'] = 'PAPER_ONLY'
    return cluster


def social_summary(address):
    checksum = Web3.to_checksum_address(address)
    with db_connect() as con:
        rows = con.execute('''
            SELECT url,platform,account_type,relationship,source,provenance,
                observed_at,confidence,verification_status
            FROM social_evidence WHERE token_address=? ORDER BY observed_at DESC
        ''', (checksum,)).fetchall()
    keys = ('url','platform','account_type','relationship','source','provenance',
            'observed_at','confidence','verification_status')
    return {'mode': 'PAPER_ONLY', 'token_address': checksum,
            'status': 'PASS' if rows else 'UNKNOWN',
            'evidence': [dict(zip(keys, row)) for row in rows],
            'developer_relationship_status': 'UNKNOWN' if rows else 'UNKNOWN'}


def track_address(address):
    checksum = Web3.to_checksum_address(address)
    with db_connect() as con:
        con.execute('INSERT OR IGNORE INTO tracked_addresses(address,added_at) VALUES (?,?)',
                    (checksum, _utcnow()))
    return checksum


def untrack_address(address):
    checksum = Web3.to_checksum_address(address)
    with db_connect() as con:
        return con.execute('DELETE FROM tracked_addresses WHERE address=?',
                           (checksum,)).rowcount > 0


def tracked_addresses():
    with db_connect() as con:
        return [row[0] for row in con.execute(
            'SELECT address FROM tracked_addresses ORDER BY added_at'
        ).fetchall()]


def reserve_alert(dedupe_key, token_address, alert_type='new_token'):
    try:
        with db_connect() as con:
            con.execute('''
                INSERT INTO alerts(dedupe_key,token_address,alert_type,status,created_at)
                VALUES (?,?,?,'PENDING',?)
            ''', (dedupe_key, token_address, alert_type, _utcnow()))
        return True
    except sqlite3.IntegrityError:
        return False


def finish_alert(dedupe_key, error=None):
    with db_connect() as con:
        con.execute('''
            UPDATE alerts SET status=?,sent_at=?,error=? WHERE dedupe_key=?
        ''', ('FAILED' if error else 'SENT', _utcnow() if not error else None,
              str(error)[:300] if error else None, dedupe_key))


def alert_count_since(iso_timestamp):
    with db_connect() as con:
        return con.execute(
            "SELECT COUNT(*) FROM alerts WHERE status='SENT' AND sent_at>=?",
            (iso_timestamp,),
        ).fetchone()[0]


def focus_token_addresses(focus_address):
    if not focus_address or not Web3.is_address(focus_address):
        return []
    checksum = Web3.to_checksum_address(focus_address)
    with db_connect() as con:
        direct = con.execute('SELECT address FROM tokens WHERE address=?', (checksum,)).fetchall()
        related = con.execute('''
            SELECT DISTINCT token_address FROM developer_history
            WHERE developer_address=?
        ''', (checksum,)).fetchall()
    return sorted({row[0] for row in direct + related})


def consume_rpc_request(provider_host, daily_limit, usage_date=None):
    """Atomically reserve one provider request; persists across restarts."""
    day = usage_date or datetime.now(timezone.utc).date().isoformat()
    limit = max(1, int(daily_limit))
    with db_connect() as con:
        con.execute('BEGIN IMMEDIATE')
        con.execute('''
            INSERT OR IGNORE INTO rpc_usage(provider_host,usage_date,request_count,updated_at)
            VALUES (?,?,0,?)
        ''', (provider_host, day, _utcnow()))
        count = con.execute('''
            SELECT request_count FROM rpc_usage
            WHERE provider_host=? AND usage_date=?
        ''', (provider_host, day)).fetchone()[0]
        if count >= limit:
            return False, count
        count += 1
        con.execute('''
            UPDATE rpc_usage SET request_count=?,updated_at=?
            WHERE provider_host=? AND usage_date=?
        ''', (count, _utcnow(), provider_host, day))
    return True, count


def rpc_usage_status(provider_host, daily_limit, usage_date=None):
    day = usage_date or datetime.now(timezone.utc).date().isoformat()
    with db_connect() as con:
        row = con.execute('''
            SELECT request_count,updated_at FROM rpc_usage
            WHERE provider_host=? AND usage_date=?
        ''', (provider_host, day)).fetchone()
    used = row[0] if row else 0
    return {
        'usage_date': day, 'used': used, 'limit': int(daily_limit),
        'remaining': max(0, int(daily_limit) - used),
        'updated_at': row[1] if row else None,
    }
