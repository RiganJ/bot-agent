# Base AI Sniper Agent — v0.3.3

**PAPER ONLY.** This is a read-only Base mainnet discovery, intelligence, and wallet-evidence monitor. It has no private-key handling, signing, transaction submission, token approval, swap, or automatic real-money trading path.

v0.3.3 upgrades the existing project in place. Existing Telegram commands, SQLite data, scanner controls, authorization, focus lock, RPC budgets, reorg semantics, and PAPER ONLY behavior remain compatible.

## v0.3.3 intelligence

- Developer evidence keeps deployer, owner, factory, funding wallet, proxy authority, and implementation as separate roles with source, provenance, observation time, confidence, and status.
- Public wallet history reports direct creations and funding transactions. Clusters retain their evidence edges and never infer common ownership from a shared factory, hook, template, or other infrastructure alone.
- Website and X links are extracted from provider metadata with their source path. They are labeled as project accounts; developer-account relationships remain `UNKNOWN` unless separately verified.
- Public hex, Base64, caller-supplied ABI calldata, common encrypted envelope formats, proxy storage, and runtime bytecode can be inspected read-only. Encryption detection reports metadata and never claims plaintext recovery.
- Static capability indicators and opaque patterns retain `PASS`, `FAIL`, `UNKNOWN`, and `NOT_APPLICABLE` distinctions. Obfuscation or encryption is not automatically classified as malicious.
- Credentials and secret-like fields are recursively redacted before v0.3.3 persistence and bot output.

Optional decryption is deliberately local-only and supports only the documented `BASE_AI_OWNED_AES256_GCM_V1` data envelope. It does not support wallets or Ethereum keystores. The user must explicitly attest ownership and enter the password through a local hidden prompt:

```powershell
python -m app.local_decrypt owned-envelope.json output.bin --i-own-this-data
```

Never provide private keys, seed phrases, keystore passwords, decryption credentials, or decrypted secrets to Telegram or an LLM/API.

## What v0.3 does

- Discovers confirmed pool-creation events directly from a small allowlist of documented Base DEX factories.
- Resolves factory, pool address or pool ID, currencies, tokens, configured quote asset, block, block hash, transaction hash, and log index.
- Persists pool/token deduplication and confirmed checkpoints in SQLite.
- Feeds discovered tokens into the existing v0.2 GoPlus, proxy, holder, market, and risk intelligence engine through a bounded asynchronous worker queue.
- Records deployer, owner, factory, proxy authority, previous direct deployments, and observed funding relationships as separate evidence.
- Sends duplicate-safe, rate-limited Telegram alerts when all configured watchlist criteria have usable evidence and match.

Risk remains directional: **0 is the lowest detected risk and 100 is the highest detected risk**. Missing evidence does not lower the score or prove safety. Evidence confidence remains separate. Unavailable analysis is `INCONCLUSIVE`.

## Supported discovery protocols

The default on-chain allowlist is deliberately explicit:

- `uniswap_v3`: official Base `UniswapV3Factory` at `0x33128a8fC17869897dcE68Ed026d694621f6FDfD` ([Uniswap Base deployments](https://developers.uniswap.org/docs/protocols/v3/deployments/v3-base-deployments)).
- `aerodrome_v2`: official Aerodrome `PoolFactory` at `0x420DD381b31aEf6683db6B902084cB0FFECe40Da` and its documented `PoolCreated` event ([Aerodrome contracts](https://github.com/aerodrome-finance/contracts)).
- `uniswap_v4`: Base `PoolManager` at `0x498581ff718922c3f8e6a244956af099b2652b2b`; discovery decodes `Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)` from the indexed pool ID and currencies ([official v4 deployments](https://developers.uniswap.org/docs/protocols/v4/deployments), [IPoolManager ABI](https://github.com/Uniswap/v4-core/blob/main/src/interfaces/IPoolManager.sol)).
- `aerodrome_slipstream`: Base CL factory at `0x5e7BB104d84c7CB9B682AaC2F3d509f5F406809A`; discovery decodes `PoolCreated(address,address,int24,address)` ([verified Base deployment and ABI](https://basescan.org/address/0x5e7BB104d84c7CB9B682AaC2F3d509f5F406809A#code), [official Slipstream interface](https://github.com/aerodrome-finance/slipstream/blob/main/contracts/core/interfaces/ICLFactory.sol)).

`SCANNER_PROTOCOLS` defaults to all four and can be set to a comma-separated subset. Unknown names fail at startup instead of silently scanning an unverified factory. V4 currency address zero represents native ETH; the normalized token address maps it to Base WETH for the existing token-analysis pipeline while retaining the original zero currency. V4 pool identity uses the emitted `bytes32` pool ID, never the shared PoolManager address.

An optional secondary source is available with `DEXSCREENER_DISCOVERY=true`. It uses only DEX Screener's documented `GET /token-profiles/latest/v1` and `GET /tokens/v1/base/{tokenAddresses}` endpoints ([API reference](https://docs.dexscreener.com/api/reference)). It is disabled by default, polls no faster than once per minute, requests at most two API calls per poll, and paces requests. DEX Screener rows are marked `reported_unverified`; their `pairCreatedAt` is stored separately from local `discovered_at` and is not treated as an on-chain timestamp, block, or transaction. Ambiguous V4 entries that identify only the shared PoolManager are ignored rather than merged into one false pool.

## Setup

Python 3.11+:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

At minimum, configure:

```dotenv
TELEGRAM_BOT_TOKEN=...
TELEGRAM_ALLOWED_USER_ID=...
BASE_RPC_URL=https://your-base-mainnet-rpc
```

The RPC must support `eth_getLogs`. Public RPCs may impose small block-range limits; reduce `SCANNER_BLOCK_CHUNK` when necessary.

Optional secondary discovery:

```dotenv
DEXSCREENER_DISCOVERY=false
DEXSCREENER_POLL_SECONDS=300
```

Run:

```powershell
python -m app.bot
```

The scanner service starts with the bot, but discovery runs only when the persisted `scanner_enabled` state is true. Use `/scan_on` and `/scan_off`.

## Scanner reliability model

- The first run starts from `SCANNER_BOOTSTRAP_BLOCKS` behind the confirmed head, or from `SCANNER_START_BLOCK` when set. It is always bounded by `SCANNER_MAX_BACKFILL_BLOCKS`; it never defaults to genesis.
- Only blocks at least `SCANNER_CONFIRMATIONS` deep are scanned.
- A checkpoint is committed after all events in a chunk have been persisted.
- On restart, scanning resumes at the block after the checkpoint.
- The saved checkpoint hash is compared with the current canonical hash. A mismatch or chain rollback rewinds `SCANNER_REORG_REWIND_BLOCKS`, marks orphan-only pools/tokens noncanonical, and replays the range.
- The four on-chain protocols share one `eth_getLogs` cursor because they are queried together over identical block ranges. Per-protocol coverage counters/cursors are saved with each checkpoint. When a protocol is newly enabled against an existing v0.3 checkpoint, it replays from the saved bounded initial anchor before returning to the head; `SCANNER_MAX_BACKFILL_BLOCKS` and `SCANNER_START_BLOCK` remain the explicit bounds.
- Pool addresses, factory/log identities, token addresses, watchlist entries, and alerts have persistent uniqueness constraints.
- RPC calls use bounded retries and exponential backoff. Repeated scan-cycle failures open a temporary circuit breaker.
- Discovery and analysis queues are bounded. Blocking Web3, SQLite, and provider work runs outside the Telegram event loop.

## Intelligence and watchlist settings

The v0.2 analyzer is reused for manual and discovered-token analysis. A token matches the automatic watchlist only when all of these fields are available:

- decision is `WATCHLIST` and no hard rejection is present;
- liquidity is at least `WATCH_MIN_LIQUIDITY_USD`;
- oldest observed pair age is at most `WATCH_MAX_TOKEN_AGE_HOURS`;
- detected risk is at most `WATCH_MAX_RISK_SCORE`;
- evidence confidence is at least `WATCH_MIN_EVIDENCE_CONFIDENCE`.

Missing liquidity, age, risk, or confidence does not match. A watchlist match is not a buy recommendation and never triggers a transaction.

## Developer evidence

When evidence is available, v0.3 stores these roles independently:

- contract deployer;
- on-chain token owner;
- creation factory;
- EIP-1967 proxy admin/ProxyAdmin owner or beacon owner;
- earliest observed native-asset funding wallet.

With `BASESCAN_API_KEY` or `ETHERSCAN_API_KEY`, direct previous contract-creation transactions by known/tracked deployers are refreshed periodically. Factory/internal creations may be absent when trace data is unavailable. Funding edges explicitly store `ownership_claim=false`; they are not proof of common control. The system never fabricates social identity, X/Twitter accounts, reputation, or linked wallets.

## Telegram commands

Every command retains `TELEGRAM_ALLOWED_USER_ID` authorization.

- `/status` — existing paper-mode state.
- `/analyze 0xToken` — existing manual v0.2 intelligence report.
- `/history` — existing recent manual analyses.
- `/scan_on`, `/scan_off` — enable or disable the persistent scanner.
- `/scanner_status` — checkpoint, queue, protocol, focus, failure, and circuit status.
- `/rpc_status` — active sanitized `eth_chainId`, `eth_blockNumber`, and one-block factory-filtered `eth_getLogs` health checks plus the last RPC failure.
- `/discovery_status` — persistent pipeline counters, persisted pool/token totals, queue depth, checkpoint/lag, and recent sanitized errors. It separates empty ranges, decode failures, persistence failures, analysis rejection, worker failure, and provider failure.
- `/protocol_status` — per-protocol blocks scanned, events detected, decoding failures, last successful scan, and cursor; also reports DEX Screener's independent timestamp cursor and provider request usage, plus Base RPC budget and log-range ceiling.
- `/recent` — recently discovered tokens and analysis state.
- `/watchlist` — active automatic watchlist matches.
- `/dev 0xAddress` — recorded deployment roles and funding evidence.
- `/wallet 0xAddress` — public explorer history, direct creations, funding evidence, and stored relationships.
- `/cluster 0xAddress` — explainable wallet/token evidence graph; common ownership remains `UNKNOWN` unless independently proven.
- `/social 0xToken` — project website/X evidence with provenance and verification status.
- `/decode publicPayload` — decode public hex/Base64 and identify encrypted formats; credentials are rejected.
- `/contract_inspect 0xContract` — proxy, upgrade-authority, static capability, opacity, evidence, and uncertainty summary.
- `/track 0xAddress`, `/untrack 0xAddress` — manage deployer-history monitoring.
- `/focus 0xAddress`, `/unfocus` — persistently restrict work to a known token/developer relationship and then resume enabled discovery.

## Focus lock

Focus does not unlock, trade, or infer identity. While focus is active:

- new unrelated pool discovery pauses;
- queued unrelated analyses are skipped;
- known tokens related to the focused token/developer are periodically reanalyzed;
- the focused/tracked developer history can continue refreshing.

`/unfocus` resumes discovery only if the persistent scanner flag is enabled.

## Database migrations

`db_connect()` performs idempotent migrations and never drops existing tables or rewrites existing analysis/state rows. v0.3.3 adds:

- `discovered_pools` (protocol-independent address/pool-ID identity, source, chain and verification metadata) and `protocol_scan_status`;
- existing `pools` rows are backfilled into the normalized table; original rows remain intact;
- `schema_migrations`, `pools`, `tokens`, `scan_checkpoints`, `rpc_usage`;
- `developers`, `developer_history`, `funding_links`, `tracked_addresses`;
- `watchlists`, `alerts`.
- `discovery_metrics`, `discovery_errors` (bounded sanitized diagnostic history).
- `intelligence_evidence`, `wallet_relationships`, and `social_evidence` for provenance-aware v0.3.3 reports.

The existing `analyses`, `state`, and all their rows are preserved.

## Configuration

See `.env.example` for every setting. Important groups are:

- RPC scanning: `SCANNER_PROTOCOLS`, confirmations, bootstrap/backfill, block chunk, poll interval, retry and reorg settings.
- Work limits: `ANALYSIS_QUEUE_SIZE`, `ANALYSIS_CONCURRENCY`, circuit-breaker settings.
- Filters: `WATCH_MIN_LIQUIDITY_USD`, `WATCH_MAX_TOKEN_AGE_HOURS`, `WATCH_MAX_RISK_SCORE`, `WATCH_MIN_EVIDENCE_CONFIDENCE`.
- Alerts: `ALERT_MIN_INTERVAL_SECONDS`, `ALERT_MAX_PER_HOUR`.
- Optional evidence: `BASESCAN_API_KEY` or `ETHERSCAN_API_KEY`.

Secrets are passed only as provider parameters. Provider URLs, API keys, exception messages, and bot tokens are not included in scanner status, Telegram alerts, or structured logs.

## Discovery diagnostics and historical replay

The discovery path is now measured at each boundary: successful scanned ranges, raw pool logs, decoded events, decode failures, newly persisted tokens, queue admissions, completed analyses, risk rejections, watchlist-filter exclusions, unsupported contracts, persistence/analysis/worker/provider failures, and sent alerts. Counters survive restarts. A range that returns no logs increments both `scanned_ranges` and `empty_ranges`; it is not conflated with a decoding or provider failure.

Pool and token rows are committed before analysis is queued. `/recent` reads discovered tokens directly and therefore includes rejected, inconclusive, unsupported, and still-pending tokens; `/watchlist` remains the filtered subset.

Regression fixtures replay independently verified Base events for each on-chain protocol:

- Uniswap V3 block `22712412`, transaction [`0x4e6d…fed5`](https://basescan.org/tx/0x4e6da7746f4a228b3ade82939252a84eedcf96617f2785b62d532a1189b7fed5).
- Aerodrome V2 block `16894743`, transaction `0xc504…62a4`, independently documented in the [Bitquery Aerodrome Base example](https://docs.bitquery.io/docs/blockchain/Base/aerodrome-base-api/).
- Uniswap V4 block `53531133`, transaction [`0x296e…3e2e`](https://basescan.org/tx/0x296eca8ef3428cabc6085a6a718928e271beb33f733477f4cf0f4bad6f593e2e), including native ETH currency zero and its PoolManager pool ID.
- Aerodrome Slipstream block `53507356`, transaction [`0x5844…6cd`](https://basescan.org/tx/0x58441a2333203c94491b2b5a51e53a24373a81c8c55eb2bed7476803e735e6cd).

`replay_historical_range()` accepts at most 10 blocks, performs only `eth_getLogs` decoding, and never writes pools, tokens, watchlists, alerts, or the live checkpoint. The deterministic tests use captured Base receipt logs and explorer transaction references, so the normal test suite does not require an RPC key or network access.

## RPC diagnostics

The scanner uses a read-only JSON-RPC transport that records only the provider hostname. It distinguishes:

- HTTP rate limiting (`429`) from other HTTP transport failures (`403`, `500`, and similar);
- JSON-RPC error objects and sanitized error codes/messages;
- connection/read timeouts;
- network transport failures;
- malformed JSON and malformed JSON-RPC results;
- wrong-chain responses.

Failure logs include the hostname, JSON-RPC method, HTTP status, sanitized RPC code/message, requested block range, elapsed milliseconds, and retry count. Full RPC URLs, URL paths/query strings, credentials, authorization headers, API keys, and Telegram secrets are never logged.

`eth_getLogs` starts with `SCANNER_BLOCK_CHUNK`, reduces rejected ranges down to `SCANNER_MIN_BLOCK_CHUNK`, and uses bounded exponential backoff with jitter. A failed log range or failed event-processing step does not advance the checkpoint.

For Alchemy hosts, every `eth_getLogs` call is capped to 10 blocks before the first request. A limit reported by another provider is learned and saved in SQLite state, so retries and restarts retain the same ceiling. `SCANNER_PROVIDER_MAX_BLOCK_RANGE` can impose a smaller explicit ceiling; it cannot make the scanner ignore a learned lower limit.

`SCANNER_RPC_REQUESTS_PER_SECOND` applies steady request pacing, while `SCANNER_RPC_DAILY_REQUEST_BUDGET` is counted atomically in SQLite and survives restarts. Both successful and failed provider requests consume the configured budget. A zero daily budget disables the daily ceiling.

Scanner status reports the latest confirmed block, checkpoint block, exact lag in blocks, current range ceiling, daily usage/remaining budget, and estimated request capacity. It reports `SCANNER_LAGGING` when lag exceeds `SCANNER_LAG_THRESHOLD_BLOCKS` or when the configured per-second/daily allowance cannot sustain Base block production. It never skips unscanned blocks to reduce lag.

When no checkpoint exists, the initial confirmed-range start is saved separately before the first log request. Provider failures therefore reuse the same anchor instead of repeatedly moving the initial window forward. DEX Screener has no historical block cursor: its latest-profile snapshot is secondary discovery only and cannot provide complete historical coverage.

## Remaining uncertainties

- Public RPC endpoints can throttle or reject log ranges. A production deployment should use a trusted Base RPC with documented `eth_getLogs` limits.
- The supported on-chain allowlist is intentionally not exhaustive. Other Base AMMs and factories are not scanned.
- DEX Screener's latest-profile list is a limited snapshot, not an exhaustive token or historical pool feed. Its rows remain unverified until an on-chain factory event is observed.
- Etherscan account history proves only observed direct transactions. Internal/factory deployments require trace coverage that may not be available.
- DEX liquidity and pair age come from DEX Screener and can lag or be incomplete.
- GoPlus and holder lists remain provider evidence, not a substitute for a bytecode audit.
- Telegram delivery failure is recorded. Alerts are deduplicated persistently, so operators should inspect `/watchlist` after an outage.

## Tests

```powershell
python -m pytest -q
```

The suite includes mocked factory log decoding, pool/token deduplication, checkpoint restart, reorg replay, provider circuit breaking, focus behavior, inconclusive analysis, developer/funding evidence, and duplicate-safe Telegram alerts.
