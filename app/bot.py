"""Telegram control plane. No private keys and no live trading endpoints."""
import asyncio
import json
import logging
import os
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
from web3 import Web3
from .core import (
    inspect_contract, paper_status, read_state, write_state, set_focus,
    recent_tokens, list_watchlist, developer_summary, track_address,
    untrack_address,
    record_developer_evidence,
    discovery_diagnostics,
    protocol_scan_status,
    wallet_summary, cluster_summary, social_summary,
)
from .intelligence import fetch_wallet_history
from .intelligence_v033 import decode_public_payload, redact_sensitive
from .scanner import ScannerService

logging.basicConfig(level=logging.INFO)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


def authorized(update: Update):
    allowed = os.getenv('TELEGRAM_ALLOWED_USER_ID', '').strip()
    return bool(allowed and update.effective_user and str(update.effective_user.id) == allowed)


async def guard(update):
    if not authorized(update):
        await update.effective_message.reply_text('Unauthorized. Set TELEGRAM_ALLOWED_USER_ID in .env.')
        return False
    return True


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    await update.message.reply_text(
        'Base AI Sniper Agent v0.3.3 — PAPER ONLY. Commands: /status '
        '/analyze 0x... /focus 0x... /unfocus /scan_on /scan_off '
        '/scanner_status /rpc_status /discovery_status /protocol_status '
        '/recent /watchlist '
        '/dev 0x... /wallet 0x... /cluster 0x... /social 0x... '
        '/decode payload /contract_inspect 0x... /track 0x... '
        '/untrack 0x... /history'
    )


async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    data = await asyncio.to_thread(paper_status)
    await update.message.reply_text(json.dumps(data, indent=2))


async def analyze(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    if len(context.args) != 1:
        await update.message.reply_text('Usage: /analyze 0xTokenContractAddress')
        return
    try:
        result = await asyncio.to_thread(inspect_contract, context.args[0])
        await asyncio.to_thread(
            record_developer_evidence, result['address'],
            result.get('developer', {}), result.get('contract', {})
        )
        await update.message.reply_text(format_analysis(result)[:3900])
    except Exception as exc:
        logging.error('Contract inspection failed error_type=%s', type(exc).__name__)
        await update.message.reply_text(f'Analysis failed: {type(exc).__name__}. Check RPC/address and server logs.')


def format_analysis(result):
    contract = result.get('contract', {})
    developer = result.get('developer', {})
    market = result.get('market', {})
    security = result.get('security', {}).get('checks', {})
    holders = result.get('holders', {})
    risk = result.get('risk', {})
    pool_label, pool_identity = _market_pool_identity(market)
    source_status = market.get('liquidity_source_status') or 'UNKNOWN'
    liquidity_scope = (
        market.get('liquidity_attribution')
        or market.get('liquidity_scope')
        or 'UNKNOWN'
    )
    lines = [
        f"Token report — {result.get('decision', 'NO_BUY')} (PAPER ONLY)",
        f"Address: {result.get('address', 'unknown')}",
        f"Contract: {contract.get('contract_type', 'unknown')} | "
        f"ERC-20: {'yes' if contract.get('metadata', {}).get('is_erc20') else 'unknown/no'}",
        f"Implementation: {contract.get('implementation') or 'NOT APPLICABLE/UNKNOWN'} | "
        f"Upgrade authority: {contract.get('upgrade_authority') or contract.get('upgrade_authority_status', 'NOT APPLICABLE')}",
        f"Developer: {developer.get('deployer') or 'UNKNOWN'}"
        + (f" | Factory: {developer['factory']}" if developer.get('factory') else ''),
        f"Owner: {developer.get('owner') or 'UNKNOWN'}",
        f"Funding wallet: {((developer.get('funding_wallet') or {}).get('address')) or 'UNKNOWN'}"
        " (funding link is not ownership evidence)",
        f"Liquidity: {_money(market.get('liquidity_usd'))} | "
        f"24h volume: {_money(market.get('volume_24h_usd'))}",
        f"Liquidity source status: {source_status} | Scope: {liquidity_scope}",
        f"{pool_label}: {pool_identity}",
        f"Pairs: {market.get('pair_count', 'UNKNOWN')} | "
        f"Oldest pair age: {_days(market.get('oldest_pair_age_days'))}",
        f"24h activity: {_activity_text(market.get('activity_24h'))} | "
        f"Price change: {_percent(market.get('price_change_24h_percent'))}",
        f"Holder concentration: {_holder_text(holders)}",
        "Security: " + ', '.join(
            f"{name}={check.get('status', 'UNKNOWN')}"
            for name, check in security.items()
        ),
        f"Risk score: {risk.get('risk_score', 'UNKNOWN')}/100 "
        "(0=lowest detected risk; 100=highest) | "
        f"Evidence confidence: {risk.get('evidence_confidence', 'UNKNOWN')}%",
        f"Assessment: {risk.get('assessment') or 'UNKNOWN'} "
        "(UNKNOWN is never classified as safe)",
    ]
    if risk.get('hard_rejections'):
        lines.append("Rejection: " + "; ".join(risk["hard_rejections"]))
    missing = result.get('missing_evidence', [])
    if missing:
        lines.append("Missing evidence: " + "; ".join(missing))
    coverage = result.get('check_coverage', {})
    for state, label in (
        ('unsupported', 'Unsupported checks'),
        ('not_applicable', 'Not applicable checks'),
    ):
        if coverage.get(state):
            lines.append(f"{label}: " + ", ".join(coverage[state]))
    if developer.get('deployer_note'):
        lines.append("Deployer data: " + developer['deployer_note'])
    errors = result.get('api_errors', [])
    if errors:
        lines.append("Provider issues: " + "; ".join(
            f"{error.get('source')}: {error.get('message')}" for error in errors
        ))
    return '\n'.join(lines)


def _market_pool_identity(market):
    identity = market.get('discovered_pool_identity')
    identity_type = market.get('discovered_pool_identity_type')
    if identity:
        label = 'Pool ID' if identity_type == 'bytes32_pool_id' else 'Pool contract'
        return label, str(identity)
    pool_ids = market.get('candidate_pool_ids')
    if isinstance(pool_ids, list) and pool_ids:
        return ('Pool ID' if len(pool_ids) == 1 else 'Pool IDs'), ', '.join(
            str(value) for value in pool_ids
        )
    pool_addresses = market.get('verified_pool_addresses')
    if isinstance(pool_addresses, list) and pool_addresses:
        return (
            'Pool contract' if len(pool_addresses) == 1 else 'Pool contracts',
            ', '.join(str(value) for value in pool_addresses),
        )
    pair_details = market.get('pair_details')
    if isinstance(pair_details, list):
        identities = [
            str(item.get('pair_id')) for item in pair_details
            if isinstance(item, dict) and item.get('pair_id')
        ]
        if identities:
            types = {
                item.get('pair_identity_type') for item in pair_details
                if isinstance(item, dict) and item.get('pair_id')
            }
            label = 'Pool ID' if types == {'bytes32_pool_id'} else 'Pool identity'
            if len(identities) > 1:
                label += 's'
            return label, ', '.join(identities)
    return 'Pool identity', 'UNKNOWN'


def _money(value):
    return f"${float(value):,.2f}" if value is not None else 'UNKNOWN'


def _days(value):
    return f"{value} days" if value is not None else 'UNKNOWN'


def _percent(value):
    return f"{float(value):.2f}%" if value is not None else 'UNKNOWN'


def _activity_text(activity):
    if not isinstance(activity, dict) or not activity:
        return 'UNKNOWN'
    buys = activity.get('buys', 'UNKNOWN')
    sells = activity.get('sells', 'UNKNOWN')
    return f"{buys} buys / {sells} sells"


def _holder_text(holders):
    if holders.get('status') != 'PASS':
        return 'UNKNOWN'
    categories = {}
    for row in holders.get('classifications', []):
        category = row.get('classification', 'unclassified')
        categories[category] = categories.get(category, 0) + 1
    category_text = ', '.join(f"{name}={count}" for name, count in sorted(categories.items()))
    return (f"top 1 {float(holders['top_holder_percent']):.2f}% / "
            f"top 10 {float(holders['top_10_percent']):.2f}%"
            + (f" | categories: {category_text}" if category_text else ""))


async def focus(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    try:
        if len(context.args) != 1: raise ValueError('Usage: /focus 0xDeveloperWallet')
        addr = set_focus(context.args[0])
        service = context.application.bot_data.get('scanner')
        if service: service.wake()
        await update.message.reply_text(f'Focused address: {addr}. Unrelated discovery and analysis are paused; known related tokens and this developer remain monitored. This is not verified identity evidence.')
    except ValueError as exc:
        await update.message.reply_text(str(exc))


async def unfocus(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    write_state('focused_developer', None)
    service = context.application.bot_data.get('scanner')
    if service: service.wake()
    await update.message.reply_text('Focus cleared. Enabled discovery resumes. No trading actions were performed.')


async def scan_on(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    write_state('scanner_enabled', True)
    service = context.application.bot_data.get('scanner')
    if service: service.wake()
    suffix = (' Focus is active, so unrelated discovery remains paused.'
              if read_state('focused_developer') else '')
    await update.message.reply_text('Persistent Base pool scanner enabled.' + suffix)


async def scan_off(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    write_state('scanner_enabled', False)
    service = context.application.bot_data.get('scanner')
    if service: service.wake()
    await update.message.reply_text('Discovery preference disabled.')


async def scanner_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    service = context.application.bot_data.get('scanner')
    data = await asyncio.to_thread(service.status) if service else {
        'mode': 'PAPER_ONLY', 'enabled': read_state('scanner_enabled', False),
        'runtime': 'not started',
    }
    await update.message.reply_text(json.dumps(data, indent=2)[:3900])


async def rpc_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    service = context.application.bot_data.get('scanner')
    if not service:
        await update.message.reply_text('RPC scanner runtime is not started.')
        return
    data = await service.rpc_status(refresh=True)
    await update.message.reply_text(json.dumps(data, indent=2)[:3900])


async def discovery_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    service = context.application.bot_data.get('scanner')
    data = await asyncio.to_thread(
        service.discovery_status if service else discovery_diagnostics
    )
    await update.message.reply_text(json.dumps(data, indent=2)[:3900])


async def protocol_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    service = context.application.bot_data.get('scanner')
    data = (
        await asyncio.to_thread(service.protocol_status) if service else {
            'mode': 'PAPER_ONLY',
            'protocols': await asyncio.to_thread(protocol_scan_status),
        }
    )
    await update.message.reply_text(json.dumps(data, indent=2)[:3900])


async def recent(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    rows = await asyncio.to_thread(recent_tokens, 10)
    text = '\n'.join(
        f"{row['address']} | {row['analysis_state']} | risk={row['risk_score']} | "
        f"evidence={row['evidence_confidence']}% | liquidity={row['liquidity_usd']}"
        for row in rows
    ) or 'No discovered tokens yet.'
    await update.message.reply_text(text[:3900])


async def watchlist(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    rows = await asyncio.to_thread(list_watchlist, 20)
    text = '\n'.join(
        f"{row['address']} | risk={row['risk_score']} | "
        f"evidence={row['evidence_confidence']}% | liquidity={row['liquidity_usd']}"
        for row in rows
    ) or 'Watchlist is empty.'
    await update.message.reply_text(text[:3900])


async def dev(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    if len(context.args) != 1 or not Web3.is_address(context.args[0]):
        await update.message.reply_text('Usage: /dev 0xDeveloperWallet')
        return
    result = await asyncio.to_thread(developer_summary, context.args[0])
    if not result['developer'] and not result['history'] and not result['funding_links']:
        await update.message.reply_text('No developer evidence recorded for that address.')
        return
    lines = [json.dumps(result['developer'], indent=2)]
    lines.extend(
        f"{item['role']}: {item['token_address']} ({item['source']})"
        for item in result['history']
    )
    lines.extend(
        f"Funding evidence: {item['funding_address']} -> {item['funded_address']} "
        '(not ownership proof)'
        for item in result['funding_links']
    )
    await update.message.reply_text('\n'.join(lines)[:3900])


async def wallet(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    if len(context.args) != 1 or not Web3.is_address(context.args[0]):
        await update.message.reply_text('Usage: /wallet 0xPublicWalletAddress')
        return
    stored = await asyncio.to_thread(wallet_summary, context.args[0])
    errors = []
    public = await asyncio.to_thread(fetch_wallet_history, context.args[0], errors)
    result = {
        'mode': 'PAPER_ONLY', 'address': stored['address'],
        'public_history_status': public.get('status', 'UNKNOWN'),
        'transaction_count_returned': public.get('transaction_count_returned', 0),
        'created_contracts': public.get('created_contracts', []),
        'funding_relationships': public.get('funding_relationships', []),
        'recorded_relationships': stored.get('relationships', []),
        'ownership_status': 'UNKNOWN', 'provider_issues': errors,
        'note': 'Shared infrastructure and funding are not proof of common ownership.',
    }
    await update.message.reply_text(json.dumps(redact_sensitive(result), indent=2)[:3900])


async def cluster(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    if len(context.args) != 1 or not Web3.is_address(context.args[0]):
        await update.message.reply_text('Usage: /cluster 0xWalletOrTokenAddress')
        return
    result = await asyncio.to_thread(cluster_summary, context.args[0])
    await update.message.reply_text(json.dumps(result, indent=2)[:3900])


async def social(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    if len(context.args) != 1 or not Web3.is_address(context.args[0]):
        await update.message.reply_text('Usage: /social 0xTokenAddress')
        return
    result = await asyncio.to_thread(social_summary, context.args[0])
    if result['status'] == 'UNKNOWN':
        await asyncio.to_thread(inspect_contract, context.args[0])
        result = await asyncio.to_thread(social_summary, context.args[0])
    await update.message.reply_text(json.dumps(result, indent=2)[:3900])


async def decode(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    if len(context.args) != 1:
        await update.message.reply_text(
            'Usage: /decode PUBLIC_HEX_OR_BASE64. Never send keys, seed phrases, '
            'passwords, credentials, or decrypted secrets.'
        )
        return
    try:
        result = await asyncio.to_thread(decode_public_payload, context.args[0])
        await update.message.reply_text(json.dumps(result, indent=2)[:3900])
    except ValueError as exc:
        await update.message.reply_text(str(exc))


async def contract_inspect(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    if len(context.args) != 1 or not Web3.is_address(context.args[0]):
        await update.message.reply_text('Usage: /contract_inspect 0xContractAddress')
        return
    try:
        result = await asyncio.to_thread(inspect_contract, context.args[0])
        contract = result.get('contract', {})
        report = {
            'mode': 'PAPER_ONLY', 'address': result.get('address'),
            'contract_type': contract.get('contract_type', 'UNKNOWN'),
            'implementation': contract.get('implementation') or 'NOT_APPLICABLE',
            'upgrade_authority_status': contract.get(
                'upgrade_authority_status', 'NOT_APPLICABLE'),
            'upgrade_authority': contract.get('upgrade_authority'),
            'static_inspection': contract.get('static_inspection', {'status': 'UNKNOWN'}),
            'risk': result.get('risk'),
            'missing_evidence': result.get('missing_evidence'),
        }
        await update.message.reply_text(json.dumps(report, indent=2)[:3900])
    except Exception as exc:
        logging.error('Contract inspection failed error_type=%s', type(exc).__name__)
        await update.message.reply_text(f'Inspection failed: {type(exc).__name__}')


async def track(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    try:
        if len(context.args) != 1 or not Web3.is_address(context.args[0]):
            raise ValueError('Usage: /track 0xAddress')
        address = await asyncio.to_thread(track_address, context.args[0])
        service = context.application.bot_data.get('scanner')
        if service: service.wake()
        await update.message.reply_text(f'Tracking enabled for {address}. Relationships remain evidence, not identity proof.')
    except ValueError as exc:
        await update.message.reply_text(str(exc))


async def untrack(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    if len(context.args) != 1 or not Web3.is_address(context.args[0]):
        await update.message.reply_text('Usage: /untrack 0xAddress')
        return
    removed = await asyncio.to_thread(untrack_address, context.args[0])
    await update.message.reply_text('Tracking removed.' if removed else 'Address was not tracked.')


async def history(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard(update): return
    from .core import db_connect
    with db_connect() as con:
        rows = con.execute('SELECT ts,address FROM analyses ORDER BY id DESC LIMIT 5').fetchall()
    await update.message.reply_text('\n'.join(f'{ts} {addr}' for ts, addr in rows) or 'No analyses yet.')


def main():
    load_dotenv()
    token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not token or not os.getenv('TELEGRAM_ALLOWED_USER_ID'):
        raise SystemExit('Set TELEGRAM_BOT_TOKEN and TELEGRAM_ALLOWED_USER_ID in .env')
    async def post_init(application):
        async def send_alert(message):
            await application.bot.send_message(
                chat_id=int(os.getenv('TELEGRAM_ALLOWED_USER_ID')), text=message
            )
        service = ScannerService(alert_callback=send_alert)
        application.bot_data['scanner'] = service
        await service.start()

    async def post_shutdown(application):
        service = application.bot_data.get('scanner')
        if service:
            await service.stop()

    app = (ApplicationBuilder().token(token).post_init(post_init)
           .post_shutdown(post_shutdown).build())
    for command, handler in [
        ('start', start), ('status', status), ('analyze', analyze),
        ('focus', focus), ('unfocus', unfocus), ('scan_on', scan_on),
        ('scan_off', scan_off), ('scanner_status', scanner_status),
        ('rpc_status', rpc_status), ('discovery_status', discovery_status),
        ('protocol_status', protocol_status),
        ('recent', recent),
        ('watchlist', watchlist), ('dev', dev),
        ('wallet', wallet), ('cluster', cluster), ('social', social),
        ('decode', decode), ('contract_inspect', contract_inspect),
        ('track', track), ('untrack', untrack), ('history', history),
    ]:
        app.add_handler(CommandHandler(command, handler))
    app.run_polling()


if __name__ == '__main__':
    main()
