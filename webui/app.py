# -*- coding: utf-8 -*-
"""
Flask local console.

Reuses the existing backend:
    core.db                     —— SQLite persistence and queries of accounts / email pool / tasks
    core.registration_service   —— Thread-pool batch registration + task logs
    webui.config_editor         —— safely read and write config/*.py

All endpoints return JSON; the front end is the single-file templates/index.html (native JS + fetch).
Binds to 127.0.0.1 by default, accessible locally only.
"""
import logging
import gzip
import json
import threading
import time
import uuid
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, make_response, render_template, request
import pyotp

from core import account_inspection_service, codex_retry_service, db, plan_check_service, extract_link_service, codex_agent_service, live_check_service
from webui.auth import init_auth, register_auth_routes
from core import registration_service as svc
from webui import config_editor

logger = logging.getLogger(__name__)

_POOL_SOURCE_VALUES = frozenset(("all", "outlook", "generic_api", "imap", "cloudflare_domain"))


def _pool_source_arg(default: str = "outlook") -> str:
    src = str(request.args.get("source") or "").strip().lower()
    if not src and request.method == "POST":
        data = request.get_json(silent=True) or {}
        src = str(data.get("source") or data.get("type") or "").strip().lower()
    return src if src in _POOL_SOURCE_VALUES else default


def _with_pool_source(rows: list[dict], source: str) -> list[dict]:
    out = []
    for r in rows:
        x = dict(r)
        x["source"] = source
        if not x.get("copy_line"):
            x["copy_line"] = x.get("email") or ""
        out.append(x)
    return out




def _matches_query(row: dict, q: str | None) -> bool:
    q = str(q or "").strip().lower()
    if not q:
        return True
    try:
        return q in "\n".join(str(v) for v in row.values()).lower()
    except Exception:
        return False


def _paginate_items(items: list[dict], *, page: int, page_size: int) -> dict:
    page = max(1, int(page or 1))
    page_size = max(1, min(500, int(page_size or 50)))
    total = len(items)
    offset = (page - 1) * page_size
    return {
        "ok": True,
        "items": items[offset:offset + page_size],
        "total": total,
        "page": page,
        "page_size": page_size,
        "offset": offset,
        "limit": page_size,
    }


def _compact_account_for_list(row: dict) -> dict:
    """Lightweight account list object: only returns the fields the current table rendering and button logic need.

    Principles:
    - Never return the full Token / Token preview / TOTP Secret / Agent Token.
    - Timestamps, error reasons, link extraction details etc. are only returned when the front end really shows them; empty values are not returned.
    - When copying/downloading sensitive content, read it on demand through the /secret endpoint.
    """
    out = {
        "id": row.get("id"),
        "email": row.get("email"),
        "has_access_token": bool(str(row.get("access_token") or "").strip()),
        "totp_enabled": bool(row.get("totp_secret")),
        "codex_agent_has_token": bool(str(row.get("codex_agent_token") or "").strip()),
    }

    extra_raw = row.get("extra_json")
    extra = {}
    if isinstance(extra_raw, str) and extra_raw.strip():
        try:
            extra = json.loads(extra_raw)
        except Exception:
            extra = {}
    elif isinstance(extra_raw, dict):
        extra = extra_raw
    password = str(
        extra.get("registration_password")
        or row.get("registration_password")
        or ""
    ).strip()
    if password:
        out["password"] = password

    # These are the fields shown directly in the fixed list columns.
    for key in (
        "user_name", "email_source", "original_email", "note", "archived", "created_at",
        "plan_type", "current_plan_type", "plus_trial_eligible",
        "eligible_promo_campaigns", "plus_trial_discount_percentage",
        "plan_check_status", "codex_status", "codex_agent_status",
        "totp_setup_status",
    ):
        if key in row:
            out[key] = row.get(key)

    if row.get("plan_check_status") in ("queued", "running") or row.get("plan_check_ok") is False:
        out["plan_check_ok"] = row.get("plan_check_ok")

    # The fields below are only returned when they have a value, to avoid filling every row with null / empty strings / internal state.
    optional_keys = (
        # Plan display additions: paid expiry / discount / failure reason.
        "plan_check_error", "plan_expires_at", "plan_renews_at", "renews_at",
        "billing_period", "billing_currency", "discount_amount", "discount_type",
        "discount_expires_at", "discount_promo_campaign_id",
        "token_expired", "token_expires_at",
        # Liveness check state.
        "live_check_status", "live_check_error", "live_checked_at",
        "live_check_proxy_used", "live_check_fingerprint_text",
        # Only needed when link extraction succeeded/failed.
        "extract_link_status", "extract_link_type", "extract_link_message", "extract_link_error",
        "extract_link_long_url", "extract_link_copy_paste", "extract_link_image_url_png",
        "extract_link_image_url_svg", "extract_link_expires_at",
        # Codex / Agent status hints.
        "codex_error", "codex_agent_message", "codex_agent_runtime_id",
        "codex_agent_sub2api_url", "codex_agent_sub2api_mode", "codex_agent_sub2api_total",
        "totp_setup_error", "totp_setup_message", "totp_setup_started_at", "totp_setup_completed_at",
        "email_change_status", "email_change_error", "email_change_new_email",
        "email_change_started_at", "email_change_completed_at",
    )
    for key in optional_keys:
        value = row.get(key)
        if value is not None and value != "":
            out[key] = value
    plan = str(row.get("current_plan_type") or row.get("plan_type") or "").lower()
    if any(x in plan for x in ("plus", "pro", "team", "go")):
        expire = row.get("expires_at")
        if expire:
            out["expires_at"] = expire
    return out


def _account_secret_value(row: dict, field: str) -> str:
    field = (field or "").strip()
    if field == "access_token":
        return str(row.get("access_token") or "")
    if field == "copy_line":
        try:
            from core.db import _account_line

            return str(_account_line(row) or "")
        except Exception:
            return str(row.get("copy_line") or "")
    if field == "codex_agent_token":
        return str(row.get("codex_agent_token") or "")
    if field == "totp_secret":
        return str(row.get("totp_secret") or "")
    if field == "totp_code":
        secret = str(row.get("totp_secret") or "").strip()
        return pyotp.TOTP(secret).now() if secret else ""
    if field == "login_credentials":
        password = _account_secret_value(row, "password")
        if password == "Not set":
            password = ""
        return "---".join((
            str(row.get("email") or "").strip(), password, str(row.get("totp_secret") or "").strip(),
        ))
    if field == "password":
        extra_raw = row.get("extra_json")
        extra = {}
        if isinstance(extra_raw, str) and extra_raw.strip():
            try:
                extra = json.loads(extra_raw)
            except Exception:
                extra = {}
        elif isinstance(extra_raw, dict):
            extra = extra_raw
        return str(extra.get("registration_password") or row.get("registration_password") or "Not set")
    if field == "full_export":
        try:
            from core.db import _account_full_export_line

            return str(_account_full_export_line(row) or "")
        except Exception:
            return ""
    raise ValueError("field only supports access_token/copy_line/codex_agent_token/totp_secret/totp_code/password/login_credentials/full_export")


def _compact_job_for_list(row: dict) -> dict:
    """Lightweight registration task list object: only returns the fields needed for table display and button logic."""
    out = {
        "id": row.get("id"),
        "status": row.get("status"),
    }
    for key in (
        "parent_job_id", "retry_attempt", "email", "started_at", "completed_at",
        "display_status", "retryable", "retry_action", "retry_label",
        "manual_otp_required",
    ):
        value = row.get(key)
        if value is not None and value != "" and value is not False:
            out[key] = value
    err = str(row.get("error_message") or "").strip()
    if err:
        # The list only needs a summary; for full errors and stack traces see the "task log".
        out["error_message"] = err[:240] + ("…" if len(err) > 240 else "")
    traffic = row.get("network_traffic")
    if isinstance(traffic, dict) and traffic.get("available"):
        # Traffic statistics only contain byte counters, no URL/Header/request body, so they can be returned directly with the task list.
        out["network_traffic"] = traffic
    return out


def _job_status_counts(rows: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    counts["active"] = sum(int(counts.get(s, 0) or 0) for s in ("pending", "running", "stopping"))
    return counts


def _read_log_tail(path, *, max_bytes: int, default_running: bool = False, running_fn=None) -> dict:
    if not path.exists():
        return {"ok": True, "log": "", "running": bool(default_running)}
    size = path.stat().st_size
    with path.open("rb") as f:
        if size > max_bytes:
            f.seek(size - max_bytes)
        content = f.read().decode("utf-8", errors="replace")
    running = bool(default_running)
    if callable(running_fn):
        try:
            running = bool(running_fn())
        except Exception:
            pass
    return {"ok": True, "log": content, "running": running}

def create_app(auth_code: str | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates")
    _prepared_downloads: dict[str, dict] = {}

    @app.after_request
    def _compress_json_response(response: Response):
        """gzip is enabled by default for JSON API responses, reducing the transfer size when the local front end pulls large lists."""
        accept_encoding = (request.headers.get("Accept-Encoding") or "").lower()
        # gzip is on by default: browsers send gzip automatically; local scripts without Accept-Encoding are compressed as well.
        # Plain text is only returned when the client explicitly declares identity and does not accept gzip.
        gzip_allowed = ("gzip" in accept_encoding) or (not accept_encoding)
        if (
            response.direct_passthrough
            or response.headers.get("Content-Encoding")
            or not gzip_allowed
        ):
            return response
        mimetype = (response.mimetype or "").lower()
        if mimetype != "application/json":
            return response
        data = response.get_data()
        if not data or len(data) < 1024:
            return response
        compressed = gzip.compress(data, compresslevel=6)
        if len(compressed) >= len(data):
            return response
        response.set_data(compressed)
        response.headers["Content-Encoding"] = "gzip"
        response.headers["Content-Length"] = str(len(compressed))
        vary = response.headers.get("Vary")
        response.headers["Vary"] = "Accept-Encoding" if not vary else f"{vary}, Accept-Encoding"
        return response

    def _put_prepared_download(content: bytes, filename: str, mimetype: str = "application/zip") -> str:
        now = time.time()
        # Also clean up temporary downloads older than 10 minutes, to avoid memory build-up.
        for k, v in list(_prepared_downloads.items()):
            if now - float(v.get("created_at") or 0) > 600:
                _prepared_downloads.pop(k, None)
        download_id = uuid.uuid4().hex
        _prepared_downloads[download_id] = {
            "content": bytes(content),
            "filename": filename,
            "mimetype": mimetype,
            "created_at": now,
        }
        return download_id

    @app.get("/api/downloads/<download_id>")
    def api_prepared_download(download_id: str):
        item = _prepared_downloads.pop(str(download_id or ""), None)
        if not item:
            return jsonify({"ok": False, "error": "The download has expired or does not exist, please generate it again"}), 404
        content = item.get("content") or b""
        filename = item.get("filename") or "download.zip"
        mimetype = item.get("mimetype") or "application/octet-stream"
        return Response(
            content,
            mimetype=mimetype,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(content)),
                "Cache-Control": "no-store, max-age=0",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
                "X-Download-Options": "noopen",
            },
        )

    init_auth(app, auth_code=auth_code)
    register_auth_routes(app)
    with account_inspection_service.startup_recovery_guard() as can_recover:
        if can_recover:
            recovered_registration_jobs = db.recover_interrupted_registration_jobs()
            if recovered_registration_jobs:
                logger.warning("Released %s registration tasks interrupted by a WebUI restart", recovered_registration_jobs)
            recovered_plan_checks = db.recover_interrupted_plan_checks()
            if recovered_plan_checks:
                logger.warning("Restored %s plan check states interrupted by a WebUI restart", recovered_plan_checks)
            recovered_extract_links = db.recover_interrupted_extract_links()
            if recovered_extract_links:
                logger.warning("Restored %s link extraction states interrupted by a WebUI restart", recovered_extract_links)
            db.recover_interrupted_account_inspections()
            recovered_live_checks = db.recover_interrupted_live_checks()
            if recovered_live_checks:
                logger.warning("Restored %s liveness check states interrupted by a WebUI restart", recovered_live_checks)
            recovered_codex_agents = db.recover_interrupted_codex_agents()
            if recovered_codex_agents:
                logger.warning("Restored %s Codex Agent Token states interrupted by a WebUI restart", recovered_codex_agents)
            recovered_totp_setups = db.recover_interrupted_totp_setups()
            if recovered_totp_setups:
                logger.warning("Restored %s 2FA states interrupted by a WebUI restart", recovered_totp_setups)
            recovered_email_changes = db.recover_interrupted_email_changes()
            if recovered_email_changes:
                logger.warning("Restored %s email change states interrupted by a WebUI restart", recovered_email_changes)

    # ----------------------------------------------------------
    # Pages
    # ----------------------------------------------------------
    @app.get("/")
    def index():
        requested_ui = (request.args.get("ui") or "").strip().lower()
        if requested_ui in {"legacy", "modern"}:
            ui_mode = requested_ui
        else:
            ui_mode = (request.cookies.get("ui_mode") or "modern").strip().lower()
            if ui_mode not in {"legacy", "modern"}:
                ui_mode = "modern"

        template_name = "index_legacy.html" if ui_mode == "legacy" else "index.html"
        resp = make_response(render_template(template_name))
        if requested_ui in {"legacy", "modern"}:
            resp.set_cookie("ui_mode", ui_mode, max_age=60 * 60 * 24 * 365, samesite="Lax")
        return resp

    # ----------------------------------------------------------
    # Statistics overview
    # ----------------------------------------------------------
    @app.get("/api/summary")
    def api_summary():
        from config import email as _email_cfg
        from core.email_provider import parse_email_sources
        pool = {"total": 0, "available": 0, "used": 0, "failed": 0}
        for src in parse_email_sources(_email_cfg.EMAIL_SOURCE):
            # GPTMail/MailNest/CloudMail addresses are generated on demand and do not belong to the local email pool.
            if src in ("gptmail", "mailnest", "cloudmail", "remail", "xigua", "mailcode", "cloudflare"):
                continue
            one = (
                db.generic_api_email_pool_summary() if src == "generic_api"
                else db.imap_email_pool_summary() if src == "imap"
                else db.domain_email_pool_summary() if src == "cloudflare_domain"
                else db.outlook_pool_summary()
            )
            for k in pool:
                pool[k] += int(one.get(k, 0) or 0)
        domain_pool = db.domain_email_pool_summary()
        return jsonify({
            "accounts": db.count_accounts(),
            "outlook_total": pool.get("total", 0),
            "outlook_available": pool.get("available", 0),
            "outlook_used": pool.get("used", 0),
            "outlook_failed": pool.get("failed", 0),
            "domain_total": domain_pool.get("total", 0),
            "domain_available": domain_pool.get("available", 0),
            "domain_used": domain_pool.get("used", 0),
            "domain_failed": domain_pool.get("failed", 0),
        })

    # ----------------------------------------------------------
    # Registered accounts
    # ----------------------------------------------------------
    @app.get("/api/accounts")
    def api_accounts():
        limit = request.args.get("limit", default=500, type=int)
        archived = str(request.args.get("archived", default="0") or "0").lower()
        plan_filter = str(request.args.get("plan", default="") or "").lower()
        codex_filter = str(request.args.get("codex_status", default="") or "").strip().lower()
        totp_filter = str(
            request.args.get("totp_status")
            or request.args.get("totp_filter")
            or request.args.get("twofa_status")
            or ""
        ).strip().lower()
        q = str(request.args.get("q", default="") or "").strip()
        date_from = str(request.args.get("date_from", default="") or "").strip() or None
        date_to = str(request.args.get("date_to", default="") or "").strip() or None
        # New paginated API: returned when page/page_size or paged=1 is passed {items,total,page,page_size,...}
        paged = str(request.args.get("paged", default="") or "").lower() in {"1", "true", "yes"}
        page_arg = request.args.get("page", default=None, type=int)
        page_size_arg = request.args.get("page_size", default=None, type=int)
        if paged or page_arg is not None or page_size_arg is not None:
            page = max(1, int(page_arg or 1))
            page_size = max(1, min(500, int(page_size_arg or limit or 50)))
            offset = (page - 1) * page_size
            result = db.list_accounts_page(limit=page_size, offset=offset, archived=archived, plan_filter=plan_filter, codex_filter=codex_filter, q=q, date_from=date_from, date_to=date_to, totp_filter=totp_filter)
            result["items"] = [_compact_account_for_list(r) for r in (result.get("items") or [])]
            result.update({"ok": True, "page": page, "page_size": page_size, "compact": True})
            return jsonify(result)
        return jsonify(db.list_accounts(limit=limit, archived=archived, plan_filter=plan_filter, codex_filter=codex_filter, q=q, date_from=date_from, date_to=date_to, totp_filter=totp_filter))

    @app.get("/api/accounts/plan-check-status")
    def api_account_plan_check_status():
        """Lightweight plan check state; sensitive fields such as Token and email password are not returned."""
        limit = request.args.get("limit", default=5000, type=int)
        archived = str(request.args.get("archived", default="0") or "0").lower()
        plan_filter = str(request.args.get("plan", default="") or "").lower()
        codex_filter = str(request.args.get("codex_status", default="") or "").strip().lower()
        totp_filter = str(
            request.args.get("totp_status")
            or request.args.get("totp_filter")
            or request.args.get("twofa_status")
            or ""
        ).strip().lower()
        q = str(request.args.get("q", default="") or "").strip()
        date_from = str(request.args.get("date_from", default="") or "").strip() or None
        date_to = str(request.args.get("date_to", default="") or "").strip() or None
        page_arg = request.args.get("page", default=None, type=int)
        page_size_arg = request.args.get("page_size", default=None, type=int)
        if page_arg is not None or page_size_arg is not None:
            page = max(1, int(page_arg or 1))
            page_size = max(1, min(500, int(page_size_arg or limit or 50)))
            offset = (page - 1) * page_size
            snapshot = db.list_account_plan_check_statuses(limit=page_size, offset=offset, archived=archived, plan_filter=plan_filter, codex_filter=codex_filter, q=q, date_from=date_from, date_to=date_to, totp_filter=totp_filter)
            snapshot.update({"page": page, "page_size": page_size})
        else:
            snapshot = db.list_account_plan_check_statuses(limit=max(1, min(5000, limit)), archived=archived, plan_filter=plan_filter, codex_filter=codex_filter, q=q, date_from=date_from, date_to=date_to, totp_filter=totp_filter)
        snapshot["queue"] = plan_check_service.queue_settings()
        return jsonify(snapshot)


    @app.get("/api/accounts/<int:acc_id>/secret")
    def api_account_secret(acc_id: int):
        """Read the sensitive values of a single account on demand, to avoid sending full Tokens / whole rows for the account list at once."""
        field = str(request.args.get("field") or "").strip()
        acc = db.get_account(acc_id)
        if not acc:
            return jsonify({"ok": False, "error": "Account does not exist"}), 404
        try:
            value = _account_secret_value(acc, field)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, "id": acc_id, "field": field, "value": value})

    @app.post("/api/accounts/secret-bulk")
    def api_accounts_secret_bulk():
        """Read the sensitive values of accounts in batch on demand.Body {account_ids:[...], field}."""
        data = request.get_json(silent=True) or {}
        ids = data.get("account_ids") or data.get("ids") or []
        field = str(data.get("field") or "").strip()
        if not isinstance(ids, list) or not ids:
            return jsonify({"ok": False, "error": "account_ids must be a non-empty array"}), 400
        if len(ids) > 5000:
            return jsonify({"ok": False, "error": "At most 5000 accounts can be read at a time"}), 400
        values = []
        skipped = []
        seen = set()
        for raw in ids:
            try:
                acc_id = int(raw)
            except (TypeError, ValueError):
                skipped.append({"id": raw, "reason": "ID invalid"})
                continue
            if acc_id in seen:
                continue
            seen.add(acc_id)
            acc = db.get_account(acc_id)
            if not acc:
                skipped.append({"id": acc_id, "reason": "Account does not exist"})
                continue
            try:
                value = _account_secret_value(acc, field)
            except ValueError as exc:
                return jsonify({"ok": False, "error": str(exc)}), 400
            if value:
                values.append({"id": acc_id, "email": acc.get("email"), "value": value})
            else:
                skipped.append({"id": acc_id, "email": acc.get("email"), "reason": "value is empty"})
        return jsonify({"ok": True, "field": field, "values": values, "count": len(values), "skipped": skipped})

    @app.post("/api/accounts/<int:acc_id>/archive")
    def api_account_archive(acc_id: int):
        """Archive / unarchive one account. Body {archived: true|false}."""
        data = request.get_json(silent=True) or {}
        archived = bool(data.get("archived", True))
        updated = db.archive_account(acc_id=acc_id, archived=archived)
        if not updated:
            return jsonify({"ok": False, "error": "Account does not exist"}), 404
        return jsonify({"ok": True, "updated": True, "id": acc_id, "archived": archived})

    @app.post("/api/accounts/archive-bulk")
    def api_accounts_archive_bulk():
        """Batch archive / unarchive accounts. Body {account_ids:[...], archived:true|false}."""
        data = request.get_json(silent=True) or {}
        ids = data.get("account_ids") or data.get("ids") or []
        archived = bool(data.get("archived", True))
        if not isinstance(ids, list) or not ids:
            return jsonify({"ok": False, "error": "account_ids must be a non-empty array"}), 400
        if len(ids) > 5000:
            return jsonify({"ok": False, "error": "At most 5000 accounts can be archived at a time"}), 400
        account_ids = []
        skipped = []
        seen = set()
        for raw in ids:
            try:
                acc_id = int(raw)
            except (TypeError, ValueError):
                skipped.append({"id": raw, "reason": "ID invalid"})
                continue
            if acc_id in seen:
                continue
            seen.add(acc_id)
            account_ids.append(acc_id)
        updated, db_skipped = db.archive_accounts(account_ids=account_ids, archived=archived)
        skipped.extend(db_skipped)
        return jsonify({"ok": True, "updated": updated, "updated_count": len(updated), "archived": archived, "skipped": skipped})

    @app.post("/api/accounts/<int:acc_id>/delete")
    def api_account_delete(acc_id: int):
        """Delete one registered account record. Only the locally saved account/token record is deleted; the email pool state is not changed."""
        deleted = db.delete_account(acc_id=acc_id)
        if not deleted:
            return jsonify({"ok": False, "error": "Account does not exist"}), 404
        return jsonify({"ok": True, "deleted": True})

    @app.post("/api/accounts/delete-deactivated")
    def api_accounts_delete_deactivated():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or data.get("archived") not in ("0", "only", "all"):
            return jsonify({"ok": False, "error": "Please specify archived: 0, only or all"}), 400
        deleted = db.delete_deactivated_accounts(archived=data["archived"])
        return jsonify({"ok": True, "deleted_count": deleted})

    @app.post("/api/accounts/delete-bulk")
    def api_accounts_delete_bulk():
        """Batch delete registered account records. Body {account_ids: [...]} or {ids: [...]}."""
        data = request.get_json(silent=True) or {}
        ids = data.get("account_ids") or data.get("ids") or []
        if not isinstance(ids, list) or not ids:
            return jsonify({"ok": False, "error": "account_ids must be a non-empty array"}), 400
        if len(ids) > 5000:
            return jsonify({"ok": False, "error": "At most 5000 accounts can be deleted at a time"}), 400
        account_ids = []
        skipped = []
        seen = set()
        for raw in ids:
            try:
                acc_id = int(raw)
            except (TypeError, ValueError):
                skipped.append({"id": raw, "reason": "ID invalid"})
                continue
            if acc_id in seen:
                continue
            seen.add(acc_id)
            account_ids.append(acc_id)
        deleted, db_skipped = db.delete_accounts(account_ids=account_ids)
        skipped.extend(db_skipped)
        return jsonify({
            "ok": True,
            "deleted": deleted,
            "deleted_count": len(deleted),
            "skipped": skipped,
        })

    @app.post("/api/accounts/<int:acc_id>/note")
    def api_account_note(acc_id: int):
        """Update the note of a single registered account.Body {note: "..."}, an empty string means clearing it."""
        data = request.get_json(silent=True) or {}
        note = str(data.get("note") or "")
        if len(note) > 2000:
            return jsonify({"ok": False, "error": "A note can have at most 2000 characters"}), 400
        updated = db.update_account_note(acc_id=acc_id, note=note)
        if not updated:
            return jsonify({"ok": False, "error": "Account does not exist"}), 404
        return jsonify({"ok": True, "updated": True, "id": acc_id, "note": note})

    @app.post("/api/accounts/<int:acc_id>/totp-setup")
    def api_account_totp_setup(acc_id: int):
        """Enable 2FA/TOTP for a single account, and write the secret back to the account record automatically on success."""
        acc = db.get_account(acc_id)
        if not acc:
            return jsonify({"ok": False, "error": "Account does not exist"}), 404
        token = str(acc.get("access_token") or "").strip()
        if not token:
            return jsonify({"ok": False, "error": "The account has no access_token"}), 400
        if bool(acc.get("totp_secret")):
            return jsonify({"ok": False, "error": "The account has already enabled 2FA"}), 400

        try:
            from core import twofa_service
        except Exception as exc:
            return jsonify({"ok": False, "error": f"2FA Service failed to load:{type(exc).__name__}: {exc}"}), 503

        queued = twofa_service.enqueue_account_totp_setup(
            account_id=acc_id,
            email=str(acc.get("email") or ""),
            access_token=token,
            trigger="manual",
            proxy=str(acc.get("proxy_used") or "") or None,
        )
        queued_payload = {k: v for k, v in queued.items() if k != "future"}
        if queued.get("busy"):
            return jsonify({"ok": False, **queued_payload}), 409
        if not queued.get("accepted"):
            return jsonify({"ok": False, **queued_payload}), 503
        return jsonify({
            "ok": True,
            "started": True,
            "queue": twofa_service.queue_settings(),
            **queued_payload,
        }), 202

    @app.post("/api/accounts/<int:acc_id>/change-email")
    def api_account_change_email(acc_id: int):
        """Queue an email change for a single account.Body {source}."""
        data = request.get_json(silent=True) or {}
        source = str(data.get("source") or "").strip().lower()
        allowed = {"outlook", "generic_api", "imap", "cloudflare_domain", "cloudflare", "gptmail", "mailnest", "cloudmail", "remail", "xigua", "mailcode"}
        if source not in allowed:
            return jsonify({"ok": False, "error": "Please choose a valid email source"}), 400
        acc = db.get_account(acc_id)
        if not acc:
            return jsonify({"ok": False, "error": "Account does not exist"}), 404
        if not str(acc.get("access_token") or "").strip():
            return jsonify({"ok": False, "error": "The account has no access_token, please refresh it with a liveness check first AT"}), 400
        from core import email_change_service
        result = email_change_service.enqueue(acc_id, source, trigger="manual")
        public = {k: v for k, v in result.items() if k != "future"}
        return jsonify({"ok": bool(result.get("accepted")), **public}), (202 if result.get("accepted") else 409)

    @app.post("/api/accounts/change-email-bulk")
    def api_accounts_change_email_bulk():
        """Batch email change.Body {account_ids:[...], source}."""
        data = request.get_json(silent=True) or {}
        ids = data.get("account_ids") or data.get("ids") or []
        source = str(data.get("source") or "").strip().lower()
        allowed = {"outlook", "generic_api", "imap", "cloudflare_domain", "cloudflare", "gptmail", "mailnest", "cloudmail", "remail", "xigua", "mailcode"}
        if source not in allowed:
            return jsonify({"ok": False, "error": "Please choose a valid email source"}), 400
        if not isinstance(ids, list) or not ids:
            return jsonify({"ok": False, "error": "account_ids must be a non-empty array"}), 400
        if len(ids) > 500:
            return jsonify({"ok": False, "error": "At most 500 accounts can be submitted at a time"}), 400
        from core import email_change_service
        started, skipped = [], []
        seen_ids: set[int] = set()
        for raw_id in ids:
            try:
                acc_id = int(raw_id)
            except (TypeError, ValueError):
                skipped.append({"id": raw_id, "reason": "ID invalid"})
                continue
            if acc_id in seen_ids:
                continue
            seen_ids.add(acc_id)
            acc = db.get_account(acc_id)
            if not acc:
                skipped.append({"id": acc_id, "reason": "Account does not exist"})
                continue
            if not str(acc.get("access_token") or "").strip():
                skipped.append({"id": acc_id, "email": acc.get("email"), "reason": "missing access_token"})
                continue
            result = email_change_service.enqueue(acc_id, source, trigger="manual_bulk")
            if result.get("accepted"):
                started.append({"id": acc_id, "email": acc.get("email"), "status": "queued"})
            else:
                skipped.append({"id": acc_id, "email": acc.get("email"), "reason": result.get("error")})
        return jsonify({"ok": True, "started": started, "started_count": len(started), "skipped": skipped}), 202

    @app.post("/api/accounts/totp-setup-bulk")
    def api_accounts_totp_setup_bulk():
        """Add the 2FA/TOTP setup tasks of accounts to the background queue in batch. Body {account_ids:[...]}."""
        data = request.get_json(silent=True) or {}
        ids = data.get("account_ids") or data.get("ids") or []
        if not isinstance(ids, list) or not ids:
            return jsonify({"ok": False, "error": "account_ids must be a non-empty array"}), 400
        if len(ids) > 500:
            return jsonify({"ok": False, "error": "At most 500 accounts can be submitted at a time"}), 400

        account_ids = []
        skipped = []
        seen = set()
        for raw in ids:
            try:
                acc_id = int(raw)
            except (TypeError, ValueError):
                skipped.append({"id": raw, "reason": "ID invalid"})
                continue
            if acc_id in seen:
                continue
            seen.add(acc_id)
            account_ids.append(acc_id)

        accounts = []
        for acc_id in account_ids:
            acc = db.get_account(acc_id)
            if not acc:
                skipped.append({"id": acc_id, "reason": "Account does not exist"})
                continue
            email = str(acc.get("email") or "").strip()
            token = str(acc.get("access_token") or "").strip()
            if not token:
                skipped.append({"id": acc_id, "email": email, "reason": "missing access_token"})
                continue
            if str(acc.get("totp_secret") or "").strip():
                skipped.append({"id": acc_id, "email": email, "reason": "The account has already enabled 2FA"})
                continue
            if not email:
                skipped.append({"id": acc_id, "reason": "Email is empty"})
                continue
            accounts.append(acc)

        try:
            from core import twofa_service
        except Exception as exc:
            return jsonify({"ok": False, "error": f"2FA Service failed to load:{type(exc).__name__}: {exc}"}), 503

        started = []
        busy = []
        failed = []
        for acc in accounts:
            acc_id = int(acc.get("id") or 0)
            email = str(acc.get("email") or "").strip()
            try:
                queued = twofa_service.enqueue_account_totp_setup(
                    account_id=acc_id,
                    email=email,
                    access_token=str(acc.get("access_token") or "").strip(),
                    trigger="manual_bulk",
                    proxy=str(acc.get("proxy_used") or "") or None,
                )
            except Exception as exc:
                failed.append({
                    "id": acc_id,
                    "email": email,
                    "error": f"{type(exc).__name__}: {exc}",
                })
                continue

            # Future object is not JSON serializable; the batch API only returns a summary of the queue result.
            public_result = {k: v for k, v in queued.items() if k != "future"}
            item = {"id": acc_id, "email": email, **public_result}
            if queued.get("accepted"):
                item["status"] = "queued"
                started.append(item)
            elif queued.get("busy"):
                busy.append(item)
            else:
                failed.append(item)

        return jsonify({
            "ok": True,
            "message": f"Queued {len(started)} 2FA setup tasks",
            "started": started,
            "started_count": len(started),
            "busy": busy,
            "busy_count": len(busy),
            "failed": failed,
            "failed_count": len(failed),
            "skipped": skipped,
            "skipped_count": len(skipped),
            "queue": twofa_service.queue_settings(),
        }), 202

    @app.post("/api/accounts/note-bulk")
    def api_accounts_note_bulk():
        """Batch update the notes of registered accounts.Body {account_ids: [...], note: "..."}, an empty string means clearing it."""
        data = request.get_json(silent=True) or {}
        ids = data.get("account_ids") or data.get("ids") or []
        note = str(data.get("note") or "")
        if not isinstance(ids, list) or not ids:
            return jsonify({"ok": False, "error": "account_ids must be a non-empty array"}), 400
        if len(ids) > 5000:
            return jsonify({"ok": False, "error": "At most 5000 accounts can be annotated at a time"}), 400
        if len(note) > 2000:
            return jsonify({"ok": False, "error": "A note can have at most 2000 characters"}), 400

        account_ids = []
        skipped = []
        seen = set()
        for raw in ids:
            try:
                acc_id = int(raw)
            except (TypeError, ValueError):
                skipped.append({"id": raw, "reason": "ID invalid"})
                continue
            if acc_id in seen:
                continue
            seen.add(acc_id)
            account_ids.append(acc_id)
        updated, db_skipped = db.update_accounts_note(account_ids=account_ids, note=note)
        skipped.extend(db_skipped)
        return jsonify({
            "ok": True,
            "updated": updated,
            "updated_count": len(updated),
            "skipped": skipped,
            "skipped_count": len(skipped),
        })

    @app.get("/api/accounts/inspections")
    def api_account_inspections():
        try:
            page = int(request.args.get("page", 1))
            if not 1 <= page <= 1 + (2**63 - 1) // 20:
                raise ValueError("page out of range")
        except (ValueError, TypeError):
            return jsonify({"ok": False, "error": "page must be a positive integer and cannot be out of range"}), 400
        return jsonify({"ok": True, **account_inspection_service.list_inspections(limit=20, offset=(page - 1) * 20)})

    @app.get("/api/accounts/inspections/<int:inspection_id>/failures")
    def api_account_inspection_failures(inspection_id):
        try:
            page = int(request.args.get("page", 1))
            if not 1 <= page <= 1 + (2**63 - 1) // 20:
                raise ValueError("page out of range")
        except (ValueError, TypeError):
            return jsonify({"ok": False, "error": "page must be a positive integer and cannot be out of range"}), 400
        result = db.list_account_inspection_failures(inspection_id, limit=20, offset=(page - 1) * 20)
        if result is None:
            return jsonify({"ok": False, "error": "Inspection task does not exist"}), 404
        return jsonify({"ok": True, **result})

    @app.post("/api/accounts/inspections")
    def api_start_account_inspection():
        data = request.get_json(silent=True)
        if request.get_data() and not isinstance(data, dict):
            return jsonify({"ok": False, "error": "The request body must be a valid JSON object"}), 400
        try:
            run, created = account_inspection_service.start_inspection(
                workers=(data or {}).get("workers", account_inspection_service.DEFAULT_WORKERS),
                archived=(data or {}).get("archived", "0"))
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": created, "task": run,
                        "error": "" if created else "There is an unfinished inspection task, please wait for it to finish"}), 202 if created else 409

    @app.post("/api/accounts/check-live-bulk")
    def api_accounts_check_live_bulk():
        """Batch liveness check: added to the background queue; log in again in the protocol BrowserSession fingerprint environment and refresh the latest AT."""
        data = request.get_json(silent=True) or {}
        ids = data.get("account_ids") or data.get("ids") or []
        if not isinstance(ids, list) or not ids:
            return jsonify({"ok": False, "error": "account_ids must be a non-empty array"}), 400
        if len(ids) > 500:
            return jsonify({"ok": False, "error": "At most 500 accounts can be checked at a time"}), 400

        account_ids: list[int] = []
        skipped: list[dict] = []
        seen = set()
        for raw in ids:
            try:
                acc_id = int(raw)
            except (TypeError, ValueError):
                skipped.append({"id": raw, "reason": "ID invalid"})
                continue
            if acc_id in seen:
                continue
            seen.add(acc_id)
            account_ids.append(acc_id)

        accounts = []
        for acc_id in account_ids:
            acc = db.get_account(acc_id)
            if not acc:
                skipped.append({"id": acc_id, "reason": "Account does not exist"})
                continue
            email = str(acc.get("email") or "").strip()
            if not email:
                skipped.append({"id": acc_id, "reason": "Email is empty"})
                continue
            accounts.append(acc)

        started = []
        busy_count = 0
        failed = []
        for acc in accounts:
            acc_id = int(acc.get("id") or 0)
            email = str(acc.get("email") or "")
            queued = live_check_service.enqueue_account_live_check(
                account_id=acc_id,
                email=email,
                trigger="manual",
                # The liveness check uses the same network routing as "check plan":
                # PLAN_CHECK_PROXY_MODE / PLAN_CHECK_PROXY / PROXY_POOL.
                # The proxy_used from the account registration is not reused, to avoid failing forever on an old registration exit that got a CF 403.
                proxy=None,
            )
            if queued.get("accepted"):
                started.append({"id": acc_id, "email": email, "status": "queued"})
            elif queued.get("busy"):
                busy_count += 1
                skipped.append({"id": acc_id, "email": email, "reason": queued.get("error") or "Liveness check in progress"})
            else:
                failed.append({"id": acc_id, "email": email, "error": queued.get("error") or "Failed to enqueue"})

        return jsonify({
            "ok": True,
            "message": f"Queued {len(started)} liveness check tasks",
            "started": started,
            "started_count": len(started),
            "busy_count": busy_count,
            "failed": failed,
            "failed_count": len(failed),
            "skipped": skipped,
            "queue": live_check_service.queue_settings(),
        }), 202


    @app.post("/api/accounts/check-plan")
    def api_account_check_plan():
        """Add the plan check of a single account to the background queue.Body {account_id|email, proxy?, timezone_offset_min?}"""
        data = request.get_json(silent=True) or {}
        acc_id = data.get("account_id") or data.get("id")
        email = (data.get("email") or "").strip()
        acc = None
        if acc_id is not None:
            try:
                acc = db.get_account(int(acc_id))
            except Exception:
                acc = None
        if acc is None and email:
            acc = db.get_account_by_email(email)
        if not acc:
            return jsonify({"ok": False, "error": "Account does not exist"}), 404
        token = (acc.get("access_token") or "").strip()
        if not token:
            return jsonify({"ok": False, "error": "The account has no access_token"}), 400
        account_id = int(acc.get("id"))
        queued = plan_check_service.enqueue_account_plan_check(
            account_id=account_id,
            email=acc.get("email") or "",
            access_token=token,
            trigger="manual",
            proxy=data.get("proxy") if "proxy" in data else None,
            timezone_offset_min=str(data.get("timezone_offset_min") or "-"),
        )
        if queued.get("busy"):
            return jsonify({"ok": False, **queued}), 409
        if not queued.get("accepted"):
            return jsonify({"ok": False, **queued}), 503
        return jsonify({"ok": True, "started": True, **queued}), 202

    @app.post("/api/accounts/check-plan-bulk")
    def api_accounts_check_plan_bulk():
        """Add plan checks to the unified background queue in batch.Body {account_ids:[...], proxy?, timezone_offset_min?}"""
        data = request.get_json(silent=True) or {}
        ids = data.get("account_ids") or data.get("ids") or []
        if not isinstance(ids, list) or not ids:
            return jsonify({"ok": False, "error": "account_ids must be a non-empty array"}), 400
        if len(ids) > 500:
            return jsonify({"ok": False, "error": "At most 500 accounts can be queried at a time"}), 400
        # Consistent with the single-account query: the independent network policy is used when none is passed.
        proxy = data.get("proxy") if "proxy" in data else None
        timezone_offset_min = str(data.get("timezone_offset_min") or "-")

        items = []
        skipped = []
        seen = set()
        for raw in ids:
            try:
                acc_id = int(raw)
            except Exception:
                skipped.append({"id": raw, "reason": "ID invalid"})
                continue
            if acc_id in seen:
                continue
            seen.add(acc_id)
            acc = db.get_account(acc_id)
            if not acc:
                skipped.append({"id": acc_id, "reason": "Account does not exist"})
                continue
            if not (acc.get("access_token") or "").strip():
                skipped.append({"id": acc_id, "email": acc.get("email"), "reason": "missing access_token"})
                continue
            items.append(acc)

        started = []
        busy = []
        failed = []
        for acc in items:
            queued = plan_check_service.enqueue_account_plan_check(
                account_id=int(acc.get("id")),
                email=acc.get("email") or "",
                access_token=acc.get("access_token") or "",
                trigger="manual_bulk",
                proxy=proxy,
                timezone_offset_min=timezone_offset_min,
            )
            item = {"id": acc.get("id"), "email": acc.get("email"), **queued}
            if queued.get("accepted"):
                started.append(item)
            elif queued.get("busy"):
                busy.append(item)
            else:
                failed.append(item)
        return jsonify({
            "ok": True,
            "started": started,
            "started_count": len(started),
            "busy": busy,
            "busy_count": len(busy),
            "failed": failed,
            "failed_count": len(failed),
            "skipped": skipped,
            "skipped_count": len(skipped),
        }), 202

    @app.get("/api/extract-link/cdk")
    def api_extract_link_cdk():
        """Query the remaining count of the currently configured or the passed CDK."""
        code = (request.args.get("code") or "").strip() or None
        try:
            return jsonify({"ok": True, **extract_link_service.query_cdk(cdk=code)})
        except Exception as exc:
            return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400

    def _is_extract_eligible(acc: dict) -> bool:
        plan = str(acc.get("current_plan_type") or acc.get("plan_type") or "").lower()
        return plan == "free" and bool(acc.get("plus_trial_eligible"))

    @app.post("/api/accounts/extract-link")
    def api_account_extract_link():
        """Link extraction for a single account. Body {account_id|id, link_type?, cdk?}."""
        data = request.get_json(silent=True) or {}
        acc_id = data.get("account_id") or data.get("id")
        try:
            acc = db.get_account(int(acc_id))
        except Exception:
            acc = None
        if not acc:
            return jsonify({"ok": False, "error": "Account does not exist"}), 404
        if not _is_extract_eligible(acc):
            return jsonify({"ok": False, "error": "Link extraction is only supported for free (Plus trial eligible) accounts; please check the plan first to confirm eligibility"}), 400
        token = (acc.get("access_token") or "").strip()
        if not token:
            return jsonify({"ok": False, "error": "The account has no access_token"}), 400
        try:
            queued = extract_link_service.enqueue_account_extract(
                account_id=int(acc.get("id")),
                email=acc.get("email") or "",
                access_token=token,
                trigger="manual",
                link_type=data.get("link_type"),
                cdk=data.get("cdk"),
            )
        except Exception as exc:
            return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400
        if queued.get("busy"):
            return jsonify({"ok": False, **queued}), 409
        if not queued.get("accepted"):
            return jsonify({"ok": False, **queued}), 503
        return jsonify({"ok": True, "started": True, **{k: v for k, v in queued.items() if k != "future"}}), 202

    @app.post("/api/accounts/extract-link-bulk")
    def api_accounts_extract_link_bulk():
        """Batch link extraction. Body {account_ids:[...], link_type?, cdk?}."""
        data = request.get_json(silent=True) or {}
        ids = data.get("account_ids") or data.get("ids") or []
        if not isinstance(ids, list) or not ids:
            return jsonify({"ok": False, "error": "account_ids must be a non-empty array"}), 400
        if len(ids) > 500:
            return jsonify({"ok": False, "error": "At most 500 accounts can be processed for link extraction at a time"}), 400

        started = []
        busy = []
        failed = []
        skipped = []
        seen = set()
        for raw in ids:
            try:
                acc_id = int(raw)
            except Exception:
                skipped.append({"id": raw, "reason": "ID invalid"})
                continue
            if acc_id in seen:
                continue
            seen.add(acc_id)
            acc = db.get_account(acc_id)
            if not acc:
                skipped.append({"id": acc_id, "reason": "Account does not exist"})
                continue
            email = acc.get("email")
            if not _is_extract_eligible(acc):
                skipped.append({"id": acc_id, "email": email, "reason": "is not free (Plus trial eligible)"})
                continue
            token = (acc.get("access_token") or "").strip()
            if not token:
                skipped.append({"id": acc_id, "email": email, "reason": "missing access_token"})
                continue
            try:
                queued = extract_link_service.enqueue_account_extract(
                    account_id=acc_id,
                    email=email or "",
                    access_token=token,
                    trigger="manual_bulk",
                    link_type=data.get("link_type"),
                    cdk=data.get("cdk"),
                )
            except Exception as exc:
                failed.append({"id": acc_id, "email": email, "error": f"{type(exc).__name__}: {exc}"})
                continue
            item = {"id": acc_id, "email": email, **{k: v for k, v in queued.items() if k != "future"}}
            if queued.get("accepted"):
                started.append(item)
            elif queued.get("busy"):
                busy.append(item)
            else:
                failed.append(item)
        return jsonify({
            "ok": True,
            "started": started,
            "started_count": len(started),
            "busy": busy,
            "busy_count": len(busy),
            "failed": failed,
            "failed_count": len(failed),
            "skipped": skipped,
            "skipped_count": len(skipped),
        }), 202

    @app.post("/api/accounts/codex-agent")
    def api_account_codex_agent():
        """Generate a Codex Agent Token for a single account. Body {account_id|id, verify_task?}."""
        data = request.get_json(silent=True) or {}
        acc_id = data.get("account_id") or data.get("id")
        try:
            acc = db.get_account(int(acc_id))
        except Exception:
            acc = None
        if not acc:
            return jsonify({"ok": False, "error": "Account does not exist"}), 404
        token = (acc.get("access_token") or "").strip()
        if not token:
            return jsonify({"ok": False, "error": "The account has no access_token"}), 400
        try:
            queued = codex_agent_service.enqueue_account_codex_agent(
                account_id=int(acc.get("id")),
                email=acc.get("email") or "",
                access_token=token,
                trigger="manual",
                verify_task=bool(data.get("verify_task", True)),
            )
        except Exception as exc:
            return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400
        if queued.get("busy"):
            return jsonify({"ok": False, **queued}), 409
        if not queued.get("accepted"):
            return jsonify({"ok": False, **queued}), 503
        return jsonify({"ok": True, "started": True, **{k: v for k, v in queued.items() if k != "future"}}), 202

    @app.post("/api/accounts/codex-agent-bulk")
    def api_accounts_codex_agent_bulk():
        """Generate Codex Agent Tokens in batch. Body {account_ids:[...], verify_task?}."""
        data = request.get_json(silent=True) or {}
        ids = data.get("account_ids") or data.get("ids") or []
        if not isinstance(ids, list) or not ids:
            return jsonify({"ok": False, "error": "account_ids must be a non-empty array"}), 400
        if len(ids) > 500:
            return jsonify({"ok": False, "error": "At most 500 accounts can be submitted at a time"}), 400

        started = []
        busy = []
        failed = []
        skipped = []
        seen = set()
        for raw in ids:
            try:
                acc_id = int(raw)
            except Exception:
                skipped.append({"id": raw, "reason": "ID invalid"})
                continue
            if acc_id in seen:
                continue
            seen.add(acc_id)
            acc = db.get_account(acc_id)
            if not acc:
                skipped.append({"id": acc_id, "reason": "Account does not exist"})
                continue
            email = acc.get("email")
            token = (acc.get("access_token") or "").strip()
            if not token:
                skipped.append({"id": acc_id, "email": email, "reason": "missing access_token"})
                continue
            try:
                queued = codex_agent_service.enqueue_account_codex_agent(
                    account_id=acc_id,
                    email=email or "",
                    access_token=token,
                    trigger="manual_bulk",
                    verify_task=bool(data.get("verify_task", True)),
                )
            except Exception as exc:
                failed.append({"id": acc_id, "email": email, "error": f"{type(exc).__name__}: {exc}"})
                continue
            item = {"id": acc_id, "email": email, **{k: v for k, v in queued.items() if k != "future"}}
            if queued.get("accepted"):
                started.append(item)
            elif queued.get("busy"):
                busy.append(item)
            else:
                failed.append(item)
        return jsonify({
            "ok": True,
            "started": started,
            "started_count": len(started),
            "busy": busy,
            "busy_count": len(busy),
            "failed": failed,
            "failed_count": len(failed),
            "skipped": skipped,
            "skipped_count": len(skipped),
        }), 202

    def _codex_agent_auth_for_account(acc: dict) -> tuple[str, str]:
        """Return the generated Codex Agent auth.json text and download file name of an account from SQLite."""
        import json as _json

        email = str(acc.get("email") or "").strip()
        safe_email = "".join(ch if ch.isalnum() or ch in ("@", ".", "-", "_") else "_" for ch in (email or f"account-{acc.get('id')}"))
        filename = f"codex-agent-{safe_email}.json"
        token_text = str(acc.get("codex_agent_token") or "").strip()
        if token_text:
            try:
                payload = _json.loads(token_text)
                token_text = _json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
            except Exception:
                token_text = token_text + ("\n" if not token_text.endswith("\n") else "")
            return token_text, filename

        stored = db.get_codex_agent_credential(int(acc.get("id") or 0))
        if stored:
            return stored

        raise RuntimeError("The account has not generated a Codex Agent Token")

    def _join_sub2_url(base: str, path: str) -> str:
        base = str(base or "").strip().rstrip("/")
        path = str(path or "").strip()
        if not base or not path:
            return ""
        parsed = urlparse(path)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return path
        return f"{base}/{path.lstrip('/')}"

    def _sub2_codex_session_import_url() -> str:
        from config import sub2api as sub2api_cfg
        api_base = str(getattr(sub2api_cfg, "SUB2API_API_BASE", "") or "").strip()
        if api_base:
            return _join_sub2_url(api_base, "/api/v1/admin/accounts/import/codex-session")
        # Compatible with the old setting: SUB2API_API_URL used to be the full upload endpoint URL.
        return str(getattr(sub2api_cfg, "SUB2API_API_URL", "") or "").strip()

    def _upload_account_codex_agent_to_sub2(acc: dict) -> dict:
        """Upload the generated Codex Agent auth.json of an account to sub2api."""
        import json as _json
        from config import sub2api as sub2api_cfg
        from core.codex_agent import upload_sub2api_account

        text, _filename = _codex_agent_auth_for_account(acc)
        try:
            auth_json = _json.loads(text)
        except Exception as exc:
            raise RuntimeError(f"Agent Token JSON invalid: {exc}") from exc

        api_url = _sub2_codex_session_import_url()
        api_token = str(getattr(sub2api_cfg, "SUB2API_API_KEY", "") or getattr(sub2api_cfg, "SUB2API_API_TOKEN", "") or "").strip()
        auth_header = str(getattr(sub2api_cfg, "SUB2API_API_AUTH_HEADER", "x-api-key") or "x-api-key").strip()
        auth_prefix = str(getattr(sub2api_cfg, "SUB2API_API_AUTH_PREFIX", "") or "").strip()
        payload_mode = "codex_session_import"
        proxy_key = str(getattr(sub2api_cfg, "SUB2API_PROXY_KEY", "") or "").strip() or None
        timeout = float(getattr(sub2api_cfg, "SUB2API_API_TIMEOUT", 20) or 20)

        result = upload_sub2api_account(
            auth_json,
            api_url,
            api_token=api_token,
            auth_header=auth_header,
            auth_prefix=auth_prefix,
            payload_mode=payload_mode,
            proxy_key=proxy_key,
            timeout=timeout,
        )
        try:
            db.update_account_codex_agent(int(acc.get("id")), {
                "ok": True,
                "status": "success",
                "message": "Agent Token uploaded to sub2api",
                "sub2api_url": result.get("url"),
                "sub2api_mode": result.get("payload_mode"),
                "sub2api_total": result.get("total"),
            })
        except Exception:
            logger.exception("Failed to update the sub2api upload state of the account: account_id=%s", acc.get("id"))
        return result

    @app.post("/api/accounts/<int:acc_id>/codex-agent/upload-sub2")
    def api_account_codex_agent_upload_sub2(acc_id: int):
        """Upload the generated Codex Agent Token of a single account to sub2api."""
        acc = db.get_account(acc_id)
        if not acc:
            return jsonify({"ok": False, "error": "Account does not exist"}), 404
        try:
            result = _upload_account_codex_agent_to_sub2(acc)
        except Exception as exc:
            return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400
        return jsonify({"ok": True, "account_id": acc_id, "email": acc.get("email"), "result": result})

    @app.post("/api/accounts/codex-agent/upload-sub2-bulk")
    def api_accounts_codex_agent_upload_sub2_bulk():
        """Upload the generated Codex Agent Tokens to sub2api in batch. Body {account_ids:[...]}."""
        data = request.get_json(silent=True) or {}
        ids = data.get("account_ids") or data.get("ids") or []
        if not isinstance(ids, list) or not ids:
            return jsonify({"ok": False, "error": "account_ids must be a non-empty array"}), 400
        if len(ids) > 500:
            return jsonify({"ok": False, "error": "At most 500 accounts can be submitted at a time"}), 400

        uploaded, failed, skipped = [], [], []
        seen = set()
        for raw in ids:
            try:
                acc_id = int(raw)
            except Exception:
                skipped.append({"id": raw, "reason": "ID invalid"})
                continue
            if acc_id in seen:
                continue
            seen.add(acc_id)
            acc = db.get_account(acc_id)
            if not acc:
                skipped.append({"id": acc_id, "reason": "Account does not exist"})
                continue
            email = acc.get("email")
            if (acc.get("codex_agent_status") or "") != "success" and not (acc.get("codex_agent_token") or acc.get("codex_agent_auth_path")):
                skipped.append({"id": acc_id, "email": email, "reason": "not generated Agent Token"})
                continue
            try:
                result = _upload_account_codex_agent_to_sub2(acc)
                uploaded.append({"id": acc_id, "email": email, "url": result.get("url"), "status_code": result.get("status_code")})
            except Exception as exc:
                failed.append({"id": acc_id, "email": email, "error": f"{type(exc).__name__}: {exc}"})
        return jsonify({
            "ok": True,
            "uploaded": uploaded,
            "uploaded_count": len(uploaded),
            "failed": failed,
            "failed_count": len(failed),
            "skipped": skipped,
            "skipped_count": len(skipped),
        })

    @app.get("/api/accounts/<int:acc_id>/codex-agent/download")
    def api_account_codex_agent_download(acc_id: int):
        """Download the Codex Agent auth.json of a single account."""
        acc = db.get_account(acc_id)
        if not acc:
            return jsonify({"ok": False, "error": "Account does not exist"}), 404
        try:
            content, filename = _codex_agent_auth_for_account(acc)
        except Exception as exc:
            return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 404
        data = content.encode("utf-8")
        return Response(
            data,
            mimetype="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(data)),
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.post("/api/accounts/codex-agent/download-bulk")
    def api_accounts_codex_agent_download_bulk():
        """Download the generated Codex Agent Tokens of the selected accounts, packed as a ZIP."""
        import io
        import json as _json
        import zipfile
        from datetime import datetime as _dt

        data = request.get_json(silent=True) or {}
        if not data and request.form:
            ids_text = (request.form.get("account_ids") or request.form.get("ids") or "").strip()
            try:
                ids = _json.loads(ids_text) if ids_text else []
            except Exception:
                ids = [x.strip() for x in ids_text.split(",") if x.strip()]
        else:
            ids = data.get("account_ids") or data.get("ids") or []
        if not isinstance(ids, list) or not ids:
            return jsonify({"ok": False, "error": "account_ids must be a non-empty array"}), 400
        if len(ids) > 1000:
            return jsonify({"ok": False, "error": "At most 1000 accounts can be downloaded at a time"}), 400

        added = []
        errors = []
        used_names = set()
        seen = set()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for raw in ids:
                try:
                    acc_id = int(raw)
                except Exception:
                    errors.append({"id": raw, "error": "ID invalid"})
                    continue
                if acc_id in seen:
                    continue
                seen.add(acc_id)
                acc = db.get_account(acc_id)
                if not acc:
                    errors.append({"id": acc_id, "error": "Account does not exist"})
                    continue
                try:
                    content, filename = _codex_agent_auth_for_account(acc)
                    arcname = filename
                    if arcname in used_names:
                        stem, dot, ext = arcname.rpartition(".")
                        arcname = f"{stem or arcname}-{len(used_names)+1}{dot}{ext}" if dot else f"{arcname}-{len(used_names)+1}"
                    used_names.add(arcname)
                    zf.writestr(arcname, content)
                    added.append({"id": acc_id, "email": acc.get("email"), "filename": arcname})
                except Exception as exc:
                    errors.append({"id": acc_id, "email": acc.get("email"), "error": f"{type(exc).__name__}: {exc}"})
            manifest = {
                "exported_at": _dt.now().isoformat(timespec="seconds"),
                "source": "accounts-codex-agent",
                "count": len(added),
                "files": added,
                "errors": errors,
            }
            zf.writestr("manifest.json", _json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")

        if not added:
            return jsonify({"ok": False, "error": "No downloadable Codex Agent Token", "errors": errors}), 404
        now = _dt.now()
        dl_name = f"accounts-codex-agent-{now.strftime('%Y%m%d-%H%M%S')}.zip"
        buf.seek(0)
        zip_bytes = buf.getvalue()
        return Response(
            zip_bytes,
            mimetype="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{dl_name}"',
                "Content-Length": str(len(zip_bytes)),
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.post("/api/accounts/download-cpa-bulk")
    def api_accounts_download_cpa_bulk():
        """
        Download the Codex CPA JSON of the accounts selected in the account list directly from the CPA auth-files and pack it into a ZIP.
        Body: {"account_ids": [1,2,...]} or {"ids": [...]}
        """
        import io
        import json as _json
        import zipfile
        from datetime import datetime as _dt
        from core.codex_oauth import download_cpa_codex_auth_text, list_cpa_codex_auth_files

        data = request.get_json(silent=True) or {}
        if not data and request.form:
            ids_text = (request.form.get("account_ids") or request.form.get("ids") or "").strip()
            try:
                ids = _json.loads(ids_text) if ids_text else []
            except Exception:
                ids = [x.strip() for x in ids_text.split(",") if x.strip()]
        else:
            ids = data.get("account_ids") or data.get("ids") or []
        if not isinstance(ids, list) or not ids:
            return jsonify({"ok": False, "error": "account_ids must be a non-empty array"}), 400
        if len(ids) > 1000:
            return jsonify({"ok": False, "error": "At most 1000 accounts can be downloaded at a time"}), 400

        try:
            cpa_files = list_cpa_codex_auth_files()
        except Exception as exc:
            return jsonify({"ok": False, "error": f"Failed to read the CPA auth-files: {type(exc).__name__}: {exc}"}), 502

        def _match_cpa_file(email: str, local_filename: str = "") -> dict | None:
            """Match within the already cached CPA file list, to avoid requesting the auth-files again for every account."""
            email_l = str(email or "").strip().lower()
            local_name_l = str(local_filename or "").strip().lower()
            local_stem_l = local_name_l[:-5] if local_name_l.endswith(".json") else local_name_l

            def score(item: dict) -> int:
                name_l = str(item.get("name") or "").lower()
                item_email_l = str(item.get("email") or "").lower()
                s = 0
                if local_name_l and name_l == local_name_l:
                    s = max(s, 100)
                if local_stem_l and name_l.startswith(local_stem_l):
                    s = max(s, 80)
                if email_l and item_email_l == email_l:
                    s = max(s, 70)
                if email_l and email_l in name_l:
                    s = max(s, 60)
                if local_stem_l.endswith("-cpa-callback"):
                    base = local_stem_l[:-len("-cpa-callback")]
                    if base and name_l.startswith(base + "-"):
                        s = max(s, 75)
                return s

            ranked = sorted(((score(item), item) for item in cpa_files), key=lambda x: x[0], reverse=True)
            return ranked[0][1] if ranked and ranked[0][0] > 0 else None

        # Build an email -> local codex file name index; passing the local file name to the CPA matching logic improves the hit rate.
        local_by_email: dict[str, str] = {}
        try:
            for item in db.list_codex_accounts():
                email_key = str(item.get("email") or "").strip().lower()
                fname = str(item.get("filename") or "").strip()
                if email_key and fname and email_key not in local_by_email:
                    local_by_email[email_key] = fname
        except Exception:
            local_by_email = {}

        errors = []
        added = []
        used_names = set()
        seen_ids = set()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for raw_id in ids:
                try:
                    acc_id = int(raw_id)
                except (TypeError, ValueError):
                    errors.append({"id": raw_id, "error": "ID invalid"})
                    continue
                if acc_id in seen_ids:
                    continue
                seen_ids.add(acc_id)

                acc = db.get_account(acc_id)
                if not acc:
                    errors.append({"id": acc_id, "error": "Account does not exist"})
                    continue
                email = str(acc.get("email") or "").strip()
                if not email:
                    errors.append({"id": acc_id, "error": "The account has no email"})
                    continue

                local_filename = local_by_email.get(email.lower(), "")
                try:
                    meta = _match_cpa_file(email=email, local_filename=local_filename)
                    cpa_name_hint = str((meta or {}).get("name") or "").strip()
                    if not cpa_name_hint:
                        raise RuntimeError(f"[Codex][CPA] No matching Codex credential found in the CPA auth-files: {email}")
                    cpa_text, cpa_name, meta = download_cpa_codex_auth_text(
                        cpa_name=cpa_name_hint,
                    )
                    arcname = cpa_name
                    if arcname in used_names:
                        stem, dot, ext = arcname.rpartition(".")
                        arcname = f"{stem or arcname}-{len(used_names)+1}{dot}{ext}" if dot else f"{arcname}-{len(used_names)+1}"
                    used_names.add(arcname)
                    zf.writestr(arcname, cpa_text)
                    added.append({
                        "id": acc_id,
                        "email": email,
                        "local_filename": local_filename,
                        "cpa_filename": cpa_name,
                        "cpa_meta": meta,
                    })
                    if local_filename:
                        try:
                            db.mark_codex_exported(local_filename)
                        except Exception:
                            pass
                except Exception as exc:
                    errors.append({"id": acc_id, "email": email, "error": f"{type(exc).__name__}: {exc}"})

            manifest = {
                "exported_at": _dt.now().isoformat(timespec="seconds"),
                "source": "accounts-cpa",
                "count": len(added),
                "files": added,
                "errors": errors,
            }
            zf.writestr("manifest.json", _json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")

        if not added:
            return jsonify({"ok": False, "error": "No credential was downloaded successfully from CPA", "errors": errors}), 502
        now = _dt.now()
        dl_name = f"accounts-cpa-bulk-{now.strftime('%Y%m%d-%H%M%S')}.zip"
        buf.seek(0)
        zip_bytes = buf.getvalue()
        if isinstance(data, dict) and data.get("prepare"):
            download_id = _put_prepared_download(zip_bytes, dl_name, "application/zip")
            return jsonify({
                "ok": True,
                "prepared": True,
                "download_id": download_id,
                "download_url": f"/api/downloads/{download_id}",
                "filename": dl_name,
                "added_count": len(added),
                "error_count": len(errors),
            })
        return Response(
            zip_bytes,
            mimetype="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{dl_name}"',
                "Content-Length": str(len(zip_bytes)),
                "Cache-Control": "no-store, max-age=0",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
                "X-Download-Options": "noopen",
            },
        )

    # ----------------------------------------------------------
    # Email pool
    # ----------------------------------------------------------
    @app.get("/api/outlook")
    def api_outlook():
        status = request.args.get("status") or None
        limit = request.args.get("limit", default=500, type=int)
        source = _pool_source_arg()
        q = str(request.args.get("q", default="") or "").strip()
        paged = str(request.args.get("paged", default="") or "").lower() in {"1", "true", "yes"}
        page_arg = request.args.get("page", default=None, type=int)
        page_size_arg = request.args.get("page_size", default=None, type=int)
        if paged or page_arg is not None or page_size_arg is not None:
            page = max(1, int(page_arg or 1))
            page_size = max(1, min(500, int(page_size_arg or limit or 50)))
            offset = (page - 1) * page_size
            result = db.list_email_pool_page(
                source=source, status=status, q=q, limit=page_size, offset=offset
            )
            result.update({"ok": True, "page": page, "page_size": page_size})
            return jsonify(result)
        # The legacy API still returns an array, but the query itself also reads only limit rows from SQLite.
        result = db.list_email_pool_page(
            source=source, status=status, q=q, limit=max(1, int(limit or 1)), offset=0
        )
        return jsonify(result["items"])

    @app.post("/api/outlook/import")
    def api_outlook_import():
        """
        Import email material from pasted text.
        Outlook:email----password----clientId----refreshToken
        Generic API:email----code_url
        Generic IMAP: email----password or email:password; server/port/SSL are passed separately
        Separators are compatible with ---- and ====.
        """
        data = request.get_json(silent=True) or {}
        source = (data.get("source") or data.get("type") or "").strip()
        if source not in ("outlook", "generic_api", "imap"):
            return jsonify({"ok": False, "error": "Please choose a specific type when importing: Outlook, generic API or generic IMAP"}), 400
        text = data.get("text") or ""
        as_registered = bool(data.get("as_registered", False))
        imap_server = str(data.get("imap_server") or "").strip()
        try:
            imap_port = int(data.get("imap_port") or 993)
        except (TypeError, ValueError):
            imap_port = 0
        imap_ssl_raw = data.get("imap_ssl", True)
        imap_ssl = imap_ssl_raw if isinstance(imap_ssl_raw, bool) else str(imap_ssl_raw).strip().lower() not in {"0", "false", "no", "off"}
        if source == "imap" and (not imap_server or not (1 <= imap_port <= 65535)):
            return jsonify({"ok": False, "error": "A generic IMAP import must provide a valid server and port"}), 400
        records = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if source == "imap":
                if "----" in line:
                    parts = line.split("----", 1)
                elif "====" in line:
                    parts = line.split("====", 1)
                elif ":" in line:
                    parts = line.split(":", 1)
                else:
                    continue
            else:
                parts = line.split("----") if "----" in line else line.split("====")
            parts = [p.strip() for p in parts]
            if source == "generic_api":
                if len(parts) < 2:
                    continue
                records.append({
                    "email": parts[0],
                    "code_url": parts[1],
                    "access_token": parts[2] if len(parts) > 2 else "",
                    "totp_secret": parts[3] if len(parts) > 3 else "",
                })
                continue
            if source == "imap":
                if len(parts) < 2 or not parts[0] or not parts[1]:
                    continue
                records.append({
                    "email": parts[0], "imap_password": parts[1],
                    "imap_server": imap_server, "imap_port": imap_port,
                    "imap_ssl": imap_ssl, "imap_username": "",
                })
                continue
            if len(parts) < 4:
                continue
            records.append({
                "email": parts[0],
                "password": parts[1],
                "client_id": parts[2],
                "refresh_token": parts[3],
                "access_token": parts[4] if len(parts) > 4 else "",
                "totp_secret": parts[5] if len(parts) > 5 else "",
            })
        if not records:
            need = ("2 segments: email----code retrieval URL" if source == "generic_api" else
                    "email----IMAP password or email:IMAP password" if source == "imap" else
                    "4 segments:email----password----clientId----refreshToken")
            return jsonify({"ok": False, "error": f"No valid email line parsed (needs {need}, separated by ---- or ====)"}), 400
        if as_registered:
            inserted, skipped = db.import_registered_email_accounts(records, source=source)
        elif source == "generic_api":
            inserted, skipped = db.import_generic_api_emails(records)
        elif source == "imap":
            inserted, skipped = db.import_imap_emails(records)
        else:
            inserted, skipped = db.import_outlook_accounts(records)
        return jsonify({
            "ok": True,
            "inserted": inserted,
            "skipped": skipped,
            "parsed": len(records),
            "as_registered": as_registered,
        })

    @app.post("/api/outlook/status")
    def api_outlook_status():
        """Manually change the email status: body {email, status, note?, source?}. status is one of available/used/failed/disabled."""
        data = request.get_json(silent=True) or {}
        email = (data.get("email") or "").strip()
        status = (data.get("status") or "").strip()
        if not email or status not in ("available", "used", "failed", "disabled"):
            return jsonify({"ok": False, "error": "email or status is invalid"}), 400
        source = (data.get("source") or _pool_source_arg()).strip()
        if source == "all":
            source = "outlook"
        if source == "generic_api":
            db.release_generic_api_email(email, status=status, note=data.get("note"))
        elif source == "imap":
            db.release_imap_email(email, status=status, note=data.get("note"))
        elif source == "cloudflare_domain":
            db.release_domain_email(email, status=status, note=data.get("note"))
        else:
            db.release_outlook(email, status=status, note=data.get("note"))
        return jsonify({"ok": True})

    @app.post("/api/outlook/status-bulk")
    def api_outlook_status_bulk():
        """Change email statuses in batch. Body {items:[{email,source}], status, note?}."""
        data = request.get_json(silent=True) or {}
        items = data.get("items") or data.get("emails") or []
        status = (data.get("status") or "").strip()
        note = data.get("note")
        default_source = (data.get("source") or _pool_source_arg()).strip()
        if status not in ("available", "used", "failed", "disabled"):
            return jsonify({"ok": False, "error": "status invalid"}), 400
        if not isinstance(items, list) or not items:
            return jsonify({"ok": False, "error": "items/emails must be a non-empty array"}), 400
        if len(items) > 5000:
            return jsonify({"ok": False, "error": "At most 5000 emails can be operated on at a time"}), 400

        updated = []
        skipped = []
        seen = set()
        for raw_item in items:
            if isinstance(raw_item, dict):
                email = (str(raw_item.get("email") or "")).strip()
                item_source = (raw_item.get("source") or default_source or "outlook").strip()
            else:
                email = (str(raw_item or "")).strip()
                item_source = default_source
            if item_source == "all":
                item_source = "outlook"
            key = f"{item_source}:{email.lower()}"
            if not email:
                skipped.append({"email": raw_item, "reason": "Email is empty"})
                continue
            if key in seen:
                continue
            seen.add(key)
            try:
                if item_source == "generic_api":
                    db.release_generic_api_email(email, status=status, note=note)
                elif item_source == "imap":
                    db.release_imap_email(email, status=status, note=note)
                elif item_source == "cloudflare_domain":
                    db.release_domain_email(email, status=status, note=note)
                else:
                    db.release_outlook(email, status=status, note=note)
                updated.append({"email": email, "source": item_source, "status": status})
            except Exception as exc:
                skipped.append({"email": email, "source": item_source, "reason": f"{type(exc).__name__}: {exc}"})
        return jsonify({
            "ok": True,
            "updated": updated,
            "updated_count": len(updated),
            "skipped": skipped,
        })

    @app.post("/api/outlook/delete")
    def api_outlook_delete():
        """Remove an email from the email pool completely: body {email, source?}."""
        data = request.get_json(silent=True) or {}
        email = str(data.get("email") or "").strip()
        if not email:
            return jsonify({"ok": False, "error": "email is empty"}), 400
        raw_source = data.get("source") or data.get("type")
        source = (
            _pool_source_arg()
            if not str(raw_source or "").strip()
            else str(raw_source).strip().lower()
        )
        if source not in _POOL_SOURCE_VALUES:
            return jsonify({"ok": False, "error": "Invalid email source"}), 400
        deleted = db.delete_email_pool(email, source=source)
        return jsonify({"ok": True, "deleted": deleted})

    @app.post("/api/outlook/delete-bulk")
    def api_outlook_delete_bulk():
        """Remove emails from the email pool completely in batch: body {items/emails: [...], source?}."""
        data = request.get_json(silent=True) or {}
        raw_source = data.get("source") or data.get("type")
        source = (
            _pool_source_arg()
            if not str(raw_source or "").strip()
            else str(raw_source).strip().lower()
        )
        if source not in _POOL_SOURCE_VALUES:
            return jsonify({"ok": False, "error": "Invalid email source"}), 400
        emails = data.get("items") or data.get("emails") or []
        if not isinstance(emails, list) or not emails:
            return jsonify({"ok": False, "error": "emails/items must be a non-empty array"}), 400
        if len(emails) > 5000:
            return jsonify({"ok": False, "error": "At most 5000 emails can be deleted at a time"}), 400

        deleted: list[dict] = []
        skipped: list[dict] = []
        seen: set[str] = set()
        for raw_item in emails:
            if isinstance(raw_item, dict):
                email = str(raw_item.get("email") or "").strip()
                raw_item_source = raw_item.get("source") or raw_item.get("type")
                item_source = (
                    source
                    if not str(raw_item_source or "").strip()
                    else str(raw_item_source).strip().lower()
                )
            else:
                email = (str(raw_item or "")).strip()
                item_source = source
            if not email:
                skipped.append({"email": raw_item, "reason": "Email is empty"})
                continue
            if item_source not in _POOL_SOURCE_VALUES:
                skipped.append({"email": email, "source": item_source, "reason": "Invalid email source"})
                continue
            key = f"{item_source}:{email.casefold()}"
            if key in seen:
                continue
            seen.add(key)
            try:
                deleted_ok = db.delete_email_pool(email, source=item_source)
            except Exception as exc:
                skipped.append({
                    "email": email,
                    "source": item_source,
                    "reason": f"{type(exc).__name__}: {exc}",
                })
                continue
            if deleted_ok:
                deleted.append({"email": email, "source": item_source})
            else:
                skipped.append({"email": email, "reason": "Email does not exist"})

        return jsonify({
            "ok": True,
            "deleted": deleted,
            "deleted_count": len(deleted),
            "skipped": skipped,
        })

    # ----------------------------------------------------------
    # Domain email pool (Cloudflare domain email mode)
    # ----------------------------------------------------------
    @app.get("/api/domain-pool")
    def api_domain_pool():
        status = request.args.get("status") or None
        limit = request.args.get("limit", default=500, type=int)
        return jsonify(db.list_domain_email_pool(status=status, limit=limit))

    @app.post("/api/domain-pool/status")
    def api_domain_pool_status():
        data = request.get_json(silent=True) or {}
        email = (data.get("email") or "").strip()
        status = (data.get("status") or "").strip()
        if not email or status not in ("available", "used", "failed"):
            return jsonify({"ok": False, "error": "email or status is invalid"}), 400
        db.release_domain_email(email, status=status, note=data.get("note"))
        return jsonify({"ok": True})

    @app.post("/api/domain-pool/delete")
    def api_domain_pool_delete():
        data = request.get_json(silent=True) or {}
        email = (data.get("email") or "").strip()
        if not email:
            return jsonify({"ok": False, "error": "email is empty"}), 400
        deleted = db.delete_domain_email(email)
        return jsonify({"ok": True, "deleted": deleted})

    # ----------------------------------------------------------
    # Codex authorized accounts (CPA compatible credentials)
    # ----------------------------------------------------------
    @app.get("/api/codex")
    def api_codex_list():
        q = str(request.args.get("q", default="") or "").strip()
        archived = str(request.args.get("archived", default="0") or "0").lower()
        date_from = str(request.args.get("date_from", default="") or "").strip() or None
        date_to = str(request.args.get("date_to", default="") or "").strip() or None
        limit = request.args.get("limit", default=500, type=int)
        paged = str(request.args.get("paged", default="") or "").lower() in {"1", "true", "yes"}
        page_arg = request.args.get("page", default=None, type=int)
        page_size_arg = request.args.get("page_size", default=None, type=int)
        if paged or page_arg is not None or page_size_arg is not None:
            page = max(1, int(page_arg or 1))
            page_size = max(1, min(500, int(page_size_arg or limit or 50)))
            result = db.list_codex_accounts_page(
                archived=archived,
                date_from=date_from,
                date_to=date_to,
                q=q,
                limit=page_size,
                offset=(page - 1) * page_size,
            )
            result.update({"ok": True, "page": page, "page_size": page_size})
            result["accounts"] = result.pop("items")
            result["summary"] = db.codex_accounts_summary()
            return jsonify(result)
        result = db.list_codex_accounts_page(
            archived=archived,
            date_from=date_from,
            date_to=date_to,
            q=q,
            limit=max(1, int(limit or 1)),
            offset=0,
        )
        return jsonify({
            "summary": db.codex_accounts_summary(),
            "accounts": result["items"],
        })

    @app.post("/api/codex/archive")
    def api_codex_archive():
        """Archive / unarchive one Codex authorization credential. Body {filename, archived}."""
        data = request.get_json(silent=True) or {}
        filename = str(data.get("filename") or "").strip()
        archived = bool(data.get("archived", True))
        if not filename:
            return jsonify({"ok": False, "error": "filename required"}), 400
        try:
            rec = db.archive_codex(filename=filename, archived=archived)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        if rec is None:
            return jsonify({"ok": False, "error": f"Credential does not exist: {filename}"}), 404
        return jsonify({"ok": True, "filename": filename, "archived": archived, "record": rec})

    @app.post("/api/codex/archive-bulk")
    def api_codex_archive_bulk():
        """Batch archive / unarchive Codex authorization credentials. Body {filenames:[...], archived}."""
        data = request.get_json(silent=True) or {}
        filenames = data.get("filenames") or []
        archived = bool(data.get("archived", True))
        if not isinstance(filenames, list) or not filenames:
            return jsonify({"ok": False, "error": "filenames must be a non-empty array"}), 400
        if len(filenames) > 1000:
            return jsonify({"ok": False, "error": "At most 1000 at a time"}), 400
        updated = []
        skipped = []
        seen = set()
        for fname in filenames:
            if not isinstance(fname, str) or not fname:
                skipped.append({"filename": str(fname), "reason": "Invalid file name"})
                continue
            if fname in seen:
                continue
            seen.add(fname)
            try:
                rec = db.archive_codex(filename=fname, archived=archived)
            except ValueError as exc:
                skipped.append({"filename": fname, "reason": str(exc)})
                continue
            if rec is None:
                skipped.append({"filename": fname, "reason": "Credential does not exist"})
            else:
                updated.append({"filename": fname, "archived": archived})
        return jsonify({"ok": True, "updated": updated, "updated_count": len(updated), "archived": archived, "skipped": skipped})

    @app.get("/api/codex/download/<path:filename>")
    def api_codex_download(filename: str):
        """
        Download a CPA compatible codex-*.json file; downloading marks it as exported (count +1).
        The front end triggers it through the native browser download (a tag / window.location).
        """
        try:
            content, fname = db.read_codex_credential(filename)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 404
        db.mark_codex_exported(fname)
        return Response(
            content,
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    @app.get("/api/codex/download-from-cpa/<path:filename>")
    def api_codex_download_from_cpa(filename: str):
        """Match the CPA auth-files by the local codex file / receipt, and download the actual Codex JSON from CPA."""
        try:
            content, fname = db.read_codex_credential(filename)
            import json as _json
            try:
                local = _json.loads(content)
            except Exception:
                local = {}
            email = str(local.get("email") or "").strip()
            from core.codex_oauth import download_cpa_codex_auth_text
            cpa_text, cpa_name, _meta = download_cpa_codex_auth_text(email=email, local_filename=fname)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 404
        except Exception as exc:
            return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 502
        db.mark_codex_exported(fname)
        return Response(
            cpa_text,
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="{cpa_name}"'},
        )

    @app.post("/api/codex/download-bulk-from-cpa")
    def api_codex_download_bulk_from_cpa():
        """
        Download the selected Codex credentials from CPA in batch and pack them as a zip; every file in the zip is the raw CPA JSON.
        Body: {"filenames": ["codex-xxx-cpa-callback.json", ...]}
        """
        import io
        import json as _json
        import zipfile
        from datetime import datetime as _dt
        from core.codex_oauth import download_cpa_codex_auth_text

        data = request.get_json(silent=True) or {}
        filenames = data.get("filenames") or []
        if not isinstance(filenames, list) or not filenames:
            return jsonify({"ok": False, "error": "filenames must be a non-empty array"}), 400
        if len(filenames) > 1000:
            return jsonify({"ok": False, "error": "At most 1000 at a time"}), 400

        errors = []
        added = []
        used_names = set()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for fname in filenames:
                if not isinstance(fname, str):
                    errors.append({"filename": str(fname), "error": "not a string"})
                    continue
                try:
                    content, real_fname = db.read_codex_credential(fname)
                    try:
                        local = _json.loads(content)
                    except Exception:
                        local = {}
                    email = str(local.get("email") or "").strip()
                    cpa_text, cpa_name, _meta = download_cpa_codex_auth_text(email=email, local_filename=real_fname)
                    arcname = cpa_name
                    if arcname in used_names:
                        stem, dot, ext = arcname.rpartition(".")
                        arcname = f"{stem or arcname}-{len(used_names)+1}{dot}{ext}" if dot else f"{arcname}-{len(used_names)+1}"
                    used_names.add(arcname)
                    zf.writestr(arcname, cpa_text)
                    added.append({"local_filename": real_fname, "cpa_filename": cpa_name})
                    db.mark_codex_exported(real_fname)
                except Exception as exc:
                    errors.append({"filename": fname, "error": f"{type(exc).__name__}: {exc}"})
            manifest = {
                "exported_at": _dt.now().isoformat(timespec="seconds"),
                "source": "cpa",
                "count": len(added),
                "files": added,
                "errors": errors,
            }
            zf.writestr("manifest.json", _json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")

        if not added:
            return jsonify({"ok": False, "error": "No credential was downloaded successfully from CPA", "errors": errors}), 502
        now = _dt.now()
        dl_name = f"codex-cpa-bulk-{now.strftime('%Y%m%d-%H%M%S')}.zip"
        buf.seek(0)
        return Response(
            buf.getvalue(),
            mimetype="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{dl_name}"'},
        )

    @app.post("/api/codex/download-bulk")
    def api_codex_download_bulk():
        """
        Download the selected codex credentials in batch and pack them into one JSON file.

        Body: {"filenames": ["codex-xxx.json", ...]}
        Response: an aggregated JSON (an attachment that triggers a browser download), structure:
            {
              "exported_at": "...",
              "count": N,
              "credentials": [{"filename": "...", "data": {...raw credential content...}}, ...],
              "errors": [...]   // only present when some failed
            }
        Note: the aggregated format **cannot be read by CPA directly**, because CPA loads the auths/ directory file by file.
              The main purpose of this endpoint is backup / cross-machine migration / further processing.
        Every successful credential is marked with mark_exported automatically (count +1).
        """
        import json as _json
        from datetime import datetime as _dt

        data = request.get_json(silent=True) or {}
        filenames = data.get("filenames") or []
        if not isinstance(filenames, list) or not filenames:
            return jsonify({"ok": False, "error": "filenames must be a non-empty array"}), 400
        if len(filenames) > 1000:
            return jsonify({"ok": False, "error": "At most 1000 at a time"}), 400

        bundle = []
        errors = []
        for fname in filenames:
            if not isinstance(fname, str):
                errors.append({"filename": str(fname), "error": "not a string"})
                continue
            try:
                content, real_fname = db.read_codex_credential(fname)
                parsed = _json.loads(content)
                bundle.append({"filename": real_fname, "data": parsed})
                db.mark_codex_exported(real_fname)
            except Exception as exc:
                errors.append({"filename": fname, "error": f"{type(exc).__name__}: {exc}"})

        now = _dt.now()
        result = {
            "exported_at": now.isoformat(timespec="seconds"),
            "count": len(bundle),
            "credentials": bundle,
        }
        if errors:
            result["errors"] = errors

        dl_name = f"codex-bulk-{now.strftime('%Y%m%d-%H%M%S')}.json"
        return Response(
            _json.dumps(result, ensure_ascii=False, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="{dl_name}"'},
        )

    @app.post("/api/codex/reset-export")
    def api_codex_reset_export():
        """Clear the export state of a codex credential (mark it as not exported again). body {filename}."""
        data = request.get_json(silent=True) or {}
        fname = (data.get("filename") or "").strip()
        if not fname:
            return jsonify({"ok": False, "error": "filename is empty"}), 400
        try:
            db.reset_codex_exported(fname)
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True})

    @app.post("/api/codex/delete")
    def api_codex_delete():
        """Delete a codex credential file. body {filename}."""
        data = request.get_json(silent=True) or {}
        fname = (data.get("filename") or "").strip()
        if not fname:
            return jsonify({"ok": False, "error": "filename is empty"}), 400
        try:
            deleted = db.delete_codex_credential(fname)
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        if not deleted:
            return jsonify({"ok": False, "error": "Credential file does not exist"}), 404
        return jsonify({"ok": True, "deleted": fname})

    @app.post("/api/codex/delete-bulk")
    def api_codex_delete_bulk():
        """Delete codex credential files in batch. body {filenames:[...]}."""
        data = request.get_json(silent=True) or {}
        filenames = data.get("filenames") or []
        if not isinstance(filenames, list) or not filenames:
            return jsonify({"ok": False, "error": "filenames must be a non-empty array"}), 400
        if len(filenames) > 1000:
            return jsonify({"ok": False, "error": "At most 1000 can be deleted at a time"}), 400
        deleted = []
        skipped = []
        seen = set()
        for fname in filenames:
            fname = str(fname or "").strip()
            if not fname or fname in seen:
                continue
            seen.add(fname)
            try:
                ok = db.delete_codex_credential(fname)
                if ok:
                    deleted.append(fname)
                else:
                    skipped.append({"filename": fname, "reason": "File does not exist"})
            except Exception as exc:
                skipped.append({"filename": fname, "reason": f"{type(exc).__name__}: {exc}"})
        return jsonify({"ok": True, "deleted": deleted, "deleted_count": len(deleted), "skipped": skipped})

    def _reserve_codex_retry(email: str) -> bool:
        """In-process duplicate-prevention reservation; returns True on success."""
        return codex_retry_service.reserve(email)

    def _release_codex_retry(email: str) -> None:
        codex_retry_service.release(email)

    def _run_codex_retry_worker(email: str, *, batch_label: str | None = None, clear_log: bool = True) -> None:
        """Run the Codex rerun of one account. reserve must already have been called."""
        codex_retry_service.run_worker(email, batch_label=batch_label, clear_log=clear_log)


    @app.post("/api/codex/stop")
    def api_codex_stop():
        """Stop a single Codex rerun. Body {email}."""
        data = request.get_json(silent=True) or {}
        email = (data.get("email") or "").strip()
        if not email:
            return jsonify({"ok": False, "error": "email is empty"}), 400
        acc = db.get_account_by_email(email)
        if acc is None:
            return jsonify({"ok": False, "error": f"Account does not exist: {email}"}), 404
        result = codex_retry_service.request_stop(email)
        status = int(result.pop("status", 200) or 200)
        return jsonify(result), status

    @app.post("/api/codex/stop-bulk")
    def api_codex_stop_bulk():
        """Stop Codex reruns in batch. Body {emails:[...]} or {account_ids:[...]}."""
        data = request.get_json(silent=True) or {}
        emails = data.get("emails") or []
        ids = data.get("account_ids") or data.get("ids") or []
        targets = []
        if isinstance(emails, list) and emails:
            targets = [str(x or "").strip() for x in emails]
        elif isinstance(ids, list) and ids:
            for raw in ids:
                try:
                    acc = db.get_account(int(raw))
                except Exception:
                    acc = None
                if acc and acc.get("email"):
                    targets.append(str(acc.get("email") or "").strip())
        else:
            return jsonify({"ok": False, "error": "emails or account_ids must be a non-empty array"}), 400
        if len(targets) > 500:
            return jsonify({"ok": False, "error": "At most 500 can be stopped at a time"}), 400
        stopped = []
        skipped = []
        seen = set()
        for email in targets:
            key = email.lower()
            if not email or key in seen:
                continue
            seen.add(key)
            acc = db.get_account_by_email(email)
            if acc is None:
                skipped.append({"email": email, "reason": "Account does not exist"})
                continue
            if (acc.get("codex_status") or "") != "retrying" and not codex_retry_service.is_retrying(email):
                skipped.append({"email": email, "reason": "Not in a rerun"})
                continue
            r = codex_retry_service.request_stop(email)
            if r.get("ok"):
                stopped.append({"email": email, "injected": r.get("injected"), "running": r.get("running")})
            else:
                skipped.append({"email": email, "reason": r.get("error") or "Stop failed"})
        return jsonify({"ok": True, "stopped": stopped, "stopped_count": len(stopped), "skipped": skipped})

    @app.post("/api/codex/reset-retrying")
    def api_codex_reset_retrying():
        """Manually reset the Codex rerun-in-progress state of an account. Body {email, status?}."""
        from datetime import datetime as _dt

        data = request.get_json(silent=True) or {}
        email = (data.get("email") or "").strip()
        raw_status = (data.get("status") or "failed").strip().lower()
        if raw_status in ("", "none", "null", "clear"):
            raw_status = "empty"
        if not email:
            return jsonify({"ok": False, "error": "email is empty"}), 400
        if raw_status not in ("failed", "skipped", "empty"):
            return jsonify({"ok": False, "error": "status only supports failed/skipped/empty"}), 400

        acc = db.get_account_by_email(email)
        if acc is None:
            return jsonify({"ok": False, "error": f"Account does not exist: {email}"}), 404

        new_status = "" if raw_status == "empty" else raw_status
        err = None if raw_status == "empty" else "The user manually reset the rerun-in-progress state"
        ok = db.update_account_codex_status(email, new_status, err)
        if not ok:
            return jsonify({"ok": False, "error": f"Account does not exist: {email}"}), 404

        _release_codex_retry(email)

        try:
            log_path = codex_retry_service.log_path(email)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as f:
                ts = _dt.now().strftime("%H:%M:%S")
                shown = new_status or "empty"
                f.write(f"{ts} [WARNING] [Codex rerun] The user manually reset the rerun-in-progress state, current state={shown}\n")
        except Exception:
            logger.exception("Failed to write the Codex rerun reset log")

        return jsonify({"ok": True, "message": "Rerun-in-progress state reset", "status": new_status})

    @app.post("/api/codex/retry")
    def api_codex_retry():
        """Manually rerun the Codex authorization of an account. Body {email}."""
        data = request.get_json(silent=True) or {}
        email = (data.get("email") or "").strip()
        if not email:
            return jsonify({"ok": False, "error": "email is empty"}), 400
        acc = db.get_account_by_email(email)
        if acc is None:
            return jsonify({"ok": False, "error": f"Account does not exist: {email}"}), 404
        if (acc.get("live_check_status") or "") == "deactivated":
            return jsonify({"ok": False, "error": "The account is dead and cannot be rerun with Codex"}), 409
        if not _reserve_codex_retry(email):
            return jsonify({"ok": False, "error": "The account is currently being rerun, please wait"}), 409

        db.update_account_codex_status(email, "retrying", None)
        threading.Thread(
            target=_run_codex_retry_worker,
            kwargs={"email": email, "clear_log": True},
            name=f"codex-retry-{email}",
            daemon=True,
        ).start()
        return jsonify({"ok": True, "message": "Started the rerun in the background, refresh to check in ~1-2 minutes"})

    @app.post("/api/codex/retry-bulk")
    def api_codex_retry_bulk():
        """Rerun Codex in batch. Body {account_ids:[...], workers: 1-16}."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from datetime import datetime as _dt

        data = request.get_json(silent=True) or {}
        ids = data.get("account_ids") or data.get("ids") or []
        workers = data.get("workers", 1)
        if not isinstance(ids, list) or not ids:
            return jsonify({"ok": False, "error": "account_ids must be a non-empty array"}), 400
        try:
            workers = max(1, min(16, int(workers)))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "workers must be a number"}), 400
        if len(ids) > 500:
            return jsonify({"ok": False, "error": "At most 500 accounts can be selected at a time"}), 400

        selected = []
        skipped = []
        seen_ids = set()
        for raw in ids:
            try:
                acc_id = int(raw)
            except (TypeError, ValueError):
                skipped.append({"id": raw, "reason": "ID invalid"})
                continue
            if acc_id in seen_ids:
                continue
            seen_ids.add(acc_id)
            acc = db.get_account(acc_id)
            if not acc:
                skipped.append({"id": acc_id, "reason": "Account does not exist"})
                continue
            email = (acc.get("email") or "").strip()
            if not email:
                skipped.append({"id": acc_id, "reason": "Email is empty"})
                continue
            if (acc.get("live_check_status") or "") == "deactivated":
                skipped.append({"id": acc_id, "email": email, "reason": "Account is dead"})
                continue
            if not _reserve_codex_retry(email):
                skipped.append({"id": acc_id, "email": email, "reason": "Rerun in progress"})
                continue
            selected.append({"id": acc_id, "email": email})

        if not selected:
            return jsonify({"ok": False, "error": "No accounts can be rerun", "skipped": skipped}), 409

        batch_id = _dt.now().strftime("%Y%m%d-%H%M%S")
        for item in selected:
            email = item["email"]
            db.update_account_codex_status(email, "retrying", None)
            log_path = codex_retry_service.log_path(email)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(
                f"{_dt.now().strftime('%H:%M:%S')} [INFO] [Codex batch rerun] Added to batch job batch={batch_id} workers={workers}, waiting for a thread to execute\n",
                encoding="utf-8",
            )

        def _bulk_runner(items: list[dict], max_workers: int, batch: str):
            logger.info(f"[Codex batch rerun] Started batch={batch} count={len(items)} workers={max_workers}")
            with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix=f"codex-bulk-{batch}") as ex:
                futures = [ex.submit(_run_codex_retry_worker, it["email"], batch_label=f"{batch} #{idx}/{len(items)}", clear_log=False) for idx, it in enumerate(items, 1)]
                for fut in as_completed(futures):
                    try:
                        fut.result()
                    except Exception:
                        logger.exception(f"[Codex batch rerun] Child task error batch={batch}")
            logger.info(f"[Codex batch rerun] Finished batch={batch}")

        threading.Thread(
            target=_bulk_runner,
            args=(selected, workers, batch_id),
            name=f"codex-bulk-dispatch-{batch_id}",
            daemon=True,
        ).start()
        return jsonify({
            "ok": True,
            "message": f"Started the batch rerun of {len(selected)} accounts, concurrency {workers}",
            "started": selected,
            "started_count": len(selected),
            "skipped": skipped,
            "batch_id": batch_id,
        })

    @app.get("/api/codex/retry-log")
    def api_codex_retry_log():
        """Read the log of the most recent rerun of an email.?email=xxx"""
        email = (request.args.get("email") or "").strip()
        if not email:
            return jsonify({"ok": False, "error": "email is empty"}), 400
        p = codex_retry_service.log_path(email)
        if not p.exists():
            return jsonify({"ok": True, "log": "", "running": False})
        max_bytes = 50_000
        size = p.stat().st_size
        with p.open("rb") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
            content = f.read().decode("utf-8", errors="replace")
        return jsonify({
            "ok": True,
            "log": content,
            "running": codex_retry_service.is_retrying(email),
        })

    @app.get("/api/accounts/live-check-log")
    def api_account_live_check_log():
        """Read the log of the most recent liveness check of an email.?email=xxx"""
        from core import account_liveness
        email = (request.args.get("email") or "").strip()
        if not email:
            return jsonify({"ok": False, "error": "email is empty"}), 400
        p = account_liveness.log_path(email)
        data = _read_log_tail(p, max_bytes=80_000, running_fn=lambda: live_check_service.is_checking(email))
        return jsonify(data)

    @app.get("/api/accounts/totp-setup-log")
    def api_account_totp_setup_log():
        """Read the log of the most recent 2FA setup of an email.?email=xxx"""
        from core import twofa_service
        email = (request.args.get("email") or "").strip()
        if not email:
            return jsonify({"ok": False, "error": "email is empty"}), 400
        p = twofa_service.log_path(email)
        data = _read_log_tail(p, max_bytes=80_000, running_fn=lambda: False)
        try:
            acc = db.get_account_by_email(email) or {}
            data["running"] = bool(str(acc.get("totp_setup_status") or "") in {"queued", "running"}) or twofa_service.is_running(int(acc.get("id") or 0))
        except Exception:
            pass
        return jsonify(data)

    @app.get("/api/accounts/<int:acc_id>/change-email-log")
    def api_account_change_email_log(acc_id: int):
        """Read the log of the most recent email change of an account."""
        from core import email_change_service
        acc = db.get_account(acc_id)
        if not acc:
            return jsonify({"ok": False, "error": "Account does not exist"}), 404
        data = _read_log_tail(
            email_change_service.log_path(acc_id), max_bytes=80_000,
            running_fn=lambda: email_change_service.is_running(acc_id),
        )
        data["account_id"] = acc_id
        data["email"] = acc.get("email")
        data["running"] = bool(data.get("running") or str(acc.get("email_change_status") or "") in {"queued", "running"})
        return jsonify(data)

    # ----------------------------------------------------------
    # Registration tasks
    # ----------------------------------------------------------
    @app.get("/api/jobs")
    def api_jobs():
        limit = request.args.get("limit", default=100, type=int)
        paged = str(request.args.get("paged", default="") or "").lower() in {"1", "true", "yes"}
        page_arg = request.args.get("page", default=None, type=int)
        page_size_arg = request.args.get("page_size", default=None, type=int)
        from config import email as _email_cfg
        manual_otp_required = not bool(getattr(_email_cfg, "USE_EMAIL_SERVICE", True))
        if paged or page_arg is not None or page_size_arg is not None:
            page = max(1, int(page_arg or 1))
            page_size = max(1, min(500, int(page_size_arg or limit or 50)))
            result = db.list_jobs_page(
                limit=page_size, offset=(page - 1) * page_size
            )
            rows = result.get("items") or []
            for row in rows:
                row["manual_otp_required"] = manual_otp_required
                row.update(svc.get_retry_info(row))
            result.update({"ok": True, "page": page, "page_size": page_size})
            result["items"] = [_compact_job_for_list(r) for r in rows]
            result["status_counts"] = db.job_status_counts()
            result["compact"] = True
            return jsonify(result)
        rows = db.list_jobs(limit=max(1, int(limit or 1)))
        for row in rows:
            row["manual_otp_required"] = manual_otp_required
            row.update(svc.get_retry_info(row))
        return jsonify(rows)

    @app.post("/api/jobs")
    def api_jobs_create():
        """Start a batch registration: body {count, workers}."""
        data = request.get_json(silent=True) or {}
        try:
            count = int(data.get("count", 1))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "count invalid"}), 400
        if count < 1 or count > 200:
            return jsonify({"ok": False, "error": "count must be between 1 and 200"}), 400

        # workers Controls the thread pool used by the newly submitted tasks; if it differs from the last one, the service layer switches the new tasks to a new pool.
        try:
            workers = max(1, min(16, int(data.get("workers", 3))))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "workers invalid"}), 400

        # Before submitting, first confirm the pool has enough available emails and give the front end a gentle hint (not blocking)
        from config import email as _email_cfg
        from config import register as _register_cfg
        from core.email_provider import parse_email_sources
        if not bool(getattr(_email_cfg, "USE_EMAIL_SERVICE", True)):
            reg_email = str(getattr(_register_cfg, "REGISTER_EMAIL", "") or "").strip()
            if not reg_email:
                return jsonify({
                    "ok": False,
                    "error": "REGISTER_EMAIL is not configured for manual mode. Please fill in the 'manual registration email' on the config page, or enable automatic email claiming + code receiving.",
                }), 400
            if count > 1:
                return jsonify({
                    "ok": False,
                    "error": "In manual mode, run only 1 task at a time (the same REGISTER_EMAIL). Please set the count to 1.",
                }), 400
            jobs = svc.submit_registration(count=count, workers=workers)
            return jsonify({
                "ok": True,
                "submitted": len(jobs),
                "jobs": jobs,
                "warning": f"Manual OTP mode: {reg_email} will be used; submit the verification code on the task page",
                "workers": workers,
            })
        sources = parse_email_sources(_email_cfg.EMAIL_SOURCE)
        if "gptmail" in sources:
            api_key = str(getattr(_email_cfg, "GPTMAIL_API_KEY", "") or "").strip()
            if not api_key:
                return jsonify({
                    "ok": False,
                    "error": "The gptmail email source is selected, please fill in the GPTMail API Key (Config -> Email / OTP).",
                }), 400
        if "cloudflare" in sources:
            api_base = str(getattr(_email_cfg, "CLOUDFLARE_API_BASE", "") or "").strip()
            if not api_base:
                return jsonify({
                    "ok": False,
                    "error": "The cloudflare email source is selected, please fill in the Cloudflare API address (Config -> Email / OTP).",
                }), 400
            auth_mode = str(getattr(_email_cfg, "CLOUDFLARE_AUTH_MODE", "none") or "none").strip().lower()
            accounts_path = str(getattr(_email_cfg, "CLOUDFLARE_PATH_ACCOUNTS", "/api/new_address") or "").strip().lower()
            api_key = str(getattr(_email_cfg, "CLOUDFLARE_API_KEY", "") or "").strip()
            needs_key = auth_mode in ("x-admin-auth", "bearer", "x-api-key", "query-key") or accounts_path.rstrip("/").endswith("/admin/new_address")
            if needs_key and not api_key:
                return jsonify({
                    "ok": False,
                    "error": "Cloudflare admin/Auth mode requires the Cloudflare API Key (Config -> Email / OTP).",
                }), 400
        if "mailnest" in sources:
            api_key = str(getattr(_email_cfg, "MAIL_NEST_API_KEY", "") or "").strip()
            project_code = str(getattr(_email_cfg, "MAIL_NEST_PROJECT_CODE", "") or "").strip()
            if not api_key:
                return jsonify({
                    "ok": False,
                    "error": "The mailnest email source is selected, please fill in the MailNest API Key (Config -> Email / OTP).",
                }), 400
            if not project_code:
                return jsonify({
                    "ok": False,
                    "error": "The mailnest email source is selected, please fill in the MailNest project code (Config -> Email / OTP).",
                }), 400
        if "cloudmail" in sources:
            api_base = str(getattr(_email_cfg, "CLOUDMAIL_API_BASE", "") or "").strip()
            token = str(getattr(_email_cfg, "CLOUDMAIL_AUTH_TOKEN", "") or "").strip()
            if not api_base:
                return jsonify({
                    "ok": False,
                    "error": "The cloudmail email source is selected, please fill in the CloudMail API address (Config -> Email / OTP).",
                }), 400
            if not token:
                return jsonify({
                    "ok": False,
                    "error": "The cloudmail email source is selected, please fill in the CloudMail Token (Config -> Email / OTP).",
                }), 400
        if "xigua" in sources:
            xigua_key = str(getattr(_email_cfg, "XIGUA_API_KEY", "") or "").strip()
            if not xigua_key:
                return jsonify({"ok": False, "error": "The xigua email source is selected, please fill in the Xigua API Key (Config -> Email / OTP)."}), 400
        if "mailcode" in sources:
            for key, label in (("MAILCODE_API_KEY", "API Key"), ("MAILCODE_PRODUCT_ID", "product ID")):
                if not str(getattr(_email_cfg, key, "") or "").strip():
                    return jsonify({"ok": False, "error": f"The mailcode email source is selected, please fill in the domain email MailCode {label} (Config -> Email / OTP)."}), 400
        if "remail" in sources:
            api_base = str(getattr(_email_cfg, "REMAIL_API_BASE", "") or "").strip()
            api_key = str(getattr(_email_cfg, "REMAIL_API_KEY", "") or "").strip()
            try:
                project_id = int(getattr(_email_cfg, "REMAIL_PROJECT_ID", 2) or 0)
            except (TypeError, ValueError):
                project_id = 0
            suffix = str(getattr(_email_cfg, "REMAIL_EMAIL_SUFFIX", "") or "").strip()
            service_mode = str(getattr(_email_cfg, "REMAIL_SERVICE_MODE", "purchase") or "purchase").strip().lower()
            if not api_base:
                return jsonify({
                    "ok": False,
                    "error": "The remail email source is selected, please fill in the Remail API address (Config -> Email / OTP).",
                }), 400
            if not api_key:
                return jsonify({
                    "ok": False,
                    "error": "The remail email source is selected, please fill in the Remail API Key (Config -> Email / OTP).",
                }), 400
            if project_id <= 0:
                return jsonify({
                    "ok": False,
                    "error": "The remail email source is selected, please fill in the Remail project ID (Config -> Email / OTP).",
                }), 400
            if not suffix:
                return jsonify({
                    "ok": False,
                    "error": "The remail email source is selected, please fill in the Remail email suffix (for example outlook.com).",
                }), 400
            if service_mode not in ("code", "purchase"):
                return jsonify({
                    "ok": False,
                    "error": "Remail The service mode can only be code or purchase (Config -> Email / OTP).",
                }), 400
        if "mailcode" in sources or "gptmail" in sources or "mailnest" in sources or "cloudmail" in sources or "remail" in sources or "xigua" in sources or "cloudflare" in sources:
            # Temporary emails are generated dynamically when the task starts, so no local email pool capacity hint is needed.
            warning = ""
        elif "cloudflare_domain" in sources:
            pool = db.domain_email_pool_summary()
            warning = ""
            if sources == ["cloudflare_domain"] and pool.get("available", 0) < count:
                warning = f"The domain email pool only has {pool.get('available', 0)} available, fewer than the task count {count}; the missing ones will be generated automatically"
        elif sources == ["generic_api"]:
            pool = db.generic_api_email_pool_summary()
            warning = ""
            if pool.get("available", 0) < count:
                warning = f"The generic API email pool only has {pool.get('available', 0)} available, fewer than the task count {count}; the missing ones will fail"
        elif sources == ["imap"]:
            pool = db.imap_email_pool_summary()
            warning = ""
            if pool.get("available", 0) < count:
                warning = f"The generic IMAP email pool only has {pool.get('available', 0)} available, fewer than the task count {count}; the missing ones will fail"
        elif len(sources) > 1:
            available = 0
            if "outlook" in sources:
                available += db.outlook_pool_summary().get("available", 0)
            if "generic_api" in sources:
                available += db.generic_api_email_pool_summary().get("available", 0)
            if "imap" in sources:
                available += db.imap_email_pool_summary().get("available", 0)
            warning = ""
            if available < count:
                warning = f"The combined email pools only have {available} available, fewer than the task count {count}; the missing ones will fail"
        else:
            pool = db.outlook_pool_summary()
            warning = ""
            if pool.get("available", 0) < count:
                warning = f"Available emails only {pool.get('available', 0)} , fewer than the task count {count}; the missing ones will fail"
        jobs = svc.submit_registration(count=count, workers=workers)
        return jsonify({"ok": True, "submitted": len(jobs), "jobs": jobs, "warning": warning, "workers": workers})

    @app.get("/api/manual-otp/waiting")
    def api_manual_otp_waiting():
        """List the emails currently waiting for a manual verification code."""
        from core.manual_otp import list_waiting
        return jsonify({"ok": True, "waiting": list_waiting()})

    @app.post("/api/manual-otp")
    def api_manual_otp_submit():
        """Submit a manual email verification code. Body: {email, code} or {job_id, code}."""
        from core.manual_otp import submit_manual_otp
        data = request.get_json(silent=True) or {}
        code = (data.get("code") or data.get("otp") or "").strip()
        email = (data.get("email") or "").strip()
        job_id = data.get("job_id")
        if not email and job_id is not None:
            job = db.get_job(int(job_id))
            email = (job or {}).get("email") or ""
        if not email:
            return jsonify({"ok": False, "error": "email/job_id missing"}), 400
        try:
            result = submit_manual_otp(email, code)
            return jsonify(result)
        except Exception as exc:
            return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400

    @app.post("/api/jobs/cancel-pending")
    def api_jobs_cancel_pending():
        """Cancel all tasks still queued (status=pending). Tasks already running are left alone."""
        cancelled = svc.cancel_pending_jobs()
        return jsonify({"ok": True, "cancelled": cancelled})

    @app.post("/api/jobs/<int:job_id>/stop")
    def api_job_stop(job_id: int):
        """Manually stop a single registration task. Pending ones are cancelled; running ones receive a stop signal."""
        result = svc.request_stop_job(job_id)
        if not result.get("ok"):
            return jsonify({"ok": False, "error": result.get("error") or "Stop failed"}), int(result.get("status") or 400)
        return jsonify(result)

    @app.post("/api/jobs/<int:job_id>/retry")
    def api_job_retry(job_id: int):
        """Retry failed/stopped/cancelled tasks; the server decides automatically between a full registration and a Codex rerun."""
        data = request.get_json(silent=True) or {}
        try:
            workers = max(1, min(16, int(data.get("workers", svc.get_executor_workers()))))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "workers invalid"}), 400
        result = svc.retry_job(job_id, workers=workers)
        if not result.get("ok"):
            return jsonify(result), int(result.get("status") or 400)
        return jsonify(result)

    @app.post("/api/jobs/retry-bulk")
    def api_jobs_retry_bulk():
        """Retry tasks in batch; unsupported ones are skipped one by one and the reason is returned."""
        data = request.get_json(silent=True) or {}
        job_ids = data.get("job_ids") or data.get("ids") or []
        if not isinstance(job_ids, list) or not job_ids:
            return jsonify({"ok": False, "error": "job_ids must be a non-empty array"}), 400
        if len(job_ids) > 500:
            return jsonify({"ok": False, "error": "At most 500 tasks can be retried at a time"}), 400
        try:
            workers = max(1, min(16, int(data.get("workers", svc.get_executor_workers()))))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "workers invalid"}), 400

        started: list[dict] = []
        reused: list[dict] = []
        skipped: list[dict] = []
        seen: set[int] = set()
        for raw_id in job_ids:
            try:
                one_id = int(raw_id)
            except (TypeError, ValueError):
                skipped.append({"id": raw_id, "reason": "ID invalid"})
                continue
            if one_id in seen:
                continue
            seen.add(one_id)
            result = svc.retry_job(one_id, workers=workers)
            if not result.get("ok"):
                skipped.append({"id": one_id, "reason": result.get("error") or "Cannot be retried"})
            elif result.get("reused"):
                reused.append(result)
            else:
                started.append(result)
        return jsonify({
            "ok": True,
            "started": started,
            "started_count": len(started),
            "reused": reused,
            "reused_count": len(reused),
            "skipped": skipped,
            "skipped_count": len(skipped),
            "workers": workers,
        })

    @app.post("/api/jobs/<int:job_id>/delete")
    def api_job_delete(job_id: int):
        """Delete a task record. Running tasks cannot be deleted; a queued task is skipped automatically before execution after it is deleted."""
        job = db.get_job(job_id)
        if not job:
            return jsonify({"ok": False, "error": "Task does not exist"}), 404
        if job.get("status") in ("running", "stopping"):
            return jsonify({"ok": False, "error": "A running task cannot be deleted, please wait for it to finish before deleting"}), 409
        deleted = db.delete_job(job_id, delete_log=True, allow_running=False)
        if not deleted:
            return jsonify({"ok": False, "error": "The task does not exist or has already started running"}), 409
        return jsonify({"ok": True, "deleted": deleted})

    @app.post("/api/jobs/delete-bulk")
    def api_jobs_delete_bulk():
        """Delete task records in batch. Running tasks are skipped; for other tasks the record and the log are deleted."""
        data = request.get_json(silent=True) or {}
        job_ids = data.get("job_ids") or data.get("ids") or []
        if not isinstance(job_ids, list) or not job_ids:
            return jsonify({"ok": False, "error": "job_ids must be a non-empty array"}), 400
        if len(job_ids) > 1000:
            return jsonify({"ok": False, "error": "At most 1000 tasks can be deleted at a time"}), 400

        deleted: list[int] = []
        skipped: list[dict] = []
        seen: set[int] = set()
        for raw_id in job_ids:
            try:
                job_id = int(raw_id)
            except (TypeError, ValueError):
                skipped.append({"id": raw_id, "reason": "ID invalid"})
                continue
            if job_id in seen:
                continue
            seen.add(job_id)

            job = db.get_job(job_id)
            if not job:
                skipped.append({"id": job_id, "reason": "Task does not exist"})
                continue
            if job.get("status") in ("running", "stopping"):
                skipped.append({"id": job_id, "reason": "Running, cannot be deleted"})
                continue
            if db.delete_job(job_id, delete_log=True, allow_running=False):
                deleted.append(job_id)
            else:
                skipped.append({"id": job_id, "reason": "The task does not exist or has already started running"})

        return jsonify({"ok": True, "deleted": deleted, "deleted_count": len(deleted), "skipped": skipped})

    @app.get("/api/jobs/<int:job_id>/log")
    def api_job_log(job_id: int):
        job = db.get_job(job_id)
        if not job:
            return jsonify({"ok": False, "error": "Task does not exist"}), 404
        return jsonify({
            "ok": True,
            "job": job,
            "log": svc.read_job_log(job_id),
        })

    # ----------------------------------------------------------
    # RoxyBrowser helper APIs
    # ----------------------------------------------------------
    @app.get("/api/roxy/workspaces")
    def api_roxy_workspaces():
        try:
            from core.roxybrowser_client import RoxyBrowserClient
            result = RoxyBrowserClient().list_workspaces()
            return jsonify(result)
        except Exception as exc:
            logger.exception("Failed to get the Roxy team/workspace")
            return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 500

    # ----------------------------------------------------------
    # Config read/write
    # ----------------------------------------------------------
    @app.get("/api/config")
    def api_config_get():
        return jsonify(config_editor.get_config())

    @app.get("/api/mailcode/catalog")
    def api_mailcode_catalog():
        """Query products and balance with the saved service configuration, without buying an email."""
        from core.mailcode_client import list_products, get_wallet, MailCodeError
        try:
            return jsonify({"ok": True, "products": list_products(), "wallet": get_wallet()})
        except MailCodeError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.post("/api/cloudmail/gen-token")
    def api_cloudmail_gen_token():
        """Manually generate the CloudMail Authorization Token, and write the CloudMail configuration filled in this time to .env as well."""
        data = request.get_json(silent=True) or {}
        try:
            from core.cloudmail_client import gen_token
            from config.env_loader import write_env_values

            api_base = (data.get("api_base") or "").strip()
            admin_email = (data.get("email") or data.get("admin_email") or "").strip()
            password = (data.get("password") or "").strip()
            path = (data.get("path") or "/api/public/genToken").strip() or "/api/public/genToken"
            token = gen_token(
                email=admin_email,
                password=password,
                path=path,
                base_url=api_base,
            )
            updates = {"CLOUDMAIL_AUTH_TOKEN": token}
            # When the token is generated the user usually has not clicked "Save config" yet; the fields filled in this time are saved together here,
            # to avoid the API address / account / password being overwritten by the old .env values after loadConfig().
            if api_base:
                updates["CLOUDMAIL_API_BASE"] = api_base
            if admin_email:
                updates["CLOUDMAIL_ADMIN_EMAIL"] = admin_email
            if password:
                updates["CLOUDMAIL_PASSWORD"] = password
            if path:
                updates["CLOUDMAIL_TOKEN_PATH"] = path
            written = write_env_values(updates)
            try:
                import config as _config_pkg
                _config_pkg.reload_all()
            except Exception:
                logger.exception("CloudMail Token hot reload failed after writing")
            return jsonify({
                "ok": True,
                "token": token,
                "written": written,
                "message": "CloudMail Token generated, and the current CloudMail configuration has been saved",
            })
        except Exception as exc:
            logger.exception("Failed to generate the CloudMail Token")
            return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400

    @app.post("/api/cloudmail/domains")
    def api_cloudmail_domains():
        """Get the domain list from the CloudMail platform, and optionally write it to .env as a local cache."""
        data = request.get_json(silent=True) or {}
        try:
            from core.cloudmail_client import fetch_domains
            from config.env_loader import write_env_values

            updates = {}
            api_base = (data.get("api_base") or "").strip()
            admin_email = (data.get("email") or data.get("admin_email") or "").strip()
            password = (data.get("password") or "").strip()
            token = (data.get("token") or "").strip()
            if api_base:
                updates["CLOUDMAIL_API_BASE"] = api_base
            if admin_email:
                updates["CLOUDMAIL_ADMIN_EMAIL"] = admin_email
            if password:
                updates["CLOUDMAIL_PASSWORD"] = password
            if token:
                updates["CLOUDMAIL_AUTH_TOKEN"] = token
            if updates:
                write_env_values(updates)
                import config as _config_pkg
                _config_pkg.reload_all()

            domains = fetch_domains(force=True)
            written = write_env_values({"CLOUDMAIL_DOMAINS": "\n".join(domains)})
            try:
                import config as _config_pkg
                _config_pkg.reload_all()
            except Exception:
                logger.exception("CloudMail hot reload failed after writing the domains")
            return jsonify({
                "ok": True,
                "domains": domains,
                "count": len(domains),
                "written": written,
                "message": f"Got {len(domains)} available CloudMail domains and saved them",
            })
        except Exception as exc:
            logger.exception("Failed to get the CloudMail domains")
            return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400

    @app.post("/api/config")
    def api_config_set():
        data = request.get_json(silent=True) or {}
        updates = data.get("updates") if isinstance(data.get("updates"), dict) else data
        if not isinstance(updates, dict) or not updates:
            return jsonify({"ok": False, "error": "Nothing to update"}), 400
        try:
            result = config_editor.update_config(updates)
        except Exception as exc:
            logger.exception("Failed to write the config")
            return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 500

        # Right after the write succeeds, hot-reload all config submodules, so the runtime code sees the new values.
        reload_ok = True
        reload_err = ""
        try:
            import config as _config_pkg
            _config_pkg.reload_all()
            from core import twofa_service
            twofa_service.apply_settings()
        except Exception as exc:
            reload_ok = False
            reload_err = f"{type(exc).__name__}: {exc}"
            logger.exception("Config hot reload failed")

        return jsonify({
            "ok": True,
            "updated": result["updated"],
            "ignored": result["ignored"],
            "reloaded": reload_ok,
            "note": (
                "✅ Saved and hot-reloaded, the new values take effect immediately"
                if reload_ok
                else f"⚠️ Written to the file but the hot reload failed ({reload_err}), the web service must be restarted for it to take effect"
            ),
        })

    return app
