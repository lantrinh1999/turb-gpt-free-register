# -*- coding: utf-8 -*-
"""
WebUI startup entry point.

Usage:
    python web.py                 # default http://127.0.0.1:5000, local access only, does not open the browser automatically
    python web.py --open-browser  # Open the browser automatically after startup
    python web.py --port 8000     # change the port
    python web.py --host 0.0.0.0  # allow LAN access (sensitive tool, evaluate at your own discretion)

Fully parallel to the CLI (python main.py), the two do not affect each other.
"""
import argparse
import logging
import os
import tempfile
import webbrowser
from pathlib import Path
from threading import Timer

from webui.app import create_app
from webui.auth import is_generated_code


def _acquire_single_instance(port: int):
    """Hold a cross-process file lock to prevent multiple WebUI instances from starting on the same port."""
    lock_path = Path(tempfile.gettempdir()) / f"turb-gpt-free-register-web-{int(port)}.lock"
    handle = lock_path.open("a+", encoding="utf-8")
    handle.seek(0, os.SEEK_END)
    if handle.tell() == 0:
        handle.write("0")
        handle.flush()
    handle.seek(0)
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, IOError) as exc:
        handle.close()
        raise RuntimeError(f"WebUI on port {port} is already running") from exc
    handle.seek(0)
    handle.truncate()
    handle.write(str(os.getpid()))
    handle.flush()
    return handle


def _release_single_instance(handle) -> None:
    if handle is None:
        return
    try:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except (OSError, IOError):
        pass
    handle.close()


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="GPT registration WebUI console")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address, local-only default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=5000, help="Port, default 5000")
    parser.add_argument("--open-browser", action="store_true", help="Open the browser automatically after startup")
    parser.add_argument("--auth-code", default=None, help="WebUI authorization code; can also be configured in .env: WEBUI_AUTH_CODE=...")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    _setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    if args.auth_code:
        os.environ["WEBUI_AUTH_CODE"] = args.auth_code

    try:
        instance_lock = _acquire_single_instance(args.port)
    except RuntimeError as exc:
        logger.error(str(exc))
        raise SystemExit(2) from exc

    app = create_app(auth_code=args.auth_code)
    url = f"http://{'127.0.0.1' if args.host in ('0.0.0.0', '::') else args.host}:{args.port}"
    logger.info(f"WebUI started:{url}")
    if is_generated_code():
        from webui.auth import expected_auth_code
        logger.warning("WEBUI_AUTH_CODE/AUTH_CODE is not configured; generated a temporary authorization code for this run:%s", expected_auth_code())
    if args.host in ("0.0.0.0", "::"):
        logger.warning("Bound to all network interfaces, so other devices on the LAN can access it. This is a sensitive tool, please make sure the network is trusted.")

    # By default the browser is not opened automatically; when needed, pass explicitly --open-browser
    if args.open_browser:
        Timer(1.0, lambda: webbrowser.open(url)).start()

    # debug=False: avoids duplicate thread pools/timers caused by the two reloader processes
    try:
        app.run(host=args.host, port=args.port, debug=False, threaded=True)
    finally:
        _release_single_instance(instance_lock)


if __name__ == "__main__":
    main()
