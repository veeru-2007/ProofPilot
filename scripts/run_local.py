"""Start ProofPilot's local frontend and API with matching loopback settings."""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener


ROOT = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"
API_VERSION = 1


def port_number(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def require_free_port(port: int) -> None:
    with socket.socket() as listener:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            listener.bind((HOST, port))
        except OSError as exc:
            raise RuntimeError(f"Local port {port} is unavailable. Choose another port.") from exc


def wait_for_start(process, request, check, label: str) -> None:
    opener = build_opener(ProxyHandler({}))
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        code = process.poll()
        if code is not None:
            raise RuntimeError(f"{label} exited with code {code}. See the startup log above.")
        try:
            with opener.open(request, timeout=1) as response:
                if response.status == 200 and check(response):
                    return
        except (OSError, URLError, ValueError):
            pass
        time.sleep(0.2)
    raise RuntimeError(f"{label} did not return the expected response within 20 seconds.")


def stop_process(process) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-port", type=port_number, default=8000)
    parser.add_argument("--frontend-port", type=port_number, default=5173)
    parser.add_argument("--provider", choices=("local", "agentcore"), default="local")
    parser.add_argument("--check", action="store_true", help="Verify startup and stop both services.")
    args = parser.parse_args()
    if args.backend_port == args.frontend_port:
        parser.error("the frontend and backend need different ports")

    api_url = f"http://{HOST}:{args.backend_port}"
    frontend_url = f"http://{HOST}:{args.frontend_port}"
    frontend_dir = ROOT / "frontend"
    vite = frontend_dir / "node_modules" / "vite" / "bin" / "vite.js"
    node = shutil.which("node")
    processes = []
    try:
        if not node or not vite.is_file():
            raise RuntimeError("Node.js and the frontend dependencies are required. See README.md.")
        require_free_port(args.backend_port)
        require_free_port(args.frontend_port)
        backend_env = {
            **os.environ,
            "CORS_ORIGINS": frontend_url,
            "ALLOWED_DEMO_TARGETS": f"{api_url}/demo/laptop-selection",
            "PROOFPILOT_BROWSER_PROVIDER": args.provider,
        }
        if args.provider == "local":
            backend_env.setdefault("PROOFPILOT_WARRANT_MODE", "local_demo")
        backend = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "main:app", "--host", HOST, "--port", str(args.backend_port), "--workers", "1"],
            cwd=ROOT / "backend",
            env=backend_env,
        )
        processes.append(backend)

        def compatible_api(response):
            health = json.load(response)
            return (
                isinstance(health, dict)
                and health.get("status") == "ok"
                and health.get("api_version") == API_VERSION
                and response.headers.get("Access-Control-Allow-Origin") == frontend_url
            )

        wait_for_start(
            backend, Request(f"{api_url}/api/health", headers={"Origin": frontend_url}), compatible_api, "ProofPilot API"
        )

        frontend_env = {**os.environ, "VITE_API_URL": api_url}
        frontend_env.pop("PROOFPILOT_WARRANT_SIGNING_SECRET", None)
        frontend = subprocess.Popen(
            [node, str(vite), "--host", HOST, "--port", str(args.frontend_port), "--strictPort"],
            cwd=frontend_dir,
            env=frontend_env,
        )
        processes.append(frontend)
        wait_for_start(frontend, frontend_url, lambda response: b"ProofPilot" in response.read(), "ProofPilot frontend")
        print(f"ProofPilot is ready at {frontend_url}/ (API {api_url}, provider {args.provider}).", flush=True)
        if args.check:
            return 0
        while True:
            for label, process in (("API", backend), ("frontend", frontend)):
                if (code := process.poll()) is not None:
                    raise RuntimeError(f"ProofPilot {label} exited with code {code}.")
            time.sleep(0.5)
    except KeyboardInterrupt:
        return 0
    except (OSError, RuntimeError) as exc:
        print(f"ProofPilot startup error: {exc}", file=sys.stderr)
        return 1
    finally:
        for process in reversed(processes):
            stop_process(process)


if __name__ == "__main__":
    raise SystemExit(main())
