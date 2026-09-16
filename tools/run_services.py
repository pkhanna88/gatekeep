"""
Run the four Gatekeep application services on this machine, in one terminal.

    make services            Ctrl+C stops all four

    8000  control-plane     agents, grants, approvals, kill switch, audit
    8001  token-service     RFC 8693 exchange, JWKS
    8002  pep-proxy         enforcement
    8003  mock-salesforce   connector one's upstream

They run on the host rather than in Compose on purpose: every token must agree
on `localhost` as the hostname (docs/DECISIONS.md, Day 1), and a container sees
`localhost` as itself. Output from each service is prefixed with its name.
"""

import os
import pathlib
import signal
import subprocess
import sys
import threading
import time

import httpx

REPO = pathlib.Path(__file__).resolve().parent.parent
PY = sys.executable

SERVICES = [
    ("control-plane", "app.main:app", 8000),
    ("token-service", "token_service.main:app", 8001),
    ("pep-proxy", "pep_proxy.main:app", 8002),
    ("mock-salesforce", "mock_salesforce.main:app", 8003),
]

COLOURS = ["36", "35", "33", "34"]


def pythonpath() -> str:
    dirs = ["control-plane", "token-service", "pep-proxy", "mock-salesforce"]
    return os.pathsep.join(str(REPO / "services" / d) for d in dirs)


def pump(name: str, colour: str, stream) -> None:
    tag = (
        f"\033[{colour}m{name:>15}\033[0m |" if not os.environ.get("NO_COLOR") else f"{name:>15} |"
    )
    for line in iter(stream.readline, ""):
        print(f"{tag} {line}", end="", flush=True)


def main() -> int:
    # Line-buffer so CI, which reads this through a file, sees "All four services up".
    sys.stdout.reconfigure(line_buffering=True)
    env = {**os.environ, "PYTHONPATH": pythonpath(), "PYTHONUNBUFFERED": "1"}
    procs = []
    for (name, target, port), colour in zip(SERVICES, COLOURS, strict=True):
        p = subprocess.Popen(
            [PY, "-m", "uvicorn", target, "--port", str(port), "--log-level", "warning"],
            cwd=REPO,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        threading.Thread(target=pump, args=(name, colour, p.stdout), daemon=True).start()
        procs.append((name, port, p))

    def stop(*_):
        for _, _, p in procs:
            p.terminate()
        for _, _, p in procs:
            p.wait(timeout=10)
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    deadline = time.monotonic() + 30
    pending = {port: name for name, port, _ in procs}
    while pending and time.monotonic() < deadline:
        for port in list(pending):
            try:
                if httpx.get(f"http://localhost:{port}/healthz", timeout=1).status_code == 200:
                    print(
                        f"{'ready':>15} | {pending.pop(port)} on http://localhost:{port}",
                        flush=True,
                    )
            except httpx.HTTPError:
                pass
        if any(p.poll() is not None for _, _, p in procs):
            print("A service exited during startup. Is the stack up, migrated and seeded?")
            print("    make dev && make migrate && make seed")
            stop()
        time.sleep(0.5)
    if pending:
        print(f"Not healthy after 30s: {', '.join(pending.values())}. See output above.")
    else:
        print(
            f"{'':>15} | All four services up. "
            "API docs: http://localhost:8000/docs  Ctrl+C to stop."
        )

    while all(p.poll() is None for _, _, p in procs):
        time.sleep(1)
    print("A service stopped unexpectedly; stopping the rest.")
    stop()
    return 1


if __name__ == "__main__":
    sys.exit(main())
