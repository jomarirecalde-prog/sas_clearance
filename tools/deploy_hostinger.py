#!/usr/bin/env python3
"""
Deploy CLEARANCE to Hostinger shared hosting over SFTP/SSH.

Credentials via environment variables (never commit secrets):
  DEPLOY_SSH_HOST, DEPLOY_SSH_PORT, DEPLOY_SSH_USER, DEPLOY_SSH_PASSWORD
  DEPLOY_REMOTE_DIR (optional; auto-detects ~/domains/*/public_html)
  DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
  APP_BASE_URL (optional), APP_ENV=production

Usage:
  set DEPLOY_SSH_PASSWORD=...
  python tools/deploy_hostinger.py
  python tools/deploy_hostinger.py --import-db
"""

from __future__ import annotations

import argparse
import os
import posixpath
import stat
import sys
import zipfile
from pathlib import Path

try:
    import paramiko
except ImportError:
    print("Install: pip install paramiko", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent

SKIP_DIRS = {".git", "__pycache__", "node_modules"}
SKIP_FILES = {".env", "Thumbs.db", ".DS_Store"}
SKIP_SUFFIXES = {".sess", ".log"}


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def connect_ssh() -> paramiko.SSHClient:
    host = env("DEPLOY_SSH_HOST", "109.106.254.155")
    port = int(env("DEPLOY_SSH_PORT", "65002"))
    user = env("DEPLOY_SSH_USER", "u899628465")
    password = env("DEPLOY_SSH_PASSWORD")
    if not password:
        print("Set DEPLOY_SSH_PASSWORD", file=sys.stderr)
        sys.exit(1)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        port=port,
        username=user,
        password=password,
        timeout=60,
        allow_agent=False,
        look_for_keys=False,
    )
    return client


def run(client: paramiko.SSHClient, cmd: str) -> tuple[int, str, str]:
    _, stdout, stderr = client.exec_command(cmd)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def detect_public_html(client: paramiko.SSHClient) -> str:
    custom = env("DEPLOY_REMOTE_DIR")
    if custom:
        return custom.rstrip("/")

    code, out, _ = run(client, "find \"$HOME\"/domains -maxdepth 2 -type d -name public_html 2>/dev/null | head -1")
    path = out.strip()
    if code == 0 and path:
        return path

    code, out, _ = run(client, "echo \"$HOME/public_html\"")
    fallback = out.strip()
    if fallback:
        return fallback

    raise RuntimeError("Could not detect public_html; set DEPLOY_REMOTE_DIR")


def should_skip(rel: Path) -> bool:
    parts = rel.parts
    if parts and parts[0] in SKIP_DIRS:
        return True
    if rel.name in SKIP_FILES:
        return True
    if rel.suffix.lower() in SKIP_SUFFIXES:
        return True
    if "storage" in parts and "sessions" in parts and rel.suffix == ".sess":
        return True
    return False


def sftp_mkdirs(sftp: paramiko.SFTPClient, remote_dir: str) -> None:
    remote_dir = remote_dir.replace("\\", "/")
    if remote_dir in ("", "/"):
        return
    parts = remote_dir.split("/")
    built = ""
    for part in parts:
        if part == "":
            built = "/"
            continue
        built = posixpath.join(built, part) if built != "/" else "/" + part
        try:
            sftp.stat(built)
        except OSError:
            sftp.mkdir(built)


def upload_tree(sftp: paramiko.SFTPClient, local_root: Path, remote_root: str) -> int:
    count = 0
    for path in local_root.rglob("*"):
        rel = path.relative_to(local_root)
        if should_skip(rel):
            continue
        remote = posixpath.join(remote_root, rel.as_posix())
        if path.is_dir():
            sftp_mkdirs(sftp, remote)
            continue
        sftp_mkdirs(sftp, posixpath.dirname(remote))
        sftp.put(str(path), remote)
        count += 1
    return count


def write_remote_env(sftp: paramiko.SFTPClient, remote_root: str) -> None:
    db_host = env("DB_HOST", "127.0.0.1")
    db_port = env("DB_PORT", "3306")
    db_name = env("DB_NAME", "u899628465_Clearance_2027")
    db_user = env("DB_USER", "u899628465_Clearance_2027")
    db_password = env("DB_PASSWORD")
    if not db_password:
        print("Set DB_PASSWORD for remote .env", file=sys.stderr)
        sys.exit(1)

    app_env = env("APP_ENV", "production")
    app_debug = env("APP_DEBUG", "0")
    app_base = env("APP_BASE_URL", "")

    lines = [
        f"DB_HOST={db_host}",
        f"DB_PORT={db_port}",
        f"DB_NAME={db_name}",
        f"DB_USER={db_user}",
        f"DB_PASSWORD={db_password}",
        "",
        f"APP_ENV={app_env}",
        f"APP_DEBUG={app_debug}",
        f"APP_BASE_URL={app_base}",
        "APP_TRUST_PROXY=0",
        "",
    ]
    content = "\n".join(lines)
    remote_env = posixpath.join(remote_root, ".env")
    with sftp.open(remote_env, "w") as fh:
        fh.write(content)
    sftp.chmod(remote_env, stat.S_IRUSR | stat.S_IWUSR)


def chmod_storage(client: paramiko.SSHClient, remote_root: str) -> None:
    cmds = [
        f"chmod -R u+rwX {remote_root}/storage 2>/dev/null || true",
        f"mkdir -p {remote_root}/storage/uploads {remote_root}/storage/sessions",
        f"chmod -R 775 {remote_root}/storage/uploads {remote_root}/storage/sessions 2>/dev/null || true",
    ]
    for cmd in cmds:
        run(client, cmd)


def import_database(client: paramiko.SSHClient, remote_root: str) -> None:
    db_name = env("DB_NAME", "u899628465_Clearance_2027")
    db_user = env("DB_USER", "u899628465_Clearance_2027")
    db_password = env("DB_PASSWORD")
    if not db_password:
        print("Set DB_PASSWORD to import DB", file=sys.stderr)
        sys.exit(1)

    schema = posixpath.join(remote_root, "database/schema.sql")
    seed = posixpath.join(remote_root, "database/seed.sql")
    esc = db_password.replace("'", "'\\''")
    for label, file_path in (("schema", schema), ("seed", seed)):
        cmd = (
            f"mysql -u '{db_user}' -p'{esc}' '{db_name}' < '{file_path}'"
        )
        code, out, err = run(client, cmd)
        if code != 0:
            print(f"MySQL import {label} failed (code {code}):\n{err or out}", file=sys.stderr)
            sys.exit(1)
        print(f"Imported {label}.sql")


def create_zip(out_path: Path) -> int:
    count = 0
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in ROOT.rglob("*"):
            rel = path.relative_to(ROOT)
            if should_skip(rel):
                continue
            if path.is_dir():
                continue
            zf.write(path, rel.as_posix())
            count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Deploy CLEARANCE to Hostinger")
    parser.add_argument("--import-db", action="store_true", help="Run schema.sql + seed.sql on server")
    parser.add_argument("--pack-only", action="store_true", help="Build deploy zip only (no SSH)")
    parser.add_argument(
        "--zip",
        type=Path,
        default=ROOT / "clearance-hostinger-deploy.zip",
        help="Output zip path for --pack-only",
    )
    args = parser.parse_args()

    if args.pack_only:
        n = create_zip(args.zip)
        print(f"Packed {n} files -> {args.zip}")
        return

    client = connect_ssh()
    try:
        remote = detect_public_html(client)
        print(f"Remote document root: {remote}")

        sftp = client.open_sftp()
        try:
            sftp_mkdirs(sftp, remote)
            uploaded = upload_tree(sftp, ROOT, remote)
            write_remote_env(sftp, remote)
            print(f"Uploaded {uploaded} files")
        finally:
            sftp.close()

        chmod_storage(client, remote)

        if args.import_db:
            import_database(client, remote)

        code, out, _ = run(client, f"php -v 2>/dev/null | head -1")
        if out.strip():
            print(out.strip())

        print("Deploy finished. Open /health on your site to verify.")
    finally:
        client.close()


if __name__ == "__main__":
    main()
