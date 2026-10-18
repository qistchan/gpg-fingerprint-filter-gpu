#!/usr/bin/env python3
"""Run the CUDA vanity-key generator with isolated storage and verification."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from vanity_rules import compile_rules, matches


ALGORITHMS = (
    "rsa",
    "rsa2048",
    "rsa3072",
    "rsa4096",
    "nistp256",
    "nistp384",
    "nistp521",
    "ed25519",
    "cv25519",
)
INT32_MAX = 2**31 - 1
UINT32_MAX = 2**32 - 1
MAX_COUNT = 10_000
MAX_GPG_THREADS = 1_024
WEBHOOK_ENV = (
    "FEISHU_WEBHOOK_URL",
    "FEISHU_WEBHOOK_SECRET",
    "FEISHU_WEBHOOK_KEYWORD",
)
WEBHOOK_PREFIX = "/open-apis/bot/v2/hook/"


class RunnerError(RuntimeError):
    """A user-facing validation or runner error."""


class NotificationError(RuntimeError):
    """A sanitized notification failure."""


def _positive_int(value: str) -> int:
    try:
        number = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _optional_timeout(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return number


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe_path(path: Path) -> str:
    return str(path.expanduser().resolve())


def validate_webhook_url(value: str) -> str:
    """Validate a Feishu custom-bot URL without ever echoing it."""
    parsed = urlparse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "open.feishu.cn"
        or parsed.netloc != "open.feishu.cn"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith(WEBHOOK_PREFIX)
        or not parsed.path[len(WEBHOOK_PREFIX):]
    ):
        raise ValueError("invalid Feishu webhook URL")
    return value


def webhook_signature(timestamp: str, secret: str) -> str:
    key = f"{timestamp}\n{secret}".encode("utf-8")
    digest = hmac.new(key, b"", hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


class _NoRedirect(urlrequest.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise NotificationError("redirect")


class FeishuNotifier:
    """Small Feishu bot client with bounded retries and no secret in errors."""

    def __init__(
        self,
        url: str,
        secret: str = "",
        keyword: str = "",
        *,
        event: Any = None,
        opener: Any = None,
        clock: Callable[[], float] = time.monotonic,
        waiter: Callable[[float], bool] = time.sleep,
    ):
        self.url = validate_webhook_url(url)
        self.secret = secret
        self.keyword = keyword
        self.event = event
        self.opener = opener or urlrequest.build_opener(_NoRedirect)
        self.clock = clock
        self.waiter = waiter
        self.last_request = 0.0

    def _wait(self, delay: float, event: Any) -> bool:
        if delay <= 0:
            return not event or not event.is_set()
        if event:
            return not event.wait(delay)
        self.waiter(delay)
        return True

    def _throttle(self, event: Any) -> bool:
        delay = 1.0 - (self.clock() - self.last_request)
        if delay > 0 and not self._wait(delay, event):
            return False
        self.last_request = self.clock()
        return True

    def _payload(self, text: str, timestamp: str) -> bytes:
        payload: dict[str, Any] = {
            "msg_type": "text",
            "content": {"text": text},
        }
        if self.secret:
            payload["timestamp"] = timestamp
            payload["sign"] = webhook_signature(timestamp, self.secret)

        low = 0
        high = len(text)
        while low < high:
            middle = (low + high + 1) // 2
            payload["content"]["text"] = text[:middle]
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            if len(body) < 19_500:
                low = middle
            else:
                high = middle - 1
        payload["content"]["text"] = text[:low]
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        if len(body) >= 19_500:
            raise NotificationError("payload_too_large")
        return body

    def send(self, text: str, event: Any = None) -> str | None:
        event = self.event if event is None else event
        if self.keyword:
            text = f"{self.keyword} {text}"
        for attempt in range(3):
            if event and event.is_set():
                return "interrupted"
            if not self._throttle(event):
                return "interrupted"
            timestamp = str(int(time.time()))
            body = self._payload(text, timestamp)
            request = urlrequest.Request(
                self.url,
                data=body,
                headers={"Content-Type": "application/json; charset=utf-8"},
                method="POST",
            )
            try:
                with self.opener.open(request, timeout=5) as response:
                    status = response.getcode()
                    response_body = response.read(64 * 1024)
            except urlerror.HTTPError as exc:
                status = exc.code
                response_body = b""
            except (urlerror.URLError, TimeoutError, OSError, NotificationError):
                if attempt < 2 and self._wait(1.0 * (attempt + 1), event):
                    continue
                return "network"

            if status in (429,) or 500 <= status <= 599:
                if attempt < 2 and self._wait(1.0 * (attempt + 1), event):
                    continue
                return f"http_{status}"
            if status != 200:
                return f"http_{status}"

            try:
                response_json = json.loads(response_body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return "malformed_response"
            if not isinstance(response_json, dict):
                return "malformed_response"
            code = response_json.get("code")
            if code is None and "StatusCode" in response_json:
                code = response_json["StatusCode"]
            if isinstance(code, bool) or not isinstance(code, int):
                return "malformed_response"
            if code == 11232:
                if attempt < 2 and self._wait(1.0 * (attempt + 1), event):
                    continue
                return "rate_limited"
            if code != 0:
                return "business_error"
            return None
        return "notification_failed"

    def notify(self, text: str, event: Any = None) -> str | None:
        try:
            return self.send(text, event)
        except Exception:
            return "notification_error"


class NullNotifier:
    def notify(self, text: str, event: Any = None) -> None:
        return None


def make_notifier(event: Any = None) -> tuple[Any, list[str]]:
    url = os.environ.get("FEISHU_WEBHOOK_URL")
    if not url:
        return NullNotifier(), []
    try:
        notifier = FeishuNotifier(
            url,
            os.environ.get("FEISHU_WEBHOOK_SECRET", ""),
            os.environ.get("FEISHU_WEBHOOK_KEYWORD", ""),
            event=event,
        )
    except ValueError:
        return NullNotifier(), ["invalid_webhook"]
    return notifier, []


def _public_config(config: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in config.items()
        if key not in {"webhook_url", "webhook_secret", "webhook_keyword"}
    }


def _atomic_manifest(path: Path, manifest: dict[str, Any]) -> None:
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(temp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(manifest, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass
        raise


def _kill_group(process: subprocess.Popen, signum: int) -> None:
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        pass


def _stop_process(process: subprocess.Popen, signum: int) -> int:
    _kill_group(process, signum)
    try:
        return process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _kill_group(process, signal.SIGKILL)
        return process.wait()
    finally:
        _kill_group(process, signal.SIGKILL)


def _return_code(returncode: int | None, signal_number: int | None = None) -> int:
    if signal_number is not None:
        return 128 + signal_number
    if returncode is not None and returncode < 0:
        return 128 + (-returncode)
    return returncode if returncode is not None else 1


class ProcessInterrupted(Exception):
    def __init__(self, signum: int):
        self.signum = signum


class ProcessTimedOut(Exception):
    pass


class SignalController:
    def __init__(self):
        self.event = threading.Event()
        self.final_event: threading.Event | None = None
        self.signal_number: int | None = None
        self.process: subprocess.Popen | None = None
        self.old_handlers: dict[int, Any] = {}

    def _handle(self, signum: int, frame: Any) -> None:
        del frame
        if self.signal_number is None:
            self.signal_number = signum
            self.event.set()
        elif self.final_event is not None:
            self.final_event.set()
        process = self.process
        if process is not None:
            _kill_group(process, signum)

    def install(self) -> None:
        self.old_handlers = {
            signum: signal.getsignal(signum)
            for signum in (signal.SIGINT, signal.SIGTERM)
        }
        signal.signal(signal.SIGINT, self._handle)
        signal.signal(signal.SIGTERM, self._handle)

    def restore(self) -> None:
        for signum, handler in self.old_handlers.items():
            signal.signal(signum, handler)
        self.old_handlers.clear()

    def return_code(self) -> int:
        return 128 + (self.signal_number or signal.SIGINT)

    def final_notification_event(self) -> threading.Event:
        self.final_event = threading.Event()
        return self.final_event


def _run_child(
    command: list[str],
    *,
    env: dict[str, str],
    controller: SignalController,
    timeout: float | None,
    stdout: Any = subprocess.PIPE,
    stderr: Any = subprocess.PIPE,
    text: bool = True,
) -> subprocess.CompletedProcess:
    process = subprocess.Popen(
        command,
        stdout=stdout,
        stderr=stderr,
        env=env,
        text=text,
        start_new_session=True,
    )
    controller.process = process
    deadline = time.monotonic() + timeout if timeout is not None else None
    try:
        while True:
            if controller.event.is_set():
                raise ProcessInterrupted(
                    controller.signal_number or signal.SIGINT
                )
            remaining = deadline - time.monotonic() if deadline is not None else 0.1
            if deadline is not None and remaining <= 0:
                raise ProcessTimedOut()
            try:
                out, err = process.communicate(timeout=min(0.1, remaining))
            except subprocess.TimeoutExpired:
                continue
            if controller.event.is_set():
                raise ProcessInterrupted(
                    controller.signal_number or signal.SIGINT
                )
            return subprocess.CompletedProcess(command, process.returncode, out, err)
    except BaseException as exc:
        signum = (
            exc.signum if isinstance(exc, ProcessInterrupted) else signal.SIGTERM
        )
        _kill_group(process, signum)
        if process.poll() is None:
            _stop_process(process, signum)
        else:
            process.wait()
        raise
    finally:
        if process.poll() is None:
            _stop_process(process, signal.SIGTERM)
        else:
            process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        if controller.process is process:
            controller.process = None


def run_native(
    command: list[str],
    log_path: Path,
    *,
    timeout: float | None,
    controller: SignalController,
    gpu: str | None = None,
) -> tuple[int, str]:
    child_env = {
        key: value for key, value in os.environ.items() if key not in WEBHOOK_ENV
    }
    if gpu is not None:
        child_env["CUDA_VISIBLE_DEVICES"] = gpu
    with log_path.open("wb") as log:
        try:
            result = _run_child(
                command,
                env=child_env,
                controller=controller,
                timeout=timeout,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=False,
            )
        except ProcessInterrupted as exc:
            return 128 + exc.signum, "interrupted"
        except ProcessTimedOut:
            return _return_code(None, signal.SIGTERM), "timeout"
    if result.returncode == 0:
        return 0, "ok"
    return _return_code(result.returncode), "native_failure"


def verify_key(
    key_path: Path,
    homedir: Path,
    gpg_binary: str,
    controller: SignalController,
) -> str:
    child_env = {
        key: value for key, value in os.environ.items() if key not in WEBHOOK_ENV
    }
    child_env["GNUPGHOME"] = str(homedir)
    command = [
        gpg_binary,
        "--batch",
        "--no-options",
        "--homedir",
        str(homedir),
        "--with-colons",
        "--show-keys",
        str(key_path),
    ]
    try:
        result = _run_child(
            command,
            env=child_env,
            controller=controller,
            timeout=30,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except ProcessTimedOut as exc:
        raise RunnerError("gpg_timeout") from exc
    if result.returncode != 0:
        raise RunnerError("gpg_failure")
    primary_seen = False
    for line in result.stdout.splitlines():
        fields = line.split(":")
        if not fields:
            continue
        if fields[0] in {"pub", "sec"}:
            primary_seen = True
        elif fields[0] == "fpr" and primary_seen:
            fingerprint = fields[9] if len(fields) > 9 else ""
            if re.fullmatch(r"[0-9A-Fa-f]{40}", fingerprint):
                return fingerprint.upper()
            raise RunnerError("missing_fingerprint")
    raise RunnerError("missing_fingerprint")


def _write_key_modes(attempt_dir: Path) -> list[Path]:
    keys = sorted(
        path for path in attempt_dir.glob("*.gpg")
        if path.is_file()
    )
    for path in keys:
        os.chmod(path, 0o600)
    return keys


def _notify(
    notifier: Any,
    text: str,
    warnings: list[str],
    event: Any = None,
) -> None:
    category = notifier.notify(text, event)
    if category:
        warnings.append(category)
        print(f"警告：飞书通知失败（{category}）", file=sys.stderr)


def _error_category(exc: Exception) -> str:
    if isinstance(exc, RunnerError):
        category = str(exc)
        if re.fullmatch(r"[a-z0-9_]+", category):
            return category
        return "runner_error"
    if isinstance(exc, PermissionError):
        return "permission_error"
    if isinstance(exc, FileNotFoundError):
        return "file_not_found"
    if isinstance(exc, OSError):
        return "os_error"
    return "internal_error"


def _print_error(exc: Exception) -> None:
    category = _error_category(exc)
    descriptions = {
        "permission_error": "权限不足",
        "file_not_found": "文件或依赖不存在",
        "os_error": "系统调用失败",
    }
    print(
        f"错误：{descriptions.get(category, category)}（{category}）",
        file=sys.stderr,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the CUDA OpenPGP vanity-key generator safely."
    )
    parser.add_argument("--rule", action="append", default=[], metavar="TYPE:VALUE")
    parser.add_argument("--pattern", action="append", default=[], metavar="PATTERN")
    parser.add_argument("--data-dir", type=Path, default=Path("/data/gpg-vanity"))
    parser.add_argument(
        "--binary",
        type=Path,
        default=Path(__file__).with_name("gpg-fingerprint-filter-gpu"),
    )
    parser.add_argument("--algorithm", choices=ALGORITHMS, default="rsa")
    parser.add_argument("--count", type=_positive_int, default=1)
    parser.add_argument("--gpu")
    parser.add_argument("--threads-per-block", type=_positive_int, default=512)
    parser.add_argument(
        "--gpg-threads",
        type=_positive_int,
        default=min(max(os.cpu_count() or 1, 1), MAX_GPG_THREADS),
    )
    parser.add_argument("--time-offset", type=_positive_int, default=15_552_000)
    parser.add_argument("--base-time", type=int)
    parser.add_argument("--timeout", type=_optional_timeout)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def validate_args(args: argparse.Namespace, expanded: list[str]) -> dict[str, Any]:
    if args.count > MAX_COUNT:
        raise RunnerError(f"count must be between 1 and {MAX_COUNT}")
    if not 32 <= args.threads_per_block <= 1024 or args.threads_per_block % 32:
        raise RunnerError("threads-per-block must be a multiple of 32 from 32 to 1024")
    if not 1 <= args.gpg_threads <= MAX_GPG_THREADS:
        raise RunnerError(f"gpg-threads must be between 1 and {MAX_GPG_THREADS}")
    if not 1 <= args.time_offset <= INT32_MAX:
        raise RunnerError("time-offset must be within signed 32-bit range")
    if args.time_offset < args.threads_per_block:
        raise RunnerError("time-offset must be at least threads-per-block")
    if args.time_offset % args.threads_per_block:
        raise RunnerError("time-offset must be divisible by threads-per-block")
    base_time = int(time.time()) if args.base_time is None else args.base_time
    if not 0 <= base_time <= UINT32_MAX or base_time < args.time_offset:
        raise RunnerError("base-time must be uint32 and at least time-offset")
    if args.gpu is not None and not args.gpu:
        raise RunnerError("gpu must not be empty")
    return {
        "rules": list(args.rule),
        "patterns": list(args.pattern),
        "expanded_patterns": expanded,
        "binary": _safe_path(args.binary),
        "algorithm": args.algorithm,
        "count": args.count,
        "gpu": args.gpu,
        "threads_per_block": args.threads_per_block,
        "gpg_threads": args.gpg_threads,
        "time_offset": args.time_offset,
        "base_time": base_time,
        "timeout": args.timeout,
        "data_dir": _safe_path(args.data_dir),
    }


def _native_command(config: dict[str, Any], output_dir: Path) -> list[str]:
    return [
        config["binary"],
        "--algorithm",
        config["algorithm"],
        "--thread-per-block",
        str(config["threads_per_block"]),
        "--gpg-thread",
        str(config["gpg_threads"]),
        "--time-offset",
        str(config["time_offset"]),
        "--base-time",
        str(config["base_time"]),
        "|".join(config["expanded_patterns"]),
        str(output_dir),
    ]


def _json_dry_run(config: dict[str, Any]) -> None:
    output = dict(_public_config(config))
    output["command"] = _native_command(config, Path("<attempt-output-dir>"))
    print(json.dumps(output, ensure_ascii=False, indent=2))


def _create_job(data_dir: Path) -> tuple[Path, Path, Path, Path]:
    data_dir.mkdir(parents=True, exist_ok=True)
    for _ in range(20):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        job = data_dir / f"{stamp}-{secrets.token_hex(4)}"
        try:
            job.mkdir(mode=0o700)
            break
        except FileExistsError:
            continue
    else:
        raise RunnerError("could not allocate a unique job directory")
    keys = job / "keys"
    logs = job / "logs"
    homedir = job / "gnupg"
    keys.mkdir(mode=0o700)
    logs.mkdir(mode=0o700)
    homedir.mkdir(mode=0o700)
    return job, keys, logs, homedir


def execute(config: dict[str, Any]) -> int:
    controller = SignalController()
    controller.install()
    old_umask = os.umask(0o077)
    job: Path | None = None
    manifest_path: Path | None = None
    manifest: dict[str, Any] | None = None
    attempt: dict[str, Any] | None = None
    notifier: Any = NullNotifier()
    status = "failed"
    error_category = "internal_error"
    try:
        binary = Path(config["binary"])
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise RunnerError("binary_missing_or_not_executable")
        gpg_binary = shutil.which("gpg")
        if not gpg_binary:
            raise RunnerError("gpg_required")
        job, keys, logs, homedir = _create_job(Path(config["data_dir"]))
        manifest_path = job / "manifest.json"
        manifest: dict[str, Any] = {
            "version": 1,
            "status": "running",
            "started_at": _iso_now(),
            "config": _public_config(config),
            "attempts": [],
            "matches": [],
            "notification_warnings": [],
        }
        _atomic_manifest(manifest_path, manifest)
        print(f"任务目录：{job}")
        print(f"日志目录：{logs}")

        notifier, setup_warnings = make_notifier(controller.event)
        manifest["notification_warnings"].extend(setup_warnings)
        _atomic_manifest(manifest_path, manifest)
        if setup_warnings:
            print("警告：飞书 webhook 配置无效，已停用通知", file=sys.stderr)
        if controller.event.is_set():
            status = "interrupted"
        else:
            _notify(
                notifier,
                f"开始生成 vanity key：任务 {job.name}，规则 {','.join(config['expanded_patterns'])}",
                manifest["notification_warnings"],
            )
            _atomic_manifest(manifest_path, manifest)
            status = "interrupted" if controller.event.is_set() else "completed"

        while status == "completed":
            if len(manifest["attempts"]) >= config["count"]:
                break
            index = len(manifest["attempts"]) + 1
            if controller.event.is_set():
                status = "interrupted"
                break
            attempt_dir = keys / f"attempt-{index:05d}"
            attempt_dir.mkdir(mode=0o700)
            log_path = logs / f"attempt-{index:05d}.log"
            attempt = {
                "attempt": index,
                "status": "running",
                "started_at": _iso_now(),
                "log": str(log_path.relative_to(job)),
            }
            manifest["attempts"].append(attempt)
            _atomic_manifest(manifest_path, manifest)
            try:
                command = _native_command(config, attempt_dir)
                code, category = run_native(
                    command,
                    log_path,
                    timeout=config["timeout"],
                    controller=controller,
                    gpu=config["gpu"],
                )
                attempt["return_code"] = code
                attempt["finished_at"] = _iso_now()
                if category != "ok":
                    attempt["status"] = (
                        "interrupted" if category == "interrupted" else "failed"
                    )
                    attempt["error_category"] = category
                    _atomic_manifest(manifest_path, manifest)
                    if category == "interrupted":
                        status = "interrupted"
                    else:
                        status = "failed"
                        error_category = category
                        _notify(
                            notifier,
                            f"生成失败：任务 {job.name}，尝试 {index}，原因 {category}",
                            manifest["notification_warnings"],
                        )
                        _atomic_manifest(manifest_path, manifest)
                    break

                key_files = _write_key_modes(attempt_dir)
                if len(key_files) != 1 or key_files[0].stat().st_size == 0:
                    raise RunnerError("expected_one_key")
                fingerprint = verify_key(
                    key_files[0], homedir, gpg_binary, controller
                )
                matched = [
                    pattern for pattern in config["expanded_patterns"]
                    if matches(fingerprint, pattern)
                ]
                attempt["fingerprint"] = fingerprint
                attempt["key"] = str(key_files[0].relative_to(job))
                if not matched:
                    raise RunnerError("fingerprint_mismatch")
                attempt["matched_patterns"] = matched
                attempt["status"] = "found"
                attempt["finished_at"] = _iso_now()
                manifest["matches"].append({
                    "attempt": index,
                    "fingerprint": fingerprint,
                    "key": attempt["key"],
                    "matched_patterns": matched,
                })
                _atomic_manifest(manifest_path, manifest)
                _notify(
                    notifier,
                    f"找到 vanity key：任务 {job.name}，尝试 {index}，"
                    f"指纹 {fingerprint}，规则 {','.join(matched)}",
                    manifest["notification_warnings"],
                )
                _atomic_manifest(manifest_path, manifest)
                if controller.event.is_set():
                    status = "interrupted"
                    break
            except ProcessInterrupted as exc:
                attempt["status"] = "interrupted"
                attempt["error_category"] = "interrupted"
                attempt["return_code"] = 128 + exc.signum
                attempt["finished_at"] = _iso_now()
                status = "interrupted"
                _atomic_manifest(manifest_path, manifest)
                break
            except Exception as exc:
                error_category = _error_category(exc)
                attempt["status"] = "failed"
                attempt["error_category"] = error_category
                attempt["finished_at"] = _iso_now()
                status = "failed"
                _atomic_manifest(manifest_path, manifest)
                _print_error(exc)
                _notify(
                    notifier,
                    f"生成失败：任务 {job.name}，尝试 {index}，原因 {error_category}",
                    manifest["notification_warnings"],
                )
                _atomic_manifest(manifest_path, manifest)
                break

        if controller.event.is_set():
            status = "interrupted"
        elif status == "completed" and len(manifest["matches"]) != config["count"]:
            status = "failed"
            error_category = "incomplete_run"
        if status == "failed" and error_category == "internal_error":
            error_category = "generation_failed"
    except KeyboardInterrupt:
        controller.signal_number = controller.signal_number or signal.SIGINT
        controller.event.set()
        status = "interrupted"
    except Exception as exc:
        if controller.event.is_set():
            status = "interrupted"
        else:
            status = "failed"
            error_category = _error_category(exc)
            _print_error(exc)
            if attempt is not None and attempt.get("status") == "running":
                attempt["status"] = "failed"
                attempt["error_category"] = error_category
                attempt["finished_at"] = _iso_now()
    finally:
        try:
            process = controller.process
            if process is not None:
                if process.poll() is None:
                    _stop_process(
                        process,
                        controller.signal_number or signal.SIGTERM,
                    )
                else:
                    process.wait()
                controller.process = None
            if controller.event.is_set():
                status = "interrupted"
            if manifest is not None and manifest_path is not None:
                if attempt is not None and attempt.get("status") == "running":
                    attempt["status"] = (
                        "interrupted" if status == "interrupted" else "failed"
                    )
                    attempt["error_category"] = (
                        "interrupted" if status == "interrupted" else error_category
                    )
                    attempt["finished_at"] = _iso_now()
                manifest["status"] = status
                manifest["finished_at"] = _iso_now()
                _atomic_manifest(manifest_path, manifest)

                def send_final_interrupt() -> None:
                    nonlocal status
                    status = "interrupted"
                    manifest["status"] = status
                    manifest["finished_at"] = _iso_now()
                    _atomic_manifest(manifest_path, manifest)
                    final_event = controller.final_notification_event()
                    _notify(
                        notifier,
                        f"任务中断：{job.name}，已找到 {len(manifest['matches'])} 个匹配 key",
                        manifest["notification_warnings"],
                        final_event,
                    )
                    manifest["finished_at"] = _iso_now()
                    _atomic_manifest(manifest_path, manifest)

                if status == "interrupted":
                    send_final_interrupt()
                elif status == "completed":
                    _notify(
                        notifier,
                        f"任务完成：{job.name}，找到 {len(manifest['matches'])} 个匹配 key",
                        manifest["notification_warnings"],
                    )
                    if controller.event.is_set():
                        send_final_interrupt()
                    else:
                        _atomic_manifest(manifest_path, manifest)
                elif status == "failed":
                    _notify(
                        notifier,
                        f"任务失败：{job.name}，原因 {error_category}",
                        manifest["notification_warnings"],
                    )
                    if controller.event.is_set():
                        send_final_interrupt()
                    else:
                        _atomic_manifest(manifest_path, manifest)
                if controller.event.is_set() and status != "interrupted":
                    send_final_interrupt()
            elif controller.event.is_set():
                status = "interrupted"
        finally:
            controller.restore()
            os.umask(old_umask)
    if status == "interrupted":
        return controller.return_code()
    return 0 if status == "completed" else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        expanded = compile_rules(args.rule, args.pattern)
        config = validate_args(args, expanded)
        if args.dry_run:
            _json_dry_run(config)
            return 0
        return execute(config)
    except (RunnerError, ValueError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
