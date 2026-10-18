import contextlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from unittest import mock

import vanity


FINGERPRINT = "00000000000000000000000000000000DEADBEEF"
REPO_ROOT = Path(vanity.__file__).resolve().parent


def executable(path: Path, source: str) -> Path:
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    path.chmod(0o700)
    return path


def gpg_stub(fingerprint=FINGERPRINT, extra=""):
    return (
        "#!/usr/bin/env python3\n"
        f"{textwrap.dedent(extra)}\n"
        'print("sec:::::::::")\n'
        'print(":" .join(["fpr"] + [""] * 8 + ["'
        f"{fingerprint}"
        '", ""]))\n'
    )


class FakeResponse:
    def __init__(self, status=200, body=b'{"code": 0}'):
        self.status = status
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def getcode(self):
        return self.status

    def read(self, size=-1):
        return self.body


class FakeOpener:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        response = next(self.responses)
        if isinstance(response, BaseException):
            raise response
        return response


class RunnerTests(unittest.TestCase):
    def make_tools(self, directory: Path, native_source: str, gpg_source=None):
        directory.mkdir(parents=True, exist_ok=True)
        native = executable(directory / "native.py", native_source)
        gpg = executable(directory / "gpg", gpg_source or gpg_stub())
        return native, gpg

    def run_success(
        self,
        directory: Path,
        native_source: str,
        *extra,
        webhook_secret=None,
        webhook_url=None,
        gpg_source=None,
    ):
        native, gpg = self.make_tools(directory, native_source, gpg_source)
        data = directory / "data"
        with mock.patch.dict(os.environ, {}, clear=False), \
                mock.patch("vanity.shutil.which", return_value=str(gpg)):
            for key in vanity.WEBHOOK_ENV:
                os.environ.pop(key, None)
            if webhook_secret is not None:
                os.environ["FEISHU_WEBHOOK_SECRET"] = webhook_secret
            if webhook_url is not None:
                os.environ["FEISHU_WEBHOOK_URL"] = webhook_url
            result = vanity.main([
                "--binary", str(native),
                "--data-dir", str(data),
                "--pattern", "DEADBEEF",
                *extra,
            ])
        jobs = list(data.iterdir())
        self.assertEqual(len(jobs), 1)
        manifest = json.loads((jobs[0] / "manifest.json").read_text())
        return result, jobs[0], manifest

    def test_dry_run_does_not_check_tools_or_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "not-created"
            with mock.patch("vanity.shutil.which", side_effect=AssertionError):
                with contextlib.redirect_stdout(io_string := io.StringIO()):
                    result = vanity.main([
                        "--dry-run", "--binary", str(Path(tmp) / "missing"),
                        "--data-dir", str(data), "--pattern", "DEADBEEF",
                    ])
            self.assertEqual(result, 0)
            self.assertEqual(
                json.loads(io_string.getvalue())["expanded_patterns"], ["DEADBEEF"]
            )
            self.assertFalse(data.exists())

    def test_cli_dry_run_accepts_rule_only_and_repeated_patterns(self):
        for args, expected in (
            (["--rule", "suffix:DEADBEEF"], ["DEADBEEF"]),
            (
                ["--pattern", "DEADBEEF", "--pattern", "AAAA"],
                ["DEADBEEF", "AAAA"],
            ),
        ):
            with self.subTest(args=args), contextlib.redirect_stdout(
                io_string := io.StringIO()
            ):
                self.assertEqual(vanity.main(["--dry-run", *args]), 0)
                payload = json.loads(io_string.getvalue())
                self.assertEqual(payload["expanded_patterns"], expected)
                self.assertEqual(payload["patterns"], args[1::2] if args[0] == "--pattern" else [])

    def test_cli_dry_run_rejects_no_rules_or_patterns(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(vanity.main(["--dry-run"]), 2)

    def test_success_verifies_fingerprint_and_uses_private_storage(self):
        native_source = """\
        #!/usr/bin/env python3
        from pathlib import Path
        import os
        out = Path(os.sys.argv[-1])
        (out / "result.gpg").write_bytes(b"disposable")
        print(os.environ.get("FEISHU_WEBHOOK_SECRET", "missing"))
        """
        with tempfile.TemporaryDirectory() as tmp:
            result, job, manifest = self.run_success(
                Path(tmp), native_source, "--count", "2",
                webhook_secret="do-not-leak",
            )
            self.assertEqual(result, 0)
            self.assertEqual(manifest["status"], "completed")
            self.assertEqual(len(manifest["matches"]), 2)
            for attempt in manifest["attempts"]:
                self.assertEqual(attempt["fingerprint"], FINGERPRINT)
                key = job / attempt["key"]
                self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((job / "manifest.json").stat().st_mode), 0o600)
            log = (job / "logs" / "attempt-00001.log").read_text()
            self.assertNotIn("do-not-leak", log)

    def test_gpu_is_applied_only_to_child_and_inherited_when_omitted(self):
        native_source = """\
        #!/usr/bin/env python3
        from pathlib import Path
        import os, sys
        (Path(sys.argv[-1]) / "result.gpg").write_bytes(b"key")
        print(os.environ.get("CUDA_VISIBLE_DEVICES", "unset"))
        """
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ, {"CUDA_VISIBLE_DEVICES": "7"}
        ):
            root = Path(tmp)
            result, job, _ = self.run_success(
                root / "explicit", native_source, "--gpu", "2"
            )
            self.assertEqual(result, 0)
            self.assertIn("2", (job / "logs/attempt-00001.log").read_text())
            self.assertEqual(os.environ["CUDA_VISIBLE_DEVICES"], "7")

            result, job, _ = self.run_success(root / "inherited", native_source)
            self.assertEqual(result, 0)
            self.assertIn("7", (job / "logs/attempt-00001.log").read_text())
            self.assertEqual(os.environ["CUDA_VISIBLE_DEVICES"], "7")

    def test_native_failure_preserves_failed_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, job, manifest = self.run_success(
                Path(tmp),
                """\
                #!/usr/bin/env python3
                raise SystemExit(7)
                """,
            )
            self.assertEqual(result, 1)
            self.assertEqual(manifest["status"], "failed")
            self.assertEqual(manifest["attempts"][0]["error_category"], "native_failure")
            self.assertEqual(manifest["attempts"][0]["return_code"], 7)
            self.assertTrue((job / "logs" / "attempt-00001.log").exists())

    def test_missing_output_mismatch_and_gpg_failure_never_record_a_match(self):
        cases = (
            (
                "missing_output",
                """\
                #!/usr/bin/env python3
                """,
                gpg_stub(),
                "expected_one_key",
            ),
            (
                "mismatch",
                """\
                #!/usr/bin/env python3
                from pathlib import Path
                import sys
                (Path(sys.argv[-1]) / "result.gpg").write_bytes(b"key")
                """,
                gpg_stub("A" * 40),
                "fingerprint_mismatch",
            ),
            (
                "gpg_failure",
                """\
                #!/usr/bin/env python3
                from pathlib import Path
                import sys
                (Path(sys.argv[-1]) / "result.gpg").write_bytes(b"key")
                """,
                "#!/usr/bin/env python3\nraise SystemExit(8)\n",
                "gpg_failure",
            ),
        )
        for name, native_source, gpg_source, category in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                result, _, manifest = self.run_success(
                    Path(tmp), native_source, gpg_source=gpg_source
                )
                self.assertEqual(result, 1)
                self.assertEqual(manifest["status"], "failed")
                self.assertEqual(manifest["matches"], [])
                self.assertEqual(manifest["attempts"][0]["status"], "failed")
                self.assertEqual(
                    manifest["attempts"][0]["error_category"], category
                )

    def test_timeout_and_time_offset_validation(self):
        for timeout in ("nan", "inf", "-inf", "-1"):
            with self.subTest(timeout=timeout), contextlib.redirect_stderr(
                io.StringIO()
            ):
                with self.assertRaises(SystemExit) as raised:
                    vanity.main(["--dry-run", "--pattern", "A", "--timeout", timeout])
                self.assertEqual(raised.exception.code, 2)
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "data"
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    vanity.main([
                        "--dry-run", "--pattern", "A", "--data-dir", str(data),
                        "--time-offset", "513",
                    ]),
                    2,
                )
            self.assertFalse(data.exists())

    def test_cancel_terminates_native_process_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = executable(
                Path(tmp) / "sleep.py",
                """\
                #!/usr/bin/env python3
                import time
                time.sleep(30)
                """,
            )
            controller = vanity.SignalController()
            timer = threading.Timer(0.1, controller.event.set)
            timer.start()
            try:
                code, category = vanity.run_native(
                    [str(script), "ignored"],
                    Path(tmp) / "cancel.log",
                    timeout=None,
                    controller=controller,
                )
            finally:
                timer.join()
            self.assertEqual(category, "interrupted")
            self.assertEqual(code, 130)
            self.assertIsNone(controller.process)

    def test_unexpected_exception_reaps_child_before_clearing_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = executable(
                Path(tmp) / "sleep.py",
                "#!/usr/bin/env python3\nimport time\ntime.sleep(30)\n",
            )
            original_popen = subprocess.Popen
            children = []

            def failing_popen(*args, **kwargs):
                process = original_popen(*args, **kwargs)
                process.communicate = mock.Mock(side_effect=RuntimeError("boom"))
                children.append(process)
                return process

            controller = vanity.SignalController()
            with mock.patch("vanity.subprocess.Popen", side_effect=failing_popen):
                with self.assertRaisesRegex(RuntimeError, "boom"):
                    vanity._run_child(
                        [str(script)],
                        env=os.environ.copy(),
                        controller=controller,
                        timeout=10,
                    )
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].poll())
            self.assertIsNone(controller.process)

    def test_unexpected_attempt_error_is_persisted_and_sanitized(self):
        native_source = "#!/usr/bin/env python3\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            native, gpg = self.make_tools(root, native_source)
            with mock.patch("vanity.shutil.which", return_value=str(gpg)), \
                    mock.patch(
                        "vanity.run_native",
                        side_effect=PermissionError("/private/path/secret"),
                    ), \
                    contextlib.redirect_stderr(io_string := io.StringIO()):
                result = vanity.main([
                    "--binary", str(native),
                    "--data-dir", str(root / "data"),
                    "--pattern", "DEADBEEF",
                ])
            self.assertEqual(result, 1)
            job = next((root / "data").iterdir())
            manifest = json.loads((job / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "failed")
            self.assertEqual(manifest["attempts"][0]["status"], "failed")
            self.assertEqual(
                manifest["attempts"][0]["error_category"], "permission_error"
            )
            self.assertIn("权限不足", io_string.getvalue())
            self.assertNotIn("/private/path/secret", io_string.getvalue())

    def _run_signaled_wrapper(self, tmp: Path, *, sleeping_stage: str):
        tools = tmp / "tools"
        tools.mkdir()
        marker = tmp / "started"
        if sleeping_stage == "native":
            native_source = """\
            #!/usr/bin/env python3
            import os, sys, time
            from pathlib import Path
            Path(os.environ["STAGE_MARKER"]).write_text("native")
            time.sleep(30)
            """
            gpg_source = gpg_stub()
        else:
            native_source = """\
            #!/usr/bin/env python3
            import sys
            from pathlib import Path
            (Path(sys.argv[-1]) / "result.gpg").write_bytes(b"key")
            """
            gpg_source = gpg_stub(extra='''\
                import os, time
                from pathlib import Path
                Path(os.environ["STAGE_MARKER"]).write_text("gpg")
                time.sleep(30)
                ''')
        native, gpg = self.make_tools(tools, native_source, gpg_source)
        data = tmp / "data"
        env = os.environ.copy()
        env["PATH"] = f"{tools}{os.pathsep}{env.get('PATH', '')}"
        env["STAGE_MARKER"] = str(marker)
        env.pop("FEISHU_WEBHOOK_URL", None)
        env.pop("FEISHU_WEBHOOK_SECRET", None)
        env.pop("FEISHU_WEBHOOK_KEYWORD", None)
        process = subprocess.Popen(
            [
                sys.executable,
                str(REPO_ROOT / "vanity.py"),
                "--binary", str(native),
                "--data-dir", str(data),
                "--pattern", "DEADBEEF",
            ],
            cwd=REPO_ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 5
        while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        if not marker.exists():
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=8)
            self.fail(f"stage did not start: {stdout}\n{stderr}")
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=8)
        self.assertEqual(process.returncode, 128 + signal.SIGTERM, (stdout, stderr))
        job_dirs = list(data.iterdir())
        self.assertEqual(len(job_dirs), 1)
        manifest = json.loads((job_dirs[0] / "manifest.json").read_text())
        self.assertEqual(manifest["status"], "interrupted")
        self.assertEqual(manifest["matches"], [])
        self.assertEqual(manifest["attempts"][0]["status"], "interrupted")
        self.assertEqual(manifest["attempts"][0]["error_category"], "interrupted")
        return manifest

    def test_sigterm_during_native_is_bounded_and_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._run_signaled_wrapper(Path(tmp), sleeping_stage="native")

    def test_sigterm_during_gpg_is_bounded_and_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._run_signaled_wrapper(Path(tmp), sleeping_stage="gpg")

    def test_interrupted_notification_is_sent_after_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            native, gpg = self.make_tools(root, "#!/usr/bin/env python3\n")
            opener = FakeOpener([FakeResponse(), FakeResponse()])
            def notifier_factory(event):
                return vanity.FeishuNotifier(
                    "https://open.feishu.cn/open-apis/bot/v2/hook/token",
                    opener=opener,
                    event=event,
                    clock=lambda: 100.0,
                    waiter=lambda _: None,
                ), []

            def interrupted_native(*args, controller, **kwargs):
                controller.signal_number = signal.SIGTERM
                controller.event.set()
                return 128 + signal.SIGTERM, "interrupted"

            config = {
                "binary": str(native),
                "data_dir": str(root / "data"),
                "expanded_patterns": ["DEADBEEF"],
                "rules": [],
                "patterns": ["DEADBEEF"],
                "algorithm": "rsa",
                "count": 1,
                "gpu": None,
                "threads_per_block": 512,
                "gpg_threads": 1,
                "time_offset": 15_552_000,
                "base_time": 1_700_000_000,
                "timeout": None,
            }
            with mock.patch("vanity.shutil.which", return_value=str(gpg)), \
                mock.patch("vanity.make_notifier", side_effect=notifier_factory), \
                    mock.patch("vanity.run_native", side_effect=interrupted_native):
                result = vanity.execute(config)
            self.assertEqual(result, 128 + signal.SIGTERM)
            self.assertEqual(len(opener.requests), 2)
            final_payload = json.loads(opener.requests[-1][0].data)
            self.assertIn("任务中断", final_payload["content"]["text"])
            job = next((root / "data").iterdir())
            manifest = json.loads((job / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "interrupted")
            self.assertNotIn(
                "-----BEGIN PGP PRIVATE KEY BLOCK-----",
                final_payload["content"]["text"],
            )

    def test_sigterm_during_completion_notification_returns_signal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            native, gpg = self.make_tools(
                root,
                """\
                #!/usr/bin/env python3
                from pathlib import Path
                import sys
                (Path(sys.argv[-1]) / "result.gpg").write_bytes(b"key")
                """,
            )

            class SignalingNotifier:
                def __init__(self):
                    self.messages = []

                def notify(self, text, event=None):
                    self.messages.append(text)
                    if text.startswith("任务完成"):
                        os.kill(os.getpid(), signal.SIGTERM)

            notifier = SignalingNotifier()
            config = {
                "binary": str(native),
                "data_dir": str(root / "data"),
                "expanded_patterns": ["DEADBEEF"],
                "rules": [],
                "patterns": ["DEADBEEF"],
                "algorithm": "rsa",
                "count": 1,
                "gpu": None,
                "threads_per_block": 512,
                "gpg_threads": 1,
                "time_offset": 15_552_000,
                "base_time": 1_700_000_000,
                "timeout": None,
            }
            with mock.patch("vanity.shutil.which", return_value=str(gpg)), \
                    mock.patch("vanity.make_notifier", return_value=(notifier, [])):
                result = vanity.execute(config)
            self.assertEqual(result, 128 + signal.SIGTERM)
            self.assertTrue(any(message.startswith("任务中断") for message in notifier.messages))
            job = next((root / "data").iterdir())
            manifest = json.loads((job / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "interrupted")
            self.assertEqual(len(manifest["matches"]), 1)

    def test_invalid_webhook_warning_is_printed_and_persisted(self):
        native_source = """\
        #!/usr/bin/env python3
        from pathlib import Path
        import sys
        (Path(sys.argv[-1]) / "result.gpg").write_bytes(b"key")
        """
        with tempfile.TemporaryDirectory() as tmp, \
                contextlib.redirect_stderr(io_string := io.StringIO()):
            result, _, manifest = self.run_success(
                Path(tmp), native_source, webhook_url="https://evil.example"
            )
        self.assertEqual(result, 0)
        self.assertIn("invalid_webhook", manifest["notification_warnings"])
        self.assertIn("配置无效", io_string.getvalue())

    def test_rule_and_numeric_validation_happens_before_storage(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "data"
            with contextlib.redirect_stderr(io.StringIO()):
                result = vanity.main([
                    "--data-dir", str(data), "--pattern", "DEADBEEF",
                    "--threads-per-block", "33",
                ])
            self.assertEqual(result, 2)
            self.assertFalse(data.exists())


class FeishuTests(unittest.TestCase):
    def notifier(self, responses, *, keyword=""):
        opener = FakeOpener(responses)
        notifier = vanity.FeishuNotifier(
            "https://open.feishu.cn/open-apis/bot/v2/hook/token",
            "test-secret",
            keyword,
            opener=opener,
            clock=lambda: 100.0,
            waiter=lambda _: None,
        )
        return notifier, opener

    def test_signature_and_payload(self):
        notifier, opener = self.notifier([FakeResponse()])
        with mock.patch("vanity.time.time", return_value=1234567890):
            self.assertIsNone(notifier.send("hello"))
        request, timeout = opener.requests[0]
        payload = json.loads(request.data)
        self.assertEqual(timeout, 5)
        self.assertEqual(payload["sign"], "qCaOcLimil1ehZl6GzN2CUL6wgdt4onZPxvw8V+3TzA=")
        self.assertEqual(payload["content"]["text"], "hello")

    def test_payload_byte_limit_with_multibyte_keyword_and_controls(self):
        keyword = "通知\x01" * 12_000
        notifier, opener = self.notifier([FakeResponse()], keyword=keyword)
        self.assertIsNone(notifier.send("内容\x02" * 12_000))
        request, _ = opener.requests[0]
        self.assertLess(len(request.data), 20_000)
        text = json.loads(request.data)["content"]["text"]
        self.assertTrue(text.startswith(keyword[:len(text)]))

    def test_boolean_response_code_is_malformed(self):
        notifier, _ = self.notifier([FakeResponse(body=b'{"code":false}')])
        self.assertEqual(notifier.send("bad"), "malformed_response")

    def test_rate_limit_retries_and_business_errors_do_not_raise(self):
        notifier, opener = self.notifier([
            FakeResponse(body=b'{"code":11232}'),
            FakeResponse(body=b'{"StatusCode":0}'),
        ])
        self.assertIsNone(notifier.send("retry"))
        self.assertEqual(len(opener.requests), 2)

        notifier, _ = self.notifier([FakeResponse(body=b'{"code":1234}')])
        self.assertEqual(notifier.send("bad"), "business_error")

        notifier, _ = self.notifier([FakeResponse(body=b"not-json")])
        self.assertEqual(notifier.send("bad"), "malformed_response")

    def test_http_retries(self):
        notifier, opener = self.notifier([
            FakeResponse(status=429),
            FakeResponse(status=503),
            FakeResponse(),
        ])
        self.assertIsNone(notifier.send("retry"))
        self.assertEqual(len(opener.requests), 3)

    def test_network_failure_is_sanitized(self):
        notifier, _ = self.notifier([
            vanity.urlerror.URLError("secret-token"),
            vanity.urlerror.URLError("secret-token"),
            vanity.urlerror.URLError("secret-token"),
        ])
        self.assertEqual(notifier.send("bad"), "network")

    def test_redirect_and_url_validation(self):
        with self.assertRaises(ValueError):
            vanity.validate_webhook_url("https://evil.example/hook")
        opener = FakeOpener([
            vanity.NotificationError("redirect"),
            vanity.NotificationError("redirect"),
            vanity.NotificationError("redirect"),
        ])
        notifier = vanity.FeishuNotifier(
            "https://open.feishu.cn/open-apis/bot/v2/hook/token",
            opener=opener,
            clock=lambda: 100.0,
            waiter=lambda _: None,
        )
        self.assertEqual(notifier.send("redirect"), "network")


if __name__ == "__main__":
    unittest.main()
