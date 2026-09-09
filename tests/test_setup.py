"""Guided setup, workspace, readiness, and bounded model-context tests."""

from __future__ import annotations

import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import __version__, cli, completion, configuration, core, model_context, providers


class SetupTests(unittest.TestCase):
    def test_workspace_is_created_and_persisted_without_system_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TACU_HOME": directory}):
            chosen = configuration.save_workspace(Path(directory) / "my-project")
            self.assertTrue(chosen.is_dir())
            self.assertEqual(configuration.configured_workspace(), chosen)
            self.assertEqual(json.loads(configuration.config_path().read_text())["workspace"], str(chosen))

    def test_workspace_rejects_filesystem_and_system_directories(self) -> None:
        with self.assertRaises(core.TacuError):
            configuration.save_workspace(Path(Path.cwd().anchor))
        protected = Path("C:/Windows") if os.name == "nt" else Path("/usr/local")
        with self.assertRaises(core.TacuError):
            configuration.save_workspace(protected)

    def test_readiness_applies_ram_disk_and_exact_model_requirements(self) -> None:
        models = set(configuration.required_models())
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TACU_HOME": directory}), \
             patch("tacu.configuration.physical_memory_gb", return_value=32.0), \
             patch("tacu.configuration.shutil.disk_usage", return_value=SimpleNamespace(free=80 * 1024**3)), \
             patch("tacu.configuration.shutil.which", side_effect=lambda name: "/bin/" + name), \
             patch("tacu.configuration.ollama_models", return_value=models), \
             patch("tacu.configuration.docker_available", return_value=True), \
             patch("tacu.configuration.searxng_image_present", return_value=True), \
             patch("tacu.configuration.searxng_container_running", return_value=True), \
             patch("tacu.configuration.ollama_mlx_supported", return_value=True), \
             patch("tacu.configuration.subprocess.run") as run:
            run.return_value.stdout = "ollama version 1.0\n"
            configuration.save_workspace(Path(directory) / "project")
            report = configuration.readiness()
        self.assertTrue(report.prerequisites_ok)
        self.assertTrue(report.ready)
        self.assertEqual(set(report.required_models), models)
        self.assertEqual(report.disk_required_gb, configuration.MIN_DISK_GB_READY)

    def test_disk_floor_is_40_until_ollama_docker_and_gemma_exist(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TACU_HOME": directory}), \
             patch("tacu.configuration.physical_memory_gb", return_value=32.0), \
             patch("tacu.configuration.shutil.disk_usage", return_value=SimpleNamespace(free=25 * 1024**3)), \
             patch("tacu.configuration.shutil.which", side_effect=lambda name: "/bin/" + name if name != "docker" else None), \
             patch("tacu.configuration.ollama_models", return_value=set()), \
             patch("tacu.configuration.docker_available", return_value=False), \
             patch("tacu.configuration.searxng_image_present", return_value=False), \
             patch("tacu.configuration.ollama_mlx_supported", return_value=False), \
             patch("tacu.configuration.subprocess.run") as run:
            run.return_value.stdout = "ollama version 1.0\n"
            configuration.save_workspace(Path(directory) / "project")
            report = configuration.readiness()
        self.assertEqual(report.disk_required_gb, configuration.MIN_DISK_GB_FULL)
        self.assertFalse(report.disk_ok)
        self.assertFalse(report.ready)

    def test_readiness_is_ready_when_only_the_backup_chat_model_is_installed(self) -> None:
        backup = {configuration.BACKUP_MODEL}
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TACU_HOME": directory}), \
             patch("tacu.configuration.physical_memory_gb", return_value=32.0), \
             patch("tacu.configuration.shutil.disk_usage", return_value=SimpleNamespace(free=80 * 1024**3)), \
             patch("tacu.configuration.shutil.which", side_effect=lambda name: "/bin/" + name), \
             patch("tacu.configuration.ollama_models", return_value=backup), \
             patch("tacu.configuration.docker_available", return_value=True), \
             patch("tacu.configuration.searxng_image_present", return_value=True), \
             patch("tacu.configuration.searxng_container_running", return_value=True), \
             patch("tacu.configuration.ollama_mlx_supported", return_value=True), \
             patch("tacu.configuration.subprocess.run") as run:
            run.return_value.stdout = "ollama version 1.0\n"
            configuration.save_workspace(Path(directory) / "project")
            report = configuration.readiness()
        self.assertTrue(report.ready)
        self.assertEqual(configuration.chosen_chat_model(backup), configuration.BACKUP_MODEL)

    def test_pull_models_installs_gemma_only_unless_a_preferred_model_exists(self) -> None:
        primary = configuration.default_chat_model()
        backup = configuration.BACKUP_MODEL
        with patch("tacu.configuration.ollama_models", return_value={backup}):
            results = configuration.pull_models()
        self.assertEqual(results, [(backup, True, "already installed · using as chat model (Gemma not pulled)")])
        pull = Mock(returncode=0)
        with patch("tacu.configuration.ollama_models", return_value=set()), \
             patch("tacu.configuration.subprocess.run", return_value=pull) as run:
            results = configuration.pull_models()
        self.assertEqual(results[0][0], primary)
        self.assertTrue(results[0][1])
        run.assert_called_once_with(["ollama", "pull", primary], check=False)
        with patch("tacu.configuration.ollama_models", return_value={primary, backup}), \
             patch("tacu.configuration.subprocess.run") as run:
            results = configuration.pull_models()
        self.assertEqual(results[0][0], primary)
        run.assert_not_called()

    def test_model_preference_is_persistent_and_preserves_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TACU_HOME": directory}):
            workspace = configuration.save_workspace(Path(directory) / "project")
            self.assertEqual(configuration.save_model("qwen2.5-coder:1.5b"), "qwen2.5-coder:1.5b")
            self.assertEqual(configuration.configured_model(), "qwen2.5-coder:1.5b")
            self.assertEqual(configuration.configured_workspace(), workspace)
            configuration.clear_model()
            self.assertIsNone(configuration.configured_model())
            self.assertEqual(configuration.configured_workspace(), workspace)

    def test_model_command_lists_selects_and_reports_saved_model(self) -> None:
        available = ["qwen2.5-coder:1.5b", "qwen2.5-coder:7b", "gemma4:e4b"]
        fake = SimpleNamespace(model="qwen2.5-coder:7b", models=lambda: available)
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"TACU_HOME": directory}, clear=False
        ), patch("tacu.cli.load_provider", return_value=fake):
            os.environ.pop("TACU_MODEL", None)
            selected = io.StringIO()
            with redirect_stdout(selected):
                self.assertEqual(cli.main(["model", "use", "qwen2.5-coder:1.5b"]), 0)
            self.assertEqual(configuration.configured_model(), "qwen2.5-coder:1.5b")
            current = io.StringIO()
            with redirect_stdout(current):
                self.assertEqual(cli.main(["model", "current"]), 0)
            self.assertIn("qwen2.5-coder:1.5b", current.getvalue())
            listed = io.StringIO()
            with redirect_stdout(listed):
                self.assertEqual(cli.main(["model", "list"]), 0)
            self.assertIn("fastest", listed.getvalue())
            self.assertIn("backup", listed.getvalue())

    def test_context_preference_is_persistent_and_preserves_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TACU_HOME": directory}):
            workspace = configuration.save_workspace(Path(directory) / "project")
            self.assertEqual(configuration.configured_context_turns(), 5)
            self.assertEqual(configuration.save_context_turns(2), 2)
            self.assertEqual(configuration.configured_context_turns(), 2)
            with self.assertRaises(core.TacuError):
                configuration.save_context_turns(101)
            configuration.clear_companion_preferences()
            self.assertEqual(configuration.configured_context_turns(), 5)
            self.assertEqual(configuration.configured_workspace(), workspace)

    def test_config_command_updates_and_shows_model_and_context(self) -> None:
        available = ["qwen2.5-coder:1.5b", "qwen2.5-coder:7b", "x/flux2-klein:4b"]
        fake = SimpleNamespace(model="qwen2.5-coder:7b", models=lambda: available)
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"TACU_HOME": directory}, clear=False
        ), patch("tacu.cli.load_provider", return_value=fake):
            os.environ.pop("TACU_MODEL", None)
            updated = io.StringIO()
            with redirect_stdout(updated):
                self.assertEqual(cli.main([
                    "config", "update", "--model", "qwen2.5-coder:1.5b",
                    "--context-turns", "3",
                ]), 0)
            self.assertEqual(configuration.configured_model(), "qwen2.5-coder:1.5b")
            self.assertEqual(configuration.configured_context_turns(), 3)
            shown = io.StringIO()
            with redirect_stdout(shown):
                self.assertEqual(cli.main(["config", "show"]), 0)
            self.assertIn("qwen2.5-coder:1.5b", shown.getvalue())
            self.assertIn("last 3 turn(s)", shown.getvalue())
            self.assertIn("last 100 turn(s)", shown.getvalue())

    def test_config_rejects_image_generation_model(self) -> None:
        fake = SimpleNamespace(model="qwen2.5-coder:7b", models=lambda: ["x/flux2-klein:4b"])
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"TACU_HOME": directory}, clear=False
        ), patch("tacu.cli.load_provider", return_value=fake), redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["config", "update", "--model", "x/flux2-klein:4b"]), 1)

    def test_cli_setup_can_prepare_workspace_without_downloads(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TACU_HOME": directory}), \
             redirect_stdout(io.StringIO()):
            result = cli.main(["setup", "--workspace", str(Path(directory) / "project"),
                               "--skip-models", "--skip-docker", "--force"])
            workspace = configuration.configured_workspace()
        self.assertEqual(result, 0)
        self.assertEqual(workspace.name, "project")

    def test_unix_installer_supports_safe_dry_run(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(["sh", str(root / "install.sh"), "--dry-run", "--skip-models", "--force",
                                     "--workspace", str(Path(directory) / "project")], cwd=root,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Setting up Ollama", result.stdout)
            self.assertIn("Python", result.stdout)
            self.assertIn("SearXNG", result.stdout)
            self.assertIn("Dry run complete", result.stdout)
            self.assertFalse((Path(directory) / "project").exists())

    @unittest.skipIf(os.name == "nt", "the POSIX installer is tested separately from Windows")
    def test_complete_unix_installation_prepares_required_model_without_network(self) -> None:
        project = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            fake_ollama = fake_bin / "ollama"
            fake_ollama.write_text(
                "#!/bin/sh\n"
                "case \"$1\" in\n"
                "  --version) printf 'ollama version 9.8.7\\n' ;;\n"
                "  list) printf 'NAME ID SIZE MODIFIED\\n'; "
                "if [ -f \"$TACU_FAKE_MODEL_STATE\" ]; then "
                "while IFS= read -r model; do printf '%s stub 1GB now\\n' \"$model\"; done "
                "< \"$TACU_FAKE_MODEL_STATE\"; fi ;;\n"
                "  pull) printf '%s\\n' \"$2\" >> \"$TACU_FAKE_MODEL_STATE\" ;;\n"
                "  *) exit 1 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_ollama.chmod(0o755)
            fake_docker = fake_bin / "docker"
            fake_docker.write_text(
                "#!/bin/sh\n"
                "case \"$1\" in\n"
                "  info) exit 0 ;;\n"
                "  image)\n"
                "    if [ \"$2\" = inspect ]; then\n"
                "      [ -f \"$TACU_FAKE_DOCKER_IMAGES\" ] || exit 1\n"
                "      grep -Fx \"$3\" \"$TACU_FAKE_DOCKER_IMAGES\" >/dev/null 2>&1\n"
                "      exit $?\n"
                "    fi\n"
                "    exit 1 ;;\n"
                "  pull) printf '%s\\n' \"$2\" >> \"$TACU_FAKE_DOCKER_IMAGES\"; exit 0 ;;\n"
                "  inspect)\n"
                "    name=$2\n"
                "    if [ \"$2\" = \"-f\" ]; then name=$4; fi\n"
                "    [ -f \"$TACU_FAKE_DOCKER_CONTAINERS\" ] || exit 1\n"
                "    grep -Fx \"$name\" \"$TACU_FAKE_DOCKER_CONTAINERS\" >/dev/null 2>&1 || exit 1\n"
                "    if [ \"$2\" = \"-f\" ]; then\n"
                "      case \"$3\" in\n"
                "        *Ports*) printf '%s\\n' '{\"8080/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"8080\"}]}' ;;\n"
                "        *Id*) printf 'abc\\n' ;;\n"
                "        *) printf 'true\\n' ;;\n"
                "      esac\n"
                "    fi\n"
                "    exit 0 ;;\n"
                "  start)\n"
                "    [ -f \"$TACU_FAKE_DOCKER_CONTAINERS\" ] || exit 1\n"
                "    grep -Fx \"$2\" \"$TACU_FAKE_DOCKER_CONTAINERS\" >/dev/null 2>&1\n"
                "    exit $? ;;\n"
                "  stop|rm) exit 0 ;;\n"
                "  run)\n"
                "    name=\"\"\n"
                "    prev=\"\"\n"
                "    for arg in \"$@\"; do\n"
                "      if [ \"$prev\" = \"--name\" ]; then name=$arg; fi\n"
                "      prev=$arg\n"
                "    done\n"
                "    [ -n \"$name\" ] || exit 1\n"
                "    printf '%s\\n' \"$name\" >> \"$TACU_FAKE_DOCKER_CONTAINERS\"\n"
                "    exit 0 ;;\n"
                "  *) exit 1 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_docker.chmod(0o755)
            state = root / "models"
            docker_images = root / "docker-images"
            docker_containers = root / "docker-containers"
            user_bin = root / "bin"
            environment = os.environ.copy()
            available_path = os.pathsep.join(
                item for item in environment["PATH"].split(os.pathsep) if not (Path(item) / "ti").exists()
            )
            environment.update({"TACU_HOME": str(root / "state"), "TACU_INSTALL_HOME": str(root / "runtime"),
                                "TACU_BIN_DIR": str(user_bin), "TACU_SHELL_PROFILE": str(root / "profile"),
                                "TACU_SHELL_RC": str(root / "zshrc"),
                                "TACU_FAKE_MODEL_STATE": str(state),
                                "TACU_FAKE_DOCKER_IMAGES": str(docker_images),
                                "TACU_FAKE_DOCKER_CONTAINERS": str(docker_containers),
                                "TACU_SEARXNG_WAIT": "0",
                                "PATH": str(fake_bin) + os.pathsep + str(user_bin) + os.pathsep + available_path})
            installed = subprocess.run(["sh", str(project / "install.sh"), "--force", "--workspace", str(root / "project")],
                                       cwd=project, env=environment, capture_output=True, text=True, timeout=90)
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
            self.assertEqual(set(state.read_text().splitlines()), {configuration.default_chat_model()})
            self.assertNotIn(configuration.BACKUP_MODEL, state.read_text().splitlines())
            self.assertIn(configuration.SEARXNG_IMAGE, docker_images.read_text().splitlines())
            self.assertIn(configuration.SEARXNG_CONTAINER, docker_containers.read_text().splitlines())
            checked = subprocess.run([str(user_bin / "ticu"), "doctor", "--json"], cwd=root, env=environment,
                                     capture_output=True, text=True, timeout=20)
            payload = json.loads(checked.stdout)
            self.assertTrue(payload["docker_installed"])
            self.assertTrue(payload["searxng_image"])
            self.assertTrue(payload["searxng_running"])
            # `ready` also gates on the host's own RAM and disk. A CI runner or a
            # small container legitimately sits below the 16 GB floor, so assert what
            # this installation controls and let doctor stay honest about hardware.
            if payload["ram_ok"] and payload["disk_ok"]:
                self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
                self.assertTrue(payload["ready"])
            else:
                self.assertFalse(payload["ready"], "doctor must not claim readiness below the floor")
            short = subprocess.run([str(user_bin / "ti"), "--version"], cwd=root, env=environment,
                                   capture_output=True, text=True, timeout=20)
            self.assertEqual(short.returncode, 0, short.stderr)
            self.assertIn(f"TACU {__version__}", short.stdout)

    def test_default_models_timeout_keep_alive_and_env_example(self) -> None:
        self.assertEqual(core.DEFAULT_TIMEOUT_SECONDS, 900)
        self.assertEqual(core.DEFAULT_KEEP_ALIVE, "15m")
        self.assertEqual(core.DEFAULT_BACKUP_MODEL, "qwen2.5-coder:7b")
        self.assertEqual(configuration.OLLAMA_PINNED_VERSION, "0.32.14")
        self.assertIn(configuration.BACKUP_MODEL, configuration.required_models())
        self.assertEqual(configuration.required_models()[0], configuration.default_chat_model())
        example = Path(__file__).resolve().parents[1] / ".env.example"
        self.assertTrue(example.is_file(), "ship .env.example so users can copy it to .env")
        text = example.read_text(encoding="utf-8")
        self.assertIn("gemma4:12b-mlx", text)
        self.assertIn("qwen2.5-coder:7b", text)
        self.assertIn("0.32.14", text)
        self.assertIn("TACU_KEEP_ALIVE=15m", text)
        self.assertIn("TACU_NUM_PREDICT=1024", text)
        self.assertIn("TACU_PYTHON_VERSION=3.14.7", text)
        self.assertIn("tacu-searxng", text)
        self.assertIn("8080", text)

    def test_searxng_url_prefers_env_then_saved_then_default_8080(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TACU_HOME": directory}, clear=False):
            os.environ.pop("TACU_SEARXNG_URL", None)
            with patch("tacu.configuration.searxng_published_url", return_value=None):
                self.assertEqual(configuration.searxng_url(), "http://127.0.0.1:8080")
            configuration.save_searxng_url("http://127.0.0.1:8087")
            self.assertEqual(configuration.searxng_url(), "http://127.0.0.1:8087")
            os.environ["TACU_SEARXNG_URL"] = "http://127.0.0.1:9999"
            try:
                self.assertEqual(configuration.searxng_url(), "http://127.0.0.1:9999")
            finally:
                os.environ.pop("TACU_SEARXNG_URL", None)

    def test_next_free_host_port_skips_a_bound_socket(self) -> None:
        occupied = socket.socket()
        occupied.bind(("127.0.0.1", 0))
        port = occupied.getsockname()[1]
        try:
            found = configuration.next_free_host_port(port, limit=5)
            self.assertNotEqual(found, port)
            self.assertGreaterEqual(found, port + 1)
        finally:
            occupied.close()

    def test_searxng_settings_include_a_real_secret_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TACU_HOME": directory}):
            path = configuration.searxng_settings_path()
            text = path.read_text(encoding="utf-8")
            self.assertIn("secret_key:", text)
            self.assertNotIn("ultrasecretkey", text)
            self.assertIn("json", text)
            again = configuration.searxng_settings_path().read_text(encoding="utf-8")
            self.assertEqual(text, again)

    def test_published_port_reads_docker_json(self) -> None:
        payload = json.dumps({"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8084"}]})
        with patch("tacu.configuration._docker_text", return_value=payload):
            self.assertEqual(configuration.searxng_published_port(), 8084)
        with patch("tacu.configuration._docker_text", return_value=json.dumps({"8080/tcp": None})):
            self.assertIsNone(configuration.searxng_published_port())

    def test_ensure_searxng_recreates_when_running_without_a_host_port(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"TACU_HOME": directory, "TACU_SEARXNG_WAIT": "0"}
        ):
            with patch("tacu.configuration.ensure_searxng_image", return_value=(True, "present")), \
                 patch("tacu.configuration.searxng_container_running", side_effect=[True, True]), \
                 patch("tacu.configuration.searxng_published_url", side_effect=[None, "http://127.0.0.1:8081"]), \
                 patch("tacu.configuration.next_free_host_port", return_value=8081), \
                 patch("tacu.configuration._remove_searxng_container") as remove, \
                 patch("tacu.configuration._run_searxng_container", return_value=(True, "")), \
                 patch("tacu.configuration._wait_searxng_http", return_value=True):
                ok, message = configuration.ensure_searxng_container()
            self.assertTrue(ok)
            remove.assert_called_once()
            self.assertIn("8081", message)
            self.assertEqual(configuration.configured_searxng_url(), "http://127.0.0.1:8081")

    def test_ensure_searxng_keeps_an_existing_published_port(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TACU_HOME": directory}):
            with patch("tacu.configuration.ensure_searxng_image", return_value=(True, "present")), \
                 patch("tacu.configuration.searxng_container_running", return_value=True), \
                 patch("tacu.configuration.searxng_published_url", return_value="http://127.0.0.1:8083"), \
                 patch("tacu.configuration._wait_searxng_http", return_value=True), \
                 patch("tacu.configuration._remove_searxng_container") as remove:
                ok, message = configuration.ensure_searxng_container()
            self.assertTrue(ok)
            remove.assert_not_called()
            self.assertIn("8083", message)

    def test_ollama_version_tuple_parses_release_numbers(self) -> None:
        with patch("tacu.configuration.ollama_version_text", return_value="Ollama 0.32.14"):
            self.assertEqual(configuration.ollama_version_tuple(), (0, 32, 14))
        with patch("tacu.configuration.ollama_version_text", return_value="ollama version 0.20.6"):
            self.assertLess(configuration.ollama_version_tuple(), configuration.OLLAMA_MLX_MIN_VERSION)

    def test_version_subcommand_matches_version_flag(self) -> None:
        outputs = []
        for arguments in (["version"], ["--version"]):
            output = io.StringIO()
            with redirect_stdout(output):
                if arguments == ["--version"]:
                    with self.assertRaises(SystemExit) as stopped:
                        cli.main(arguments)
                    self.assertEqual(stopped.exception.code, 0)
                else:
                    self.assertEqual(cli.main(arguments), 0)
            outputs.append(output.getvalue())
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[0].strip(), f"TACU {__version__}")

    def test_help_word_matches_help_flags_and_supports_topics(self) -> None:
        def rendered(arguments: list[str]) -> str:
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(cli.main(arguments), 0)
            return output.getvalue()

        self.assertEqual(rendered(["help"]), rendered(["--help"]))
        self.assertEqual(rendered(["help"]), rendered(["-h"]))
        quick = rendered(["help"])
        from tacu.theme import strip_ansi
        plain = strip_ansi(quick)
        # Quick help must stay scannable; every first-class command is listed.
        # Raised from 160 when worked examples were added under data, juicy and
        # tools: the overview shows how those commands are strung together, not
        # only their shape. The cap still guards against sprawl.
        self.assertLessEqual(plain.count("\n"), 185)
        self.assertIn("FINDINGS", plain)
        self.assertIn("ti juicy", plain)
        self.assertIn("ti extract juicy", plain)
        self.assertIn("ASK", plain)
        self.assertIn("AUTO", plain)
        self.assertIn("INSPECT", plain)
        self.assertIn("PICK ONE", plain)
        self.assertIn("PROGRESSIVE HELP", plain)
        self.assertIn("GHOST + TAB", plain)
        self.assertIn("ask", plain)
        self.assertIn("✨", plain)
        self.assertNotIn("ask AI", plain)
        self.assertNotIn("auto AI", plain)
        self.assertNotIn("run AI", plain)
        self.assertIn("ti auto which process is consuming most CPU", quick)
        self.assertIn("ti help ask", quick)
        self.assertIn("t a c u", plain)
        self.assertTrue(">_ " in plain or ">_" in plain)
        self.assertIn("ti all", quick)
        self.assertIn("tutorial", quick)
        self.assertIn("no model", quick.casefold())
        self.assertIn("execute, edit, or abort", quick)
        self.assertIn("|  e.g. ", quick)
        self.assertIn("shell-init zsh", quick)
        self.assertNotIn("TACU MIND MAP", quick)
        self.assertNotIn("positional arguments:", quick)
        topic = io.StringIO()
        with redirect_stdout(topic):
            self.assertEqual(cli.main(["help", "workspace"]), 0)
        self.assertIn("focused shell", topic.getvalue())
        workspace_help = strip_ansi(rendered(["workspace", "--help"]))
        self.assertIn("|  e.g. ", workspace_help)
        self.assertIn("ti workspace enter", workspace_help)
        self.assertIn("ti workspace create ~/Projects/Assessment", workspace_help)
        self.assertIn("Shape:", workspace_help)
        self.assertNotIn("positional arguments:", workspace_help)
        self.assertNotIn("usage: ticu workspace", workspace_help)
        self.assertEqual(workspace_help, strip_ansi(rendered(["help", "workspace"])))
        self.assertEqual(workspace_help, strip_ansi(rendered(["workspace", "create", "--help"])))
        docker_help = strip_ansi(rendered(["docker", "--help"]))
        self.assertIn("|  e.g. ", docker_help)
        self.assertIn("ti docker kali", docker_help)
        self.assertNotIn("positional arguments:", docker_help)
        extract_help = strip_ansi(rendered(["extract", "juicy", "--help"]))
        self.assertIn("ti extract juicy", extract_help)
        self.assertIn("ti juicy", extract_help)
        self.assertIn("|  e.g. ", extract_help)
        self.assertNotIn("positional arguments:", extract_help)
        juicy_help = strip_ansi(rendered(["juicy", "--help"]))
        self.assertIn("ti juicy", juicy_help)
        self.assertIn("confidence", juicy_help.casefold())
        save_help = strip_ansi(rendered(["save", "--help"]))
        self.assertIn("ti save 42 --format md", save_help)
        self.assertNotIn("positional arguments:", save_help)
        model_help = strip_ansi(rendered(["model", "use", "--help"]))
        self.assertIn("ti model use", model_help)
        self.assertNotIn("positional arguments:", model_help)
        run_help = strip_ansi(rendered(["help", "run"]))
        self.assertIn("ti run", run_help)
        self.assertIn("your command", run_help.casefold())
        self.assertIn("ti run -q", run_help)
        self.assertNotIn("positional arguments:", run_help)
        ask_help = strip_ansi(rendered(["help", "ask"]))
        self.assertIn("language only", ask_help.casefold())
        self.assertIn("ti ask", ask_help)
        clip_help = strip_ansi(rendered(["help", "clip"]))
        self.assertIn("clipboard tray", clip_help)
        self.assertIn("ti clip edit 3", clip_help)
        self.assertIn("refreshes its auto-generated label", clip_help)
        self.assertNotIn("positional arguments:", clip_help)
        health_help = strip_ansi(rendered(["help", "health"]))
        self.assertIn("health & config", health_help)
        self.assertIn("ti doctor", health_help)
        self.assertIn("ti config update", health_help)
        self.assertNotIn("positional arguments:", health_help)
        tools_help = strip_ansi(rendered(["tools"]))
        self.assertIn("ti tools map", tools_help)
        self.assertIn("directory tree", tools_help)
        self.assertIn("ti tools search TEXT [WHERE]", tools_help)
        self.assertNotIn("positional arguments:", tools_help)
        data_help = strip_ansi(rendered(["data", "--help"]))
        self.assertIn("ti data load FILE [--name NAME]", data_help)
        self.assertIn("dt1", data_help)
        self.assertIn("NAME|ID", data_help)
        self.assertIn("|  e.g. ", data_help)
        self.assertNotIn("positional arguments:", data_help)
        self.assertNotIn("usage: ticu data", data_help)
        data_load_help = strip_ansi(rendered(["data", "load", "--help"]))
        self.assertIn("ti data load FILE [--name NAME]", data_load_help)
        self.assertNotIn("positional arguments:", data_load_help)
        data_topic = strip_ansi(rendered(["help", "data"]))
        self.assertIn("--name NAME", data_topic)
        self.assertEqual(data_help, data_topic)
        review_help = strip_ansi(rendered(["help", "review"]))
        self.assertIn("ti review search", review_help)
        self.assertIn("retained turns", review_help.casefold())
        copy_help = strip_ansi(rendered(["help", "copy"]))
        self.assertIn("ti copy 42:3", copy_help)
        self.assertIn("L003", copy_help)
        clip_flag_help = strip_ansi(rendered(["clip", "--help"]))
        self.assertIn("clipboard tray", clip_flag_help)
        self.assertNotIn("Positional arguments:", clip_flag_help)
        error = io.StringIO()
        with patch("sys.stderr", new=error), self.assertRaises(SystemExit):
            cli.main(["not-a-command"])
        self.assertIn("Unknown command", error.getvalue())
        self.assertNotIn("choose from", error.getvalue())

    def test_tacu_help_adds_model_examples_and_static_help_stays_offline(self) -> None:
        from tacu.theme import strip_ansi

        with patch("tacu.cli.load_provider", return_value=object()), \
             patch("tacu.cli._chat_text", return_value="ti data load logs.csv --name logs") as chat:
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(cli.main(["tacu", "help", "data"]), 0)
            text = strip_ansi(output.getvalue())
            self.assertIn("EXAMPLES (local model)", text)
            self.assertIn("ti data load logs.csv", text)
            self.assertIn("ti data", text.casefold())
            self.assertIn("|  e.g. ", text)
            prompt = chat.call_args[0][1][0]["content"]
            self.assertIn("four fields", prompt)
            self.assertIn("|  e.g.", prompt)
            chat.assert_called_once()

        formatted = (
            "create | ti workspace create [DIR] | ti workspace create ~/lab "
            "| Makes a new workspace directory and selects it.\n"
            "enter | ti workspace enter | ti workspace enter "
            "| Opens a focused shell inside the selected workspace."
        )
        with patch("tacu.cli.load_provider", return_value=object()), \
             patch("tacu.cli._chat_text", return_value=formatted):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(cli.main(["tacu", "help", "workspace"]), 0)
            text = strip_ansi(output.getvalue())
            self.assertIn("EXAMPLES (local model)", text)
            self.assertIn("|  e.g. ti workspace create ~/lab", text)
            self.assertIn("Makes a new workspace directory", text)
            self.assertNotIn("positional arguments:", text)

        with patch("tacu.cli.load_provider", return_value=object()), \
             patch("tacu.cli._chat_text", return_value="ti tools search TODO .") as chat:
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(cli.main(["help", "tacu", "tools"]), 0)
            self.assertIn("EXAMPLES (local model)", strip_ansi(output.getvalue()))
            chat.assert_called_once()

        with patch("tacu.cli._chat_text") as chat:
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(cli.main(["help", "data"]), 0)
            self.assertNotIn("EXAMPLES (local model)", output.getvalue())
            chat.assert_not_called()

        error = io.StringIO()
        with patch("sys.stderr", new=error):
            self.assertEqual(cli.main(["help", "nonsense-topic"]), 2)
        self.assertIn("Unknown help topic", error.getvalue())

    def test_natural_queries_join_words_and_refuse_ambiguous_execution(self) -> None:
        self.assertEqual(
            cli.normalize_natural_queries(["ask", "explain", "the", '"zero trust"', "phrase"]),
            ["ask", "--", 'explain the "zero trust" phrase'],
        )
        self.assertEqual(
            cli.normalize_natural_queries(["ask", "what", "", "the subnet", "", "?"]),
            ["ask", "--", "what the subnet ?"],
        )
        self.assertEqual(
            cli.normalize_natural_queries(["analyze", "which", "ports", "matter"]),
            ["analyze", "--", "which ports matter"],
        )
        self.assertEqual(cli.parser().parse_args(["health"]).subcommand, "health")
        self.assertEqual(cli.parser().parse_args(["review", "--list"]).subcommand, "review")
        self.assertEqual(cli.parser().parse_args(["report", "--list"]).subcommand, "report")
        normalized = cli.normalize_natural_queries(
            ["run", "--shell", "-q", "summarize", "failed", "tests", "--", "make", "test"]
        )
        self.assertEqual(normalized, ["run", "--shell", "--question=summarize failed tests", "--", "make", "test"])
        parsed = cli.parser().parse_args(normalized)
        self.assertEqual(parsed.question, "summarize failed tests")
        self.assertEqual(core.normalized_command(parsed.command), ["make", "test"])
        unsafe_forms = (
            ["run", "-q", "summarize", "ifconfig"],
            ["run", "-q", "--", "ifconfig"],
            ["run", "-q", "summarize", "--"],
            ["run", "-q", "summarize", "--shell", "--", "make", "test"],
            ["docker", "kali", "-q", "explain", "output", "nmap"],
        )
        for unsafe in unsafe_forms:
            with self.subTest(unsafe=unsafe), self.assertRaises(core.TacuError):
                cli.normalize_natural_queries(unsafe)
        with patch("tacu.cli.run_command") as run, redirect_stdout(io.StringIO()),              patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(cli.main(["run", "-q", "summarize", "ifconfig"]), 2)
            run.assert_not_called()

    def test_activity_reports_start_detail_completion_and_elapsed_time(self) -> None:
        output = io.StringIO()
        with patch("sys.stderr", new=output):
            with cli.Activity("capturing output") as activity:
                activity.update("42 bytes captured")
                activity.complete("captured 42 bytes")
        rendered = output.getvalue()
        self.assertIn("capturing output", rendered)
        self.assertIn("captured 42 bytes", rendered)
        self.assertRegex(rendered, r"\d+\.\d+s")

    def test_keyboard_interrupt_returns_clean_tacu_termination(self) -> None:
        error = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TACU_HOME": directory}),              patch.object(sys.stdin, "isatty", return_value=True),              patch("tacu.cli.load_provider", return_value=SimpleNamespace(model="mock")),              patch("tacu.cli.ask", side_effect=KeyboardInterrupt), patch("sys.stderr", new=error):
            result = cli.main(["ask", "stop this request"])
        self.assertEqual(result, 130)
        self.assertIn("Stopped by you", error.getvalue())
        self.assertIn("No partial response was stored", error.getvalue())
        self.assertNotIn("Traceback", error.getvalue())

    def test_run_command_cleans_process_group_when_interrupted(self) -> None:
        process = SimpleNamespace(pid=4321, returncode=None)
        process.communicate = lambda **kwargs: (_ for _ in ()).throw(KeyboardInterrupt())
        process.poll = lambda: None
        with patch("tacu.core.subprocess.Popen", return_value=process),              patch("tacu.core._terminate_process") as terminate, self.assertRaises(KeyboardInterrupt):
            core.run_command(["long-tool"], shell=False, timeout=10)
        terminate.assert_called_once_with(process)

    def test_run_command_timeout_stops_group_and_returns_partial_evidence(self) -> None:
        process = SimpleNamespace(pid=4321, returncode=None)
        process.communicate = Mock(
            side_effect=[subprocess.TimeoutExpired(["slow-tool"], 1), (b"partial output", b"")]
        )
        with patch("tacu.core.subprocess.Popen", return_value=process),              patch("tacu.core._terminate_process") as terminate:
            result = core.run_command(["slow-tool"], shell=False, timeout=1)
        terminate.assert_called_once_with(process)
        self.assertEqual(result["result"]["exit_code"], 124)
        self.assertIn("partial output", core.evidence_text(result))
        self.assertIn("timed out after 1 seconds", core.evidence_text(result, "stderr"))

    def test_shell_init_activates_zsh_punctuation_without_query_quoting(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(cli.main(["shell-init", "zsh"]), 0)
        script = output.getvalue()
        self.assertIn("alias ti='noglob ti'", script)
        self.assertIn("alias ticu='noglob ticu'", script)
        self.assertIn("TACU_SHELL_INTEGRATION=1", script)
        self.assertIn("compdef _tacu ticu ti", script)
        self.assertIn("TACU_GHOST_EXAMPLES", script)
        self.assertIn("TACU_GHOST_NEXT", script)
        self.assertIn("setopt complete_aliases", script)
        self.assertIn("bindkey '^I' _tacu_tab_complete", script)
        self.assertIn("bindkey '^[[C' _tacu_accept_ghost", script)
        self.assertIn("_tacu_reject_ghost", script)
        self.assertIn("suffix:fg=244", script)
        self.assertIn("TACU_GHOST_SUPPRESS_KEY", script)
        self.assertIn("TACU_GHOST_PROMPTS", script)
        self.assertIn("'ti config'", script)
        self.assertIn("shift words", script)

    def test_tools_map_dot_uses_shell_cwd_not_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TACU_HOME": directory}):
            workspace = configuration.save_workspace(Path(directory) / "tacu-workspace")
            cwd = Path(directory) / "shell-cwd"
            cwd.mkdir()
            (cwd / "here.txt").write_text("mapped-from-shell-cwd")
            output = io.StringIO()
            previous = Path.cwd()
            try:
                os.chdir(cwd)
                with redirect_stdout(output):
                    self.assertEqual(cli.main(["tools", "map", ".", "--depth", "2"]), 0)
            finally:
                os.chdir(previous)
            rendered = output.getvalue()
            self.assertIn("depth 2", rendered)
            self.assertIn(str(cwd.resolve()), rendered)
            self.assertIn("here.txt", rendered)
            self.assertNotIn(str(workspace.resolve()), rendered)
            self.assertNotIn("maps the TACU workspace", rendered)

    def test_completion_scripts_cover_supported_shells_tools_and_options(self) -> None:
        expected = {
            "zsh": "#compdef ticu ti",
            "bash": "complete -F _tacu_complete ticu ti",
            "fish": "complete -c ticu",
            "powershell": "Register-ArgumentCompleter",
        }
        for shell, marker in expected.items():
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(cli.main(["completion", shell]), 0)
            script = output.getvalue()
            self.assertIn(marker, script)
            self.assertIn("repo_map", script)
            self.assertIn("search", script)
            self.assertIn("version", script)
            for documented in (
                "juicy", "extract", "evidence", "save", "clear",
                "model", "completion", "shell-init", "all",
            ):
                self.assertIn(documented, script)
            if shell == "zsh":
                self.assertIn("--input=[JSON object]", script)
                self.assertIn("clip|tray", script)
                ghost = completion.zsh_ghost()
                self.assertIn("'ti clip'", ghost)
                self.assertIn("suffix:fg=244", ghost)
                self.assertIn("TACU_GHOST_SUPPRESS_KEY", ghost)
                self.assertIn("_tacu_accept_ghost", ghost)
                self.assertIn("_tacu_reject_ghost", ghost)
                self.assertIn("_tacu_tab_complete", ghost)
                self.assertIn("compadd -Q -d command_descs -a commands", script)
                self.assertNotIn("zle -N _tacu_tab\n", ghost)
                self.assertNotIn("bindkey '^I' _tacu_tab\n", ghost)

            if shell == "bash":
                self.assertIn("--input --workspace --approve", script)
                self.assertIn("list status add show edit rm search clear copy", script)

    def test_all_tutorial_has_snapshot_topics_and_interactive_deep_dives(self) -> None:
        from tacu.theme import strip_ansi

        output = io.StringIO()
        with patch.object(sys.stdin, "isatty", return_value=False), redirect_stdout(output):
            self.assertEqual(cli.main(["all"]), 0)
        self.assertIn("FULL CAPABILITY SNAPSHOT", output.getvalue())
        self.assertIn("Deep dive with: ti all TOPIC", output.getvalue())
        detail = io.StringIO()
        with redirect_stdout(detail):
            self.assertEqual(cli.main(["all", "safety"]), 0)
        self.assertIn("quoting & guardrails", detail.getvalue().casefold())
        self.assertIn("|  e.g. ", detail.getvalue())
        interactive = io.StringIO()
        with patch.object(sys.stdin, "isatty", return_value=True),              patch("builtins.input", side_effect=["2", "q"]), redirect_stdout(interactive):
            self.assertEqual(cli.main(["all"]), 0)
        self.assertIn("ti run — your command, then an answer", strip_ansi(interactive.getvalue()).casefold())
        self.assertIn("|  e.g. ", interactive.getvalue())

    def test_workspace_without_action_is_self_guiding_and_enter_uses_workspace_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TACU_HOME": directory}):
            workspace = configuration.save_workspace(Path(directory) / "project")
            output = io.StringIO()
            with patch.object(sys.stdin, "isatty", return_value=False), redirect_stdout(output):
                self.assertEqual(cli.main(["workspace"]), 0)
            self.assertIn("ticu workspace enter", output.getvalue())
            completed = SimpleNamespace(returncode=0)
            with patch("tacu.cli.subprocess.run", return_value=completed) as run:
                self.assertEqual(cli.main(["workspace", "enter"]), 0)
            self.assertEqual(run.call_args.kwargs["cwd"], workspace)

    def test_interactive_tacu_session_keeps_shell_cwd_and_shows_workspace(self) -> None:
        original = Path.cwd()
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TACU_HOME": directory}):
            workspace = configuration.save_workspace(Path(directory) / "project")
            output = io.StringIO()
            with core.HistoryStore(Path(directory) / "history.db") as store, \
                 patch("builtins.input", side_effect=EOFError), redirect_stdout(output):
                self.assertEqual(cli.interactive(store, SimpleNamespace(model="mock"), timeout=10, stream=False), 0)
            self.assertEqual(Path.cwd(), original)
            rendered = output.getvalue()
            self.assertIn(str(workspace), rendered)
            self.assertIn("shell directory", rendered)

    def test_installer_preserves_an_existing_ti_command(self) -> None:
        project = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            existing = fake_bin / "ti"
            existing.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            existing.chmod(0o755)
            environment = os.environ.copy()
            environment["PATH"] = str(fake_bin) + os.pathsep + environment["PATH"]
            checked = subprocess.run(["sh", str(project / "install.sh"), "--dry-run", "--skip-models", "--force"],
                                     cwd=project, env=environment, capture_output=True, text=True, timeout=30)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertIn(f"preserve the existing ti command at {existing}", checked.stdout)


class ModelContextTests(unittest.TestCase):
    def test_repeated_noise_is_pruned_and_relevant_middle_evidence_survives(self) -> None:
        text = "routine health check ok\n" * 9000 + "CRITICAL TARGET-992 credential expired\n" + "routine healthy\n" * 9000
        evidence = core.terminal_result(source="test", display_command="verbose", stdout=text.encode())
        message = cli.user_message("Why did TARGET-992 credential expire?", evidence)
        self.assertLess(len(message), model_context.MODEL_EVIDENCE_CHAR_LIMIT + 1000)
        self.assertIn("TARGET-992", message)
        self.assertIn("duplicates_removed", message)
        self.assertGreater(len(evidence["result"]["stdout"]["text"]), len(message))

    def test_docker_facts_replace_verbose_stdout_for_the_model(self) -> None:
        raw = json.dumps([{"Name": "/app", "Image": "sha256:abc", "Config": {"Image": "demo:latest"},
                           "State": {"Status": "running"}, "NetworkSettings": {},
                           "Noise": "x" * 100_000}])
        evidence = core.terminal_result(source="test", display_command="docker inspect app", stdout=raw.encode())
        compact = model_context.compact_evidence(evidence, "What makes this app unusual?")
        self.assertEqual(compact["result"]["stdout"]["type"], "companion_facts")
        self.assertEqual(compact["result"]["stdout"]["data"]["image"], "demo:latest")
        self.assertLess(len(json.dumps(compact)), 10_000)
        self.assertEqual(evidence["result"]["stdout"]["data"][0]["Noise"], "x" * 100_000)

    def test_generic_structured_content_stays_inside_model_budget(self) -> None:
        data = {f"key_{index}": "value " + "x" * 3000 for index in range(500)}
        evidence = core.terminal_result(source="test", display_command="json-tool", stdout=json.dumps(data).encode())
        compact = model_context.compact_evidence(evidence, "Find key_3")
        self.assertLessEqual(len(json.dumps(compact, ensure_ascii=False)), model_context.MODEL_EVIDENCE_CHAR_LIMIT + 1000)

    def test_large_interface_inventories_keep_primary_and_stay_bounded(self) -> None:
        primary = {"name": "en0", "ipv4": ["192.168.1.19"], "status": "active", "notes": "x" * 3000}
        interfaces = [{"name": f"veth{index}", "ipv4": [], "status": "inactive", "notes": "z" * 3000}
                      for index in range(250)] + [primary]
        evidence = core.terminal_result(source="test", display_command="ifconfig", stdout=b"capture")
        evidence["facts"] = {"kind": "network_interfaces", "primary": primary, "interfaces": interfaces,
                             "interface_count": len(interfaces)}
        compact = model_context.compact_evidence(evidence, "What is my primary IP address?")
        encoded = json.dumps(compact, ensure_ascii=False)
        self.assertLessEqual(len(encoded), model_context.MODEL_EVIDENCE_CHAR_LIMIT)
        self.assertEqual(compact["facts"]["primary"]["ipv4"], ["192.168.1.19"])
        self.assertEqual(len(evidence["facts"]["interfaces"]), 251)

    def test_non_local_model_view_redacts_secrets_but_local_view_keeps_evidence(self) -> None:
        evidence = core.terminal_result(
            source="test", display_command="credential-tool",
            stdout=b"username=analyst password=UltraSecret42 email=analyst@example.com",
        )
        local = model_context.compact_evidence(evidence, "What credentials were found?")
        remote = model_context.compact_evidence(
            evidence, "What credentials were found?", redact_sensitive=True,
        )
        self.assertIn("UltraSecret42", json.dumps(local))
        encoded_remote = json.dumps(remote)
        self.assertNotIn("UltraSecret42", encoded_remote)
        self.assertNotIn("analyst@example.com", encoded_remote)
        self.assertIn("[REDACTED:password]", encoded_remote)
        self.assertGreater(remote["information_policy"]["sensitive_values_redacted"], 0)
        self.assertIn("UltraSecret42", json.dumps(evidence))

    def test_only_loopback_ollama_or_explicit_local_plugin_is_local(self) -> None:
        local = providers.OllamaProvider("http://127.0.0.1:11434", "test")
        remote = providers.OllamaProvider("https://models.example.com", "test")
        self.assertTrue(providers.provider_is_local(local))
        self.assertFalse(providers.provider_is_local(remote))
        self.assertTrue(providers.provider_is_local(SimpleNamespace(local=True)))
        self.assertFalse(providers.provider_is_local(SimpleNamespace(local=False)))

    def test_ollama_chat_uses_thinking_when_content_is_empty(self) -> None:
        event = {
            "message": {"role": "assistant", "content": "", "thinking": "Use ssh -T git@github.com."},
            "done": True,
        }

        class FakeResponse:
            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *args: object) -> bool:
                return False

            def read(self) -> bytes:
                return json.dumps(event).encode()

        with patch.dict(os.environ):
            os.environ.pop("TACU_NUM_PREDICT", None)
            client = providers.OllamaProvider("http://127.0.0.1:11434", "gemma4:12b-mlx")
            self.assertEqual(client.num_predict, 1024)
            with patch("tacu.providers.urllib.request.urlopen", return_value=FakeResponse()):
                text = "".join(client.chat([{"role": "user", "content": "hi"}], stream=False))
        self.assertIn("ssh -T git@github.com", text)


class ThinkingBudgetTests(unittest.TestCase):
    """A model that thinks past its budget must never print its scratchpad."""

    class _Stream:
        def __init__(self, events: list[dict]) -> None:
            self._lines = [json.dumps(event).encode() for event in events]

        def __enter__(self) -> "ThinkingBudgetTests._Stream":
            return self

        def __exit__(self, *args: object) -> bool:
            return False

        def __iter__(self):
            return iter(self._lines)

    @staticmethod
    def _thinking(text: str, reason: str) -> list[dict]:
        return [{"message": {"role": "assistant", "content": "", "thinking": text}},
                {"done": True, "done_reason": reason}]

    @staticmethod
    def _answer(text: str) -> list[dict]:
        return [{"message": {"role": "assistant", "content": text}},
                {"done": True, "done_reason": "stop"}]

    def _client(self, budget: str = "80") -> "providers.OllamaProvider":
        with patch.dict(os.environ, {"TACU_NUM_PREDICT": budget}):
            return providers.OllamaProvider("http://127.0.0.1:11434", "gemma4:12b-mlx")

    def test_truncated_reasoning_is_retried_instead_of_printed(self) -> None:
        scratchpad = "The user is asking for the current directory. I need to find"
        responses = [self._Stream(self._thinking(scratchpad, "length")),
                     self._Stream(self._answer("Run pwd to print the current directory."))]
        client = self._client(budget="1024")
        with patch("tacu.providers.urllib.request.urlopen", side_effect=responses) as opened:
            text = "".join(client.chat([{"role": "user", "content": "hi"}], stream=True))
        self.assertNotIn("The user is asking", text)
        self.assertIn("Run pwd", text)
        self.assertEqual(opened.call_count, 2, "a truncated reply should be retried")
        second = json.loads(opened.call_args_list[1].args[0].data)
        self.assertGreater(second["options"]["num_predict"], 1024)

    def test_budget_ladder_is_owned_by_the_harness(self) -> None:
        from tacu.providers import _MAX_NUM_PREDICT

        client = self._client(budget="1024")
        # Tied to the constant, so raising the cap for long listings does not
        # need this test edited to agree with it.
        self.assertEqual(client.reply_budgets(), [1024, _MAX_NUM_PREDICT])
        self.assertEqual(client.reply_budgets()[-1], _MAX_NUM_PREDICT,
                         "escalation must stop at the cap")

    def test_every_budget_is_tried_before_giving_up(self) -> None:
        scratchpad = "Looking at the available tools: - ls - find - grep - github_actions"
        client = self._client(budget="1024")
        responses = [self._Stream(self._thinking(scratchpad, "length"))
                     for _ in client.reply_budgets()]
        with patch("tacu.providers.urllib.request.urlopen", side_effect=responses) as opened:
            text = "".join(client.chat([{"role": "user", "content": "hi"}], stream=True))
        tried = [json.loads(call.args[0].data)["options"]["num_predict"]
                 for call in opened.call_args_list]
        from tacu.providers import _MAX_NUM_PREDICT

        self.assertEqual(tried, [1024, _MAX_NUM_PREDICT])
        self.assertNotIn("Looking at the available tools", text)
        self.assertNotIn("github_actions", text)
        # The harness owns the budget: never hand the user an env var to set.
        self.assertNotIn("TACU_NUM_PREDICT", text)
        self.assertIn(str(_MAX_NUM_PREDICT), text)
        self.assertIn("qwen2.5-coder:7b", text)

    def test_repeat_penalty_is_sent_to_guard_against_loops(self) -> None:
        client = self._client(budget="1024")
        responses = [self._Stream(self._answer("Fine."))]
        with patch("tacu.providers.urllib.request.urlopen", side_effect=responses) as opened:
            "".join(client.chat([{"role": "user", "content": "hi"}], stream=True))
        options = json.loads(opened.call_args_list[0].args[0].data)["options"]
        self.assertGreater(options["repeat_penalty"], 1.0)

    def test_a_reasoning_only_reply_is_asked_again_for_the_answer(self) -> None:
        # A clean reply with empty content is sometimes the Gemma MLX quirk, where
        # `thinking` holds the answer, and sometimes a scratchpad that ends "I will
        # call network_tools.list_active_connections()" and never does. The words
        # cannot tell them apart, and printing the second lost the user's trust —
        # so ask once for the answer itself. One extra generation is the price.
        scratchpad = ("The user wants to know about connections. I should look for a tool. "
                      "I will call network_tools.list_active_connections().")
        responses = [self._Stream(self._thinking(scratchpad, "stop")),
                     self._Stream(self._answer("One connection to 140.82.114.25:443."))]
        client = self._client(budget="1024")
        with patch("tacu.providers.urllib.request.urlopen", side_effect=responses) as opened:
            text = "".join(client.chat([{"role": "user", "content": "hi"}], stream=True))
        self.assertEqual(opened.call_count, 2)
        self.assertIn("140.82.114.25:443", text)
        self.assertNotIn("I will call", text, "the scratchpad must never reach the user")

    def test_the_retry_asks_for_the_answer_rather_than_the_reasoning(self) -> None:
        responses = [self._Stream(self._thinking("Thinking about it.", "stop")),
                     self._Stream(self._answer("Done."))]
        client = self._client(budget="1024")
        with patch("tacu.providers.urllib.request.urlopen", side_effect=responses) as opened:
            "".join(client.chat([{"role": "user", "content": "hi"}], stream=True))
        sent = json.loads(opened.call_args_list[1].args[0].data)["messages"]
        self.assertIn("Answer the question directly", sent[-1]["content"])

    def test_completed_reply_still_falls_back_to_thinking(self) -> None:
        # The Gemma MLX quirk this fallback exists for: when the retry also comes
        # back with reasoning only, that text is still better than nothing.
        responses = [self._Stream(self._thinking("Run pwd to see the directory.", "stop")),
                     self._Stream(self._thinking("Run pwd to see the directory.", "stop"))]
        client = self._client(budget="1024")
        with patch("tacu.providers.urllib.request.urlopen", side_effect=responses) as opened:
            text = "".join(client.chat([{"role": "user", "content": "hi"}], stream=True))
        self.assertIn("Run pwd", text)
        self.assertEqual(opened.call_count, 2)

    def test_content_is_preferred_and_never_retried(self) -> None:
        responses = [self._Stream(self._answer("Your shell is in /Users/me."))]
        client = self._client(budget="1024")
        with patch("tacu.providers.urllib.request.urlopen", side_effect=responses) as opened:
            text = "".join(client.chat([{"role": "user", "content": "hi"}], stream=True))
        self.assertEqual(text, "Your shell is in /Users/me.")
        self.assertEqual(opened.call_count, 1)


if __name__ == "__main__": unittest.main()


class SingleVersionSourceTests(unittest.TestCase):
    """A release must not be able to half-happen across several files."""

    def _root(self) -> Path:
        return Path(__file__).resolve().parents[1]

    def test_pyproject_declares_the_version_dynamic(self) -> None:
        text = (self._root() / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('dynamic = ["version"]', text)
        self.assertNotRegex(text, r'(?m)^version\s*=', "a static version would drift from __init__")

    def test_the_build_backend_reads_the_package_version(self) -> None:
        import importlib.util

        path = self._root() / "tacu_build_backend.py"
        spec = importlib.util.spec_from_file_location("tacu_build_backend_under_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.VERSION, __version__)
        self.assertIn(f"Version: {__version__}", module._metadata())


class ToolDiscoverabilityTests(unittest.TestCase):
    """`ti tools --help` must never imply TACU has fewer tools than it has."""

    def _help_text(self) -> str:
        from tacu.helptext import print_tools_help
        from tacu.theme import strip_ansi

        output = io.StringIO()
        with redirect_stdout(output):
            print_tools_help()
        return strip_ansi(output.getvalue())

    def test_every_registered_tool_is_named_in_the_help(self) -> None:
        from tacu.tools import specs

        text = self._help_text()
        for spec in specs():
            self.assertIn(spec.name, text, f"{spec.name} is registered but invisible in ti tools --help")

    def test_every_tool_entry_follows_the_house_format(self) -> None:
        """name, then a shape, then a runnable example, then what it is for."""

        from tacu.tools import specs

        text = self._help_text()
        for spec in specs():
            line = next((row for row in text.splitlines()
                         if row.startswith(f"  {spec.name} ") or row.strip() == spec.name), "")
            self.assertTrue(line, f"{spec.name} has no entry line")
            self.assertIn("|  e.g. ", line, f"{spec.name} shows no example")
            shape = line.split("|  e.g. ")[0].replace(f"  {spec.name}", "", 1).strip()
            self.assertTrue(shape, f"{spec.name} shows no syntax")

    def test_operations_in_the_shape_come_from_the_contract(self) -> None:
        text = self._help_text()
        self.assertIn("operation: sweep|outbound|listening|persistence", text)
        self.assertIn("path*", text, "required fields should be marked")

    def test_an_ungrouped_tool_still_surfaces(self) -> None:
        from tacu import helptext

        groups = tuple(item for item in helptext._TOOL_GROUPS
                       if "process" not in item[1])
        with patch.object(helptext, "_TOOL_GROUPS", groups):
            text = self._help_text()
        # process belongs to no group now, so it must still print under OTHER TOOLS.
        self.assertIn("OTHER TOOLS", text)
        self.assertIn("process", text)

    def test_the_help_points_at_the_full_listing(self) -> None:
        text = self._help_text()
        self.assertIn("ti tools list", text)
        self.assertIn("ti tools describe", text)

    def test_tools_list_uses_the_same_entry_format(self) -> None:
        from tacu.helptext import print_native_tool_listing
        from tacu.theme import strip_ansi
        from tacu.tools import specs

        output = io.StringIO()
        with redirect_stdout(output):
            print_native_tool_listing()
        text = strip_ansi(output.getvalue())
        for spec in specs():
            line = next((row for row in text.splitlines() if row.startswith(f"  {spec.name} ")), "")
            self.assertTrue(line, f"{spec.name} missing from ti tools list")
            self.assertIn("|  e.g. ", line, f"{spec.name} shows no example")
            self.assertIn(f"[{spec.risk_level}]", text, f"{spec.name} shows no risk level")


class ReleaseHistoryTests(unittest.TestCase):
    """`ti version --history` must work from an install, not only a checkout."""

    def test_history_is_parsed_newest_first_with_dates(self) -> None:
        from tacu.core import release_history

        releases = release_history()
        self.assertTrue(releases, "no release history was found")
        versions = [version for version, _date, _notes in releases]
        self.assertEqual(versions[0], __version__, "the newest entry should be this version")
        self.assertIn("0.1.0", versions)
        for _version, date, notes in releases:
            self.assertRegex(date, r"^\d{4}-\d{2}-\d{2}$")
            self.assertTrue(notes, "a release with no notes is not useful")

    def test_a_wrapped_bullet_is_joined_into_one_note(self) -> None:
        from tacu import core

        source = (
            "# Changelog\n\n"
            "## [9.9.9] - 2030-01-01\n\n"
            "### Added\n\n"
            "- A sentence that wraps\n  onto a second line.\n"
            "- A second note.\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "CHANGELOG.md"
            path.write_text(source, encoding="utf-8")
            with patch.object(core.Path, "is_file", lambda self: str(self) == str(path)), \
                 patch.object(core.Path, "read_text", lambda self, **kw: source), \
                 patch("tacu.core.Path.with_name", lambda self, name: path):
                releases = core.release_history()
        self.assertEqual(len(releases), 1)
        _version, _date, notes = releases[0]
        self.assertEqual(notes, ["A sentence that wraps onto a second line.", "A second note."])

    def test_the_changelog_travels_inside_the_wheel(self) -> None:
        root = Path(__file__).resolve().parents[1]
        backend = (root / "tacu_build_backend.py").read_text(encoding="utf-8")
        self.assertIn("CHANGELOG.md", backend,
                      "an installed TACU cannot show history the wheel does not carry")

    def test_the_command_lists_every_version_and_marks_the_installed_one(self) -> None:
        from tacu.core import release_history
        from tacu.theme import strip_ansi

        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(cli.main(["version", "--history"]), 0)
        text = strip_ansi(output.getvalue())
        for version, _date, _notes in release_history():
            self.assertIn(version, text)
        self.assertIn("← installed", text)

    def test_plain_version_is_unchanged(self) -> None:
        from tacu.theme import strip_ansi

        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(cli.main(["version"]), 0)
        self.assertEqual(strip_ansi(output.getvalue()).strip(), f"TACU {__version__}")
