from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import common  # noqa: E402


class ChildEnvironmentTest(unittest.TestCase):
    def test_passes_only_review_runtime_and_auth_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            container = pathlib.Path(temporary)
            with (
                mock.patch.dict(
                    common.os.environ,
                    {
                        "HOME": "/home/reviewer",
                        "GH_TOKEN": "github-auth",
                        "UNRELATED_PRIVATE_VALUE": "must-not-pass",
                        "DATABASE_PASSWORD": "must-not-pass",
                    },
                    clear=True,
                ),
                mock.patch.object(
                    common, "resolve_git", return_value=pathlib.Path("/usr/bin/git")
                ),
                mock.patch.object(
                    common,
                    "install_readonly_git_shim",
                    return_value=container / "tool-shims",
                ),
            ):
                env = common.child_environment(
                    container_dir=container,
                    shim_source=SCRIPTS / "git_readonly_shim",
                    passthrough_keys=("GH_TOKEN",),
                )
        self.assertEqual(env["HOME"], "/home/reviewer")
        self.assertEqual(env["GH_TOKEN"], "github-auth")
        self.assertNotIn("UNRELATED_PRIVATE_VALUE", env)
        self.assertNotIn("DATABASE_PASSWORD", env)


if __name__ == "__main__":
    unittest.main()
