"""Regression tests for Git ref inference in the knowledge stage."""

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


SOURCE_ROOT = Path(__file__).resolve().parents[1]
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from app.stages.knowledge import infer_git_refs


class InferGitRefsTests(unittest.TestCase):
    def test_vulnerable_ref_uses_fixed_commit_parent(self) -> None:
        osv_payload = {
            "references": [
                {"url": "https://github.com/lua/lua/commit/1f3c6f4534c6411313361697d98d1145a1f030fa"},
            ],
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "GIT",
                            "events": [
                                {"introduced": "c33b1728aeb7dfeec4013562660e07d32697aa6b"},
                                {"fixed": "1f3c6f4534c6411313361697d98d1145a1f030fa"},
                            ],
                        }
                    ]
                }
            ],
        }

        with patch(
            "app.stages.knowledge.fetch_github_parent_ref",
            return_value="25b143dd34fb587d1e35290c4b25bc08954800e2",
        ) as mocked_parent_lookup:
            vulnerable_ref, fixed_ref = infer_git_refs(
                osv_payload,
                fallback_fixed=None,
                fallback_vulnerable=None,
                repo_url="https://github.com/lua/lua.git",
            )

        self.assertEqual(fixed_ref, "1f3c6f4534c6411313361697d98d1145a1f030fa")
        self.assertEqual(vulnerable_ref, "25b143dd34fb587d1e35290c4b25bc08954800e2")
        mocked_parent_lookup.assert_called_once_with(
            "https://github.com/lua/lua.git",
            "1f3c6f4534c6411313361697d98d1145a1f030fa",
        )

    def test_vulnerable_ref_falls_back_when_parent_lookup_fails(self) -> None:
        osv_payload = {
            "references": [],
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "GIT",
                            "events": [
                                {"fixed": "fixed-sha"},
                            ],
                        }
                    ]
                }
            ],
        }

        with patch("app.stages.knowledge.fetch_github_parent_ref", return_value=None):
            vulnerable_ref, fixed_ref = infer_git_refs(
                osv_payload,
                fallback_fixed=None,
                fallback_vulnerable="existing-vulnerable",
                repo_url="https://github.com/example/project.git",
            )

        self.assertEqual(fixed_ref, "fixed-sha")
        self.assertEqual(vulnerable_ref, "existing-vulnerable")


if __name__ == "__main__":
    unittest.main()
