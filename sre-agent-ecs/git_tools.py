"""
git_tools.py — local code-fix tools for the RemediationAgent (Tier 2)
=====================================================================
Ported from the hackathon agent. Provides two NATIVE Bedrock tools that are
executed locally (NOT through the Datadog MCP server):

  - read_application_code  — read a file from the local app source directory
  - create_github_pr       — commit a fix to a new branch and open a GitHub PR

Exports:
  - GIT_TOOL_CONFIG   — Bedrock Converse toolConfig payload for both tools
  - GIT_TOOL_NAMES    — set of tool names routed here (not to MCP)
  - execute_git_tool  — synchronous dispatcher called by the agent loop

SECURITY NOTE: this service receives untrusted webhook payloads. Letting the
model open PRs autonomously widens the blast radius of a prompt injection, so
the whole capability is gated behind GIT_TOOLS_ENABLED (see main.py) and the
existing prompt-injection guard still applies to all alert text.
"""

import logging
import os
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Optional dependency — graceful ImportError so the module still imports
# without PyGithub installed; create_github_pr returns an informative error.
try:
    from github import Github, GithubException  # type: ignore[import]
    _PYGITHUB_AVAILABLE = True
except ImportError:
    Github = None  # type: ignore[assignment,misc]
    GithubException = Exception  # type: ignore[assignment,misc]
    _PYGITHUB_AVAILABLE = False

# ---------------------------------------------------------------------------
# Bedrock toolConfig schemas
# ---------------------------------------------------------------------------

GIT_TOOL_CONFIG: dict[str, Any] = {
    "tools": [
        {
            "toolSpec": {
                "name": "read_application_code",
                "description": (
                    "Read the full raw source of a file from the local application "
                    "repository so you can inspect exact code and line numbers. "
                    "Use this whenever the root cause appears to be in application code "
                    "(e.g. N+1 queries, missing timeouts, unbounded loops)."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "filepath": {
                                "type": "string",
                                "description": (
                                    "Path relative to the application root, "
                                    "e.g. 'services/orders.py' or 'api/checkout.py'."
                                ),
                            }
                        },
                        "required": ["filepath"],
                    }
                },
            }
        },
        {
            "toolSpec": {
                "name": "create_github_pr",
                "description": (
                    "Open a GitHub Pull Request that replaces the full content of a "
                    "file with a bug fix. Call this after you have read the file, "
                    "identified the bug, and written the corrected code. "
                    "Always include the returned PR URL in your final summary."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "filepath": {
                                "type": "string",
                                "description": "Path relative to the repo root, matching the file you read.",
                            },
                            "new_code_content": {
                                "type": "string",
                                "description": "The complete, corrected source code to replace the file contents.",
                            },
                            "commit_message": {
                                "type": "string",
                                "description": "Short git commit message describing the fix (imperative mood).",
                            },
                            "pr_title": {
                                "type": "string",
                                "description": "Pull Request title, concise and descriptive.",
                            },
                            "pr_body": {
                                "type": "string",
                                "description": (
                                    "Pull Request description. Include root cause, "
                                    "what changed, and how it fixes the issue."
                                ),
                            },
                        },
                        "required": [
                            "filepath",
                            "new_code_content",
                            "commit_message",
                            "pr_title",
                            "pr_body",
                        ],
                    }
                },
            }
        },
    ]
}

# Names of tools handled locally by this module (not forwarded to MCP)
GIT_TOOL_NAMES: frozenset[str] = frozenset(
    {"read_application_code", "create_github_pr"}
)


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def read_application_code(filepath: str) -> str:
    """
    Return the raw UTF-8 contents of a file from the local app source directory.

    Args:
        filepath: Path relative to the app root, e.g. 'services/orders.py'.

    Returns:
        File contents as a string, or an 'ERROR: ...' message the model can reason about.
    """
    base_dir = Path(os.getenv("APP_SOURCE_DIR", "./app_source")).resolve()
    target = (base_dir / filepath).resolve()

    # Path-traversal guard — resolved target must stay inside base_dir
    try:
        target.relative_to(base_dir)
    except ValueError:
        msg = f"ERROR: path traversal rejected — '{filepath}' escapes the app root."
        logger.warning(msg)
        return msg

    if not target.exists():
        msg = f"ERROR: file not found — '{filepath}' does not exist under {base_dir}."
        logger.warning(msg)
        return msg

    if not target.is_file():
        msg = f"ERROR: '{filepath}' is not a regular file."
        logger.warning(msg)
        return msg

    try:
        content = target.read_text(encoding="utf-8")
        logger.info(
            "git_tool.read_application_code — read %d chars from %s",
            len(content),
            filepath,
        )
        return content
    except OSError as exc:
        msg = f"ERROR: could not read '{filepath}': {exc}"
        logger.error(msg)
        return msg


def create_github_pr(
    filepath: str,
    new_code_content: str,
    commit_message: str,
    pr_title: str,
    pr_body: str,
) -> dict[str, Any]:
    """
    Create a new branch, commit new_code_content to filepath, and open a GitHub PR.

    Reads GITHUB_TOKEN and GITHUB_REPO ('owner/repo') from the environment.

    Returns:
        dict with 'success', 'pr_url', 'branch' on success, or 'success', 'error' on failure.
    """
    github_token = os.getenv("GITHUB_TOKEN", "")
    github_repo = os.getenv("GITHUB_REPO", "")

    if not github_token:
        return {"success": False, "error": "GITHUB_TOKEN environment variable is not set."}
    if not github_repo:
        return {"success": False, "error": "GITHUB_REPO environment variable is not set (expected 'owner/repo')."}

    if not _PYGITHUB_AVAILABLE or Github is None:
        return {
            "success": False,
            "error": "PyGithub is not installed. Run: pip install PyGithub>=2.3.0",
        }

    try:
        g = Github(github_token)
        repo = g.get_repo(github_repo)
        base_branch = repo.default_branch

        # Build a short unique branch name
        slug = filepath.replace("/", "-").replace(".", "-").replace("_", "-")[:40]
        short_id = uuid.uuid4().hex[:8]
        branch_name = f"fix/{slug}-{short_id}"

        # Create the new branch off the tip of the default branch
        base_sha = repo.get_branch(base_branch).commit.sha
        repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base_sha)
        logger.info("git_tool.create_github_pr — created branch %s", branch_name)

        # Get current file SHA if it exists (needed for update_file)
        try:
            existing = repo.get_contents(filepath, ref=branch_name)
            file_sha = existing.sha  # type: ignore[union-attr]
            repo.update_file(
                path=filepath,
                message=commit_message,
                content=new_code_content,
                sha=file_sha,
                branch=branch_name,
            )
        except GithubException:
            # File doesn't exist yet — create it
            repo.create_file(
                path=filepath,
                message=commit_message,
                content=new_code_content,
                branch=branch_name,
            )

        logger.info("git_tool.create_github_pr — committed fix to %s on %s", filepath, branch_name)

        pr = repo.create_pull(
            title=pr_title,
            body=pr_body,
            head=branch_name,
            base=base_branch,
        )

        logger.info("git_tool.create_github_pr — opened PR #%d: %s", pr.number, pr.html_url)
        return {"success": True, "pr_url": pr.html_url, "branch": branch_name}

    except Exception as exc:  # includes GithubException
        logger.error("git_tool.create_github_pr — failed: %s", exc)
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Dispatcher (called by the investigator loop for GIT_TOOL_NAMES)
# ---------------------------------------------------------------------------


def execute_git_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Synchronous dispatcher for git tools.

    Returns a dict with 'success' and either 'result' (str|dict) or 'error' (str).
    """
    if name == "read_application_code":
        filepath = arguments.get("filepath", "")
        content = read_application_code(filepath)
        if content.startswith("ERROR:"):
            return {"success": False, "error": content}
        return {"success": True, "result": content}

    if name == "create_github_pr":
        result = create_github_pr(
            filepath=arguments.get("filepath", ""),
            new_code_content=arguments.get("new_code_content", ""),
            commit_message=arguments.get("commit_message", "fix: apply AI-generated patch"),
            pr_title=arguments.get("pr_title", "AI-generated bug fix"),
            pr_body=arguments.get("pr_body", ""),
        )
        return result if not result.get("success") else {"success": True, "result": result}

    return {"success": False, "error": f"Unknown git tool: '{name}'"}
