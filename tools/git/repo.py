from __future__ import annotations

import subprocess


def get_recent_commits(limit: int = 10) -> list[dict[str, str]]:
    try:
        raw = subprocess.check_output(
            ["git", "log", f"-{limit}", "--pretty=format:%H|%an|%s"],
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("git is not installed or not on PATH") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"git log failed: {exc.output}") from exc

    commits = []
    for line in raw.splitlines():
        parts = line.split("|", maxsplit=2)
        if len(parts) == 3:
            commits.append({"hash": parts[0], "author": parts[1], "subject": parts[2]})
    return commits
