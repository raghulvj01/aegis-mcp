from __future__ import annotations

import subprocess


def get_recent_commits(limit: int = 10) -> list[dict[str, str]]:
    raw = subprocess.check_output(
        ["git", "log", f"-{limit}", "--pretty=format:%H|%an|%s"],
        text=True,
    )
    commits = []
    for line in raw.splitlines():
        commit_hash, author, subject = line.split("|", maxsplit=2)
        commits.append({"hash": commit_hash, "author": author, "subject": subject})
    return commits
