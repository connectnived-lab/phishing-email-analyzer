"""Individual groups of checks. Each module exposes ``run(email) -> list[Finding]``."""

from . import attachments, content, headers, links

ALL_CHECKS = (headers.run, links.run, content.run, attachments.run)
