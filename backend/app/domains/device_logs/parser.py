"""Parse one syslog line as RouterOS sends it, and mask what must not be
stored in the online index.

Tolerant by design. RouterOS's remote output differs between versions and
settings (``bsd-syslog=yes`` adds the RFC 3164 timestamp; whether the
identity and the topic list appear varies), and the hardware test (DESIGN
§14 H4) is what pins the exact shape on our fleet. So every part after
``<PRI>`` is optional, and a line that matches nothing is still stored
whole as the message -- a log line we failed to understand is worth more
than a log line we dropped.

What is recognised, in order:

* ``<PRI>`` -> facility, severity (RFC 5424 numbering). Absent -> both None,
  never a guessed "info".
* RFC 3164 timestamp ``Mmm dd hh:mm:ss`` (or RFC 5424 ``1 <iso>`` header).
* hostname (the RouterOS identity), when the next token is neither our tag
  nor a topic list.
* our ``wyfy-<8 hex>`` prefix tag, with or without a trailing ``:``.
* a RouterOS topic list (``dhcp,info`` / ``system,error,critical``): comma
  separated, and containing a severity word.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from app.common.masking import mask_email, mask_mobile

from .constants import MAX_MESSAGE_LENGTH, TAG_HEX_LENGTH, TAG_PREFIX

# Routers are set to Asia/Kolkata by the bootstrap (renderers
# ``_BOOTSTRAP_TIME_ZONE``); an RFC 3164 timestamp has no zone or year.
_ROUTER_TZ = ZoneInfo("Asia/Kolkata")

_PRI = re.compile(r"^<(\d{1,3})>")
_BSD_TS = re.compile(
    r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}(\d{1,2}) "
    r"(\d{2}):(\d{2}):(\d{2}) "
)
_RFC5424_HEAD = re.compile(r"^1 (\S+) ")
_TAG = re.compile(rf"^{re.escape(TAG_PREFIX)}([0-9a-f]{{{TAG_HEX_LENGTH}}}):?$")
_TOPIC_WORD = re.compile(r"^[a-z0-9-]+$")
_SEVERITY_TOPICS = frozenset({"critical", "error", "warning", "info", "debug"})
_MONTHS = {
    m: i
    for i, m in enumerate(
        (
            "Jan",
            "Feb",
            "Mar",
            "Apr",
            "May",
            "Jun",
            "Jul",
            "Aug",
            "Sep",
            "Oct",
            "Nov",
            "Dec",
        ),
        start=1,
    )
}

# Indian mobile numbers in free text: optional +91 / 91 / 0, then 10 digits
# starting 6-9, optionally written 5+5 with a space or dash. The
# look-arounds keep it out of IPs (10.20.0.31), MACs, hex ids and longer digit
# runs (byte counters).
_MOBILE_IN_TEXT = re.compile(
    r"(?<![\w.:/-])(?:\+?91[\s-]?|0)?[6-9]\d{4}[ -]?\d{5}(?![\w.:/-])"
)
_EMAIL_IN_TEXT = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


@dataclass(frozen=True)
class ParsedLine:
    facility: int | None
    severity: int | None
    device_time: datetime | None
    hostname: str | None
    tag: str | None
    topics: str | None
    message: str


def _is_topic_list(token: str) -> bool:
    words = token.rstrip(":").split(",")
    return (
        len(words) >= 2
        and all(_TOPIC_WORD.match(w) for w in words)
        and any(w in _SEVERITY_TOPICS for w in words)
    )


def _bsd_time(match: re.Match[str], received_at: datetime) -> datetime | None:
    """Attach a year (and the router's zone) to an RFC 3164 timestamp.

    Picks the year that puts the time closest to ``received_at`` and gives
    up (None) if even that is more than a day away -- a router whose clock
    is wrong by more than that has a clock problem, and inventing a
    plausible time would hide it."""
    month = _MONTHS[match.group(1)]
    day, hh, mm, ss = (int(match.group(i)) for i in range(2, 6))
    best: datetime | None = None
    for year in (received_at.year - 1, received_at.year, received_at.year + 1):
        try:
            candidate = datetime(year, month, day, hh, mm, ss, tzinfo=_ROUTER_TZ)
        except ValueError:
            continue
        if best is None or abs(candidate - received_at) < abs(best - received_at):
            best = candidate
    if best is None or abs(best - received_at) > timedelta(days=1):
        return None
    return best.astimezone(UTC)


def parse_line(raw: str, *, received_at: datetime) -> ParsedLine:
    text = raw.strip().replace("\x00", "")
    facility = severity = None
    device_time: datetime | None = None

    pri = _PRI.match(text)
    if pri:
        value = int(pri.group(1))
        if value <= 191:
            facility, severity = divmod(value, 8)
        text = text[pri.end() :]

    bsd = _BSD_TS.match(text)
    if bsd:
        device_time = _bsd_time(bsd, received_at)
        text = text[bsd.end() :]
    else:
        head = _RFC5424_HEAD.match(text)
        if head:
            try:
                device_time = datetime.fromisoformat(
                    head.group(1).replace("Z", "+00:00")
                ).astimezone(UTC)
            except ValueError:
                device_time = None
            text = text[head.end() :]

    tokens = text.split(" ")
    hostname = tag = topics = None
    index = 0
    # Header tokens only ever appear before the message proper, each at most
    # once, in the order hostname -> tag -> topics.
    if (
        bsd
        and len(tokens) > 1
        and tokens[0]
        and not _TAG.match(tokens[0])
        and not _is_topic_list(tokens[0])
    ):
        hostname = tokens[0][:255]
        index = 1
    if index < len(tokens):
        tag_match = _TAG.match(tokens[index])
        if tag_match:
            tag = tag_match.group(1)
            index += 1
    if index < len(tokens) and _is_topic_list(tokens[index]):
        topics = tokens[index].rstrip(":")[:200]
        index += 1

    message = " ".join(tokens[index:]).strip() or text.strip()
    return ParsedLine(
        facility=facility,
        severity=severity,
        device_time=device_time,
        hostname=hostname,
        tag=tag,
        topics=topics,
        message=mask_personal_data(message)[:MAX_MESSAGE_LENGTH],
    )


def mask_personal_data(text: str) -> str:
    """Mask mobile numbers and e-mail addresses in free text, reusing the
    platform's own masks (``app.common.masking``) so a masked value reads the
    same here as everywhere else in the dashboard. MACs and IPs are kept on
    purpose: they are what troubleshooting needs (DESIGN §8)."""
    text = _EMAIL_IN_TEXT.sub(lambda m: mask_email(m.group(0)) or "", text)
    return _MOBILE_IN_TEXT.sub(lambda m: mask_mobile(m.group(0)) or "", text)
