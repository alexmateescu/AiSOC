#!/usr/bin/env python3
"""No audio may leave the responder app.

Depth 9.6. The plan's wording is exact: voice input "converts speech to text
on the device and sends the text to the grounded copilot. **No audio leaves
the device.**"

A responder saying "what did this host do before the alert" out loud at 3am
is in a room with other people's conversations in it. A SOC product that
uploaded that audio to a transcription service would be exfiltrating its
customer's office, and the customer would have no way to tell — which is
exactly the shape of claim this repository has learned not to make in a
comment.

So the property is checked rather than promised. Two rules:

``no-recording-api``
    No module under ``apps/mobile/src`` may import or reference an audio
    *capture* API. ``src/lib/voice.ts`` is designed so there is nothing to
    reference: it takes a recogniser that returns a **string**, so no
    buffer, blob or file handle appears anywhere in its types and there is
    nothing for a later edit to upload by accident. This rule keeps that
    true as the app grows.

``no-binary-body``
    No ``fetch`` in that tree may send a binary body — ``FormData``,
    ``Blob``, ``ArrayBuffer``, ``Uint8Array`` or a ``ReadableStream``. That
    is the only way audio could physically leave, and refusing the shape is
    stronger than refusing a named API, because a future SDK nobody has
    heard of still has to put the bytes in a request.

Why a denylist of API names is not the whole control
-----------------------------------------------------
Because a denylist is the wrong control on its own — the osquery renderer
blocked ``--``, ``/*`` and ``;`` and never ``'``. ``no-binary-body`` is the
structural half: it does not care what produced the bytes.

Deliberately scoped to ``apps/mobile/src``. The console records audio
nowhere and the services never see a microphone; widening this would add
false positives in file-upload paths that have nothing to do with voice.

Usage:
    python3 scripts/check_no_audio_egress.py
    python3 scripts/check_no_audio_egress.py --self-test

Exit codes: 0 clean, 1 findings.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

SCOPE = Path("apps/mobile/src")

#: Capture APIs. Each is a thing that produces audio bytes on a device.
_RECORDING = (
    r"expo-av",
    r"expo-audio",
    r"\bAudio\.Recording\b",
    r"react-native-audio",
    r"@react-native-voice/voice",
    r"getUserMedia",
    r"MediaRecorder",
    r"AVAudioRecorder",
    r"startRecording\s*\(",
)
_RECORDING_RE = re.compile("|".join(_RECORDING))

#: Binary request bodies. The structural half: a future SDK nobody has heard
#: of still has to put the bytes somewhere, and this is where.
_BINARY_BODY_RE = re.compile(r"body\s*:\s*(?:new\s+)?(FormData|Blob|ArrayBuffer|Uint8Array|ReadableStream|File)\b")

#: `//` to end of line and `/* */`. A detector that matches prose is the
#: documented way a gate in this tree ends up grading a comment — this one's
#: sibling, `check_mcp_over_http.py`, reported a file for a sentence saying
#: it deliberately does not do the thing.
_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)


def code_only(source: str) -> str:
    return _COMMENT_RE.sub(" ", source)


def violations_in(source: str, rel: str) -> list[str]:
    code = code_only(source)
    found: list[str] = []
    for match in _RECORDING_RE.finditer(code):
        line = code[: match.start()].count("\n") + 1
        found.append(
            f"no-recording-api: {rel}:{line}: references {match.group(0)!r}. "
            "The responder app transcribes on the device and sends text; it has no reason "
            "to hold audio bytes at all."
        )
    for match in _BINARY_BODY_RE.finditer(code):
        line = code[: match.start()].count("\n") + 1
        found.append(
            f"no-binary-body: {rel}:{line}: sends a {match.group(1)} body. "
            "No request from the responder app may carry binary, because that is the only "
            "way audio could physically leave the device."
        )
    return found


def scan(root: Path) -> list[str]:
    scope = root / SCOPE
    if not scope.is_dir():
        return [f"{SCOPE} is absent — refusing to report a clean tree"]
    found: list[str] = []
    files = sorted(p for p in scope.rglob("*") if p.suffix in {".ts", ".tsx"})
    if not files:
        return [f"no TypeScript under {SCOPE} — refusing to report a clean tree"]
    for path in files:
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        found.extend(violations_in(source, str(path.relative_to(root))))
    return found


def main() -> int:
    root = repo_root()
    problems = scan(root)
    if problems:
        print("Audio could leave the responder app:\n", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(f"\n{len(problems)} problem(s).", file=sys.stderr)
        return 1
    count = len([p for p in (root / SCOPE).rglob("*") if p.suffix in {".ts", ".tsx"}])
    print(f"check_no_audio_egress: OK — {count} file(s) under {SCOPE}, no capture API and no binary request body")
    return 0


_CLEAN = """
export async function ask(q: string) {
  return fetch(url, { method: 'POST', body: JSON.stringify({ question: q }) });
}
"""
_RECORDS = "import { Audio } from 'expo-av';\nconst r = new Audio.Recording();\n"
_UPLOADS = "const fd = new FormData();\nawait fetch(url, { method: 'POST', body: FormData });\n"
_COMMENT_ONLY = "// We deliberately never call getUserMedia or send a Blob body.\nexport const x = 1;\n"


def _rule_self_test() -> list[tuple[str, bool]]:
    root = repo_root()
    return [
        ("the tree as committed is clean", not scan(root)),
        ("a JSON body carrying text is not reported", not violations_in(_CLEAN, "f.ts")),
        (
            "importing a recording API is reported",
            any("no-recording-api" in v for v in violations_in(_RECORDS, "f.ts")),
        ),
        (
            "a FormData body is reported",
            any("no-binary-body" in v for v in violations_in(_UPLOADS, "f.ts")),
        ),
        (
            "a comment saying the app does not do it is NOT reported",
            not violations_in(_COMMENT_ONLY, "f.ts"),
        ),
        (
            "a Blob body is reported even with no recording API in the file",
            any("no-binary-body" in v for v in violations_in("await fetch(u, { body: new Blob([x]) });", "f.ts")),
        ),
    ]


if __name__ == "__main__":
    if SELF_TEST_FLAG in sys.argv[1:]:
        sys.exit(self_test_main(Path(__file__).name, extra=_rule_self_test()))
    sys.exit(main())
