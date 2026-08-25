#!/usr/bin/env python3
"""Example experiment script for exodus-mcp.

Protocol (bounded JSON lines, one object per line):
  * The server writes the one-shot `init` message to this process's stdin.
  * This process sends `call`, `artifact`, or `complete` messages on stdout.
  * The server answers every `call` and `artifact` with a `result` message on
    stdin. Everything the script prints on stdout MUST be protocol JSON;
    diagnostic text belongs on stderr.

This example advances two frames, captures the rendered frame, publishes a
small derived artifact, and completes with a summary.
"""
import base64
import json
import sys


def read_message():
    line = sys.stdin.readline()
    if not line:
        raise SystemExit("server closed the protocol stream")
    return json.loads(line)


def send(payload):
    print(json.dumps(payload), flush=True)


def call(tool, arguments=None):
    message_id = "step-%d" % len(call.ids)
    call.ids.append(message_id)
    send({"type": "call", "id": message_id, "tool": tool, "arguments": arguments or {}})
    result = read_message()
    if not result.get("ok"):
        raise RuntimeError("%s failed: %s" % (tool, result["error"]["message"]))
    return result["value"]


call.ids = []


def publish_artifact(kind, mime_type, payload_bytes):
    message_id = "artifact-%d" % len(call.ids)
    call.ids.append(message_id)
    send({
        "type": "artifact",
        "id": message_id,
        "kind": kind,
        "mime_type": mime_type,
        "data_base64": base64.b64encode(payload_bytes).decode("ascii"),
    })
    result = read_message()
    if not result.get("ok"):
        raise RuntimeError("artifact publish failed: %s" % result["error"]["message"])
    return result["value"]


def main():
    init = read_message()
    assert init["type"] == "init"
    frames = init.get("arguments", {}).get("frames", 2)

    advance = call("frame_advance", {"frames": frames})
    frame = call("frame_capture", {})
    observations = json.dumps({
        "frames_completed": advance.get("frames_completed"),
        "frame_token": advance.get("frame_token"),
        "capture_sha256": frame.get("summary", {}).get("sha256"),
    }).encode("utf-8")
    published = publish_artifact(
        "experiment-observations", "application/json", observations
    )
    send({
        "type": "complete",
        "summary": {
            "frames_advanced": frames,
            "observations_artifact": published["id"],
            "observations_sha256": published["sha256"],
        },
    })


if __name__ == "__main__":
    main()