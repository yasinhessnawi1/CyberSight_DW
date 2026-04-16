"""
CyberSight DW — API Service
Exposes backend log tailing and Kafka Dead-Letter-Queue browsing.
"""

import os
import re
import glob
import json
import logging
from collections import deque
from typing import Optional

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("api")

LOG_DIR = os.environ.get("LOG_DIR", "/logs")
KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092")
DLQ_TOPIC = "network-events-dlq"

LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)"
    r" \[(?P<logger>[^\]]+)\]"
    r" (?P<level>\w+):"
    r" (?P<message>.*)$"
)

app = FastAPI(title="CyberSight DW API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _tail_file(path: str, n: int) -> list[str]:
    """Return the last *n* lines of a file."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return list(deque(fh, maxlen=n))
    except FileNotFoundError:
        return []


def _parse_line(line: str, service: str) -> Optional[dict]:
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    return {
        "timestamp": m.group("timestamp"),
        "service": service,
        "level": m.group("level"),
        "logger": m.group("logger"),
        "message": m.group("message"),
    }


@app.get("/logs")
def get_logs(
    service: Optional[str] = Query(None, description="Filter by service name"),
    lines: int = Query(200, ge=1, le=5000, description="Max lines to return"),
):
    """Tail log files from all services and return merged entries."""
    pattern = os.path.join(LOG_DIR, "*.log")
    log_files = glob.glob(pattern)

    entries: list[dict] = []
    for path in log_files:
        svc_name = os.path.splitext(os.path.basename(path))[0]
        if service and svc_name != service:
            continue
        raw_lines = _tail_file(path, lines)
        for raw in raw_lines:
            parsed = _parse_line(raw, svc_name)
            if parsed:
                entries.append(parsed)

    entries.sort(key=lambda e: e["timestamp"], reverse=True)
    return entries[:lines]


@app.get("/dlq")
def get_dlq(
    limit: int = Query(200, ge=1, le=5000, description="Max messages to return"),
):
    """Read messages from the Kafka Dead-Letter-Queue topic."""
    messages: list[dict] = []
    try:
        consumer = KafkaConsumer(
            DLQ_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP,
            auto_offset_reset="earliest",
            enable_auto_commit=False,
            group_id=None,
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            consumer_timeout_ms=3000,
        )
    except NoBrokersAvailable:
        logger.warning("Kafka not reachable — returning empty DLQ")
        return messages

    try:
        for msg in consumer:
            messages.append(msg.value)
            if len(messages) >= limit:
                break
    finally:
        consumer.close()

    return messages


@app.get("/health")
def health():
    return {"status": "ok"}
