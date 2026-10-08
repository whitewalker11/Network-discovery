#!/usr/bin/env python3
"""Small Linux metrics agent used to exercise the scanner onboarding flow."""

import json
import platform
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path


def cpu_sample(seconds=0.25):
    def read():
        with open("/proc/stat", encoding="utf-8") as f:
            fields = [int(x) for x in f.readline().split()[1:]]
        idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
        return sum(fields), idle

    total1, idle1 = read()
    time.sleep(seconds)
    total2, idle2 = read()
    delta = total2 - total1
    return round(100 * (delta - (idle2 - idle1)) / delta, 1) if delta else 0.0


def memory_sample():
    values = {}
    with open("/proc/meminfo", encoding="utf-8") as f:
        for line in f:
            key, value = line.split(":", 1)
            if key in ("MemTotal", "MemAvailable"):
                values[key] = int(value.strip().split()[0]) * 1024
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", 0)
    used = total - available
    return {
        "total_bytes": total,
        "used_bytes": used,
        "used_percent": round(100 * used / total, 1) if total else None,
    }


def network_sample():
    received = sent = 0
    with open("/proc/net/dev", encoding="utf-8") as f:
        for line in f.readlines()[2:]:
            name, counters = line.split(":", 1)
            if name.strip() == "lo":
                continue
            values = [int(x) for x in counters.split()]
            received += values[0]
            sent += values[8]
    return {"received_bytes": received, "sent_bytes": sent}


def primary_mac():
    interfaces = []
    try:
        with open("/proc/net/route", encoding="utf-8") as f:
            interfaces = [
                fields[0] for fields in (line.split() for line in f.readlines()[1:])
                if len(fields) > 3 and fields[1] == "00000000" and int(fields[3], 16) & 1
            ]
    except (OSError, ValueError):
        pass
    try:
        interfaces.extend(p.name for p in Path("/sys/class/net").iterdir() if p.name != "lo")
    except OSError:
        pass
    for name in dict.fromkeys(interfaces):
        try:
            value = Path("/sys/class/net", name, "address").read_text(encoding="utf-8").strip().lower()
            if value and value != "00:00:00:00:00:00":
                return value
        except OSError:
            continue
    return ""


def main():
    disk = shutil.disk_usage("/")
    uptime = None
    try:
        with open("/proc/uptime", encoding="utf-8") as f:
            uptime = round(float(f.read().split()[0]), 1)
    except (OSError, ValueError):
        pass
    result = {
        "agent": "network-scanner-sample",
        "hostname": platform.node(),
        "mac_address": primary_mac(),
        "platform": platform.platform(),
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "cpu_percent": cpu_sample(),
        "memory": memory_sample(),
        "disk_root": {
            "total_bytes": disk.total,
            "used_bytes": disk.used,
            "used_percent": round(100 * disk.used / disk.total, 1) if disk.total else None,
        },
        "network": network_sample(),
        "uptime_seconds": uptime,
    }
    print(json.dumps(result))


if __name__ == "__main__":
    main()
