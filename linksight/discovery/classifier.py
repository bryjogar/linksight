"""Device classification based on sysDescr, sysName, and sysObjectID."""

from __future__ import annotations

FIREWALL_KEYWORDS = [
    "palo alto",
    "pan-os",
    "fortigate",
    "fortios",
    "adaptive security appliance",
    "cisco asa",
    "firepower",
    "checkpoint",
    "pfsense",
    "opnsense",
    "sonicwall",
    "srx",
    "watchguard",
    "firewall",
    "fw-",
    "-fw",
    "firebox",
    "sophos",
    "barracuda",
]

ROUTER_KEYWORDS = [
    "router",
    "isr",
    "asr",
    "vyos",
    "mikrotik",
    "routeros",
    "junos",
    "edgeos",
    "gateway",
    "rt-",
    "-rt",
    "rtr-",
    "-rtr",
    "cisco 8",
    "cisco 19",
    "cisco 29",
    "cisco 39",
    "cisco 4",
]

SWITCH_KEYWORDS = [
    "switch",
    "catalyst",
    "nexus",
    "procurve",
    "aruba",
    "comware",
    "eos",
    "edgeswitch",
    "icx",
    "powerconnect",
    "fastpath",
    "sw-",
    "-sw",
]


def classify_device(sys_descr: str, sys_name: str = "", sys_object_id: str = "") -> str:
    """Classify device into 'firewall', 'router', 'switch', or 'unknown'.

    Evaluation order: firewall -> router -> switch.
    """
    text = f"{sys_descr} {sys_name} {sys_object_id}".lower()

    for kw in FIREWALL_KEYWORDS:
        if kw in text:
            return "firewall"

    for kw in ROUTER_KEYWORDS:
        if kw in text:
            return "router"

    for kw in SWITCH_KEYWORDS:
        if kw in text:
            return "switch"

    return "switch"


def is_edge_device(device_type: str) -> bool:
    """Return True if device type represents a network edge / gateway."""
    return device_type.lower() in ("router", "firewall", "gateway", "edge")
