"""Taxonomy and deterministic mapping rules (interface -> attack surface -> STRIDE)."""
import re

INTERFACES = {
    "CAN": "CAN",
    "ETH": "Ethernet",
    "DIAG": "Diagnostics (OBD-II)",
    "OTA": "OTA update",
    "BACKEND": "Backend / cellular",
    "HW": "Hardware / debug / keys",
}

# Keywords used to infer which interface(s) a question refers to (metadata filter for retrieval).
INTERFACE_KEYWORDS = {
    "OTA": [r"\bota\b", r"over[- ]the[- ]air", r"\bupdates?\b", r"\bmanifest\b", r"\brollback\b", r"\bdowngrade\b", r"firmware image"],
    "DIAG": [r"diagnos\w*", r"\bobd\b", r"obd-?ii", r"\buds\b", r"\bdoip\b", r"\bdtc\b", r"security access"],
    "CAN": [r"\bcan\b", r"can-?fd", r"\bcan bus\b", r"powertrain", r"body can", r"\bsecoc\b", r"gateway"],
    "ETH": [r"ethernet", r"some/?ip", r"\bvlan\b", r"\bswitch\b", r"macsec", r"100base"],
    "BACKEND": [r"backend", r"cloud", r"cellular", r"\btls\b", r"telematics data", r"remote (lock|command)", r"\bmqtt\b"],
    "HW": [r"\bhsm\b", r"\bkeys?\b", r"key material", r"\bjtag\b", r"\buart\b", r"\bdebug\b", r"secure boot"],
}


def detect_interfaces(text: str) -> list[str]:
    t = text.lower()
    found = [i for i, pats in INTERFACE_KEYWORDS.items() if any(re.search(p, t) for p in pats)]
    # "update server"/"update channel" talk about OTA even if "backend" also matches
    return found


# Deterministic interface -> attack-surface rules. Evidence (citations) is attached from the
# project documents at run time; an interface is only mapped if the project documents mention it.
SURFACE_RULES = {
    "DIAG": [
        {"entry_point": "OBD-II connector: UDS diagnostic sessions", "vector": "Unauthorised diagnostic session / security-access bypass", "asset_tags": ["diag_access"], "exposure": "Physical, external"},
        {"entry_point": "OBD-II connector: UDS request download", "vector": "Unauthorised firmware flashing through programming services", "asset_tags": ["tcu_firmware"], "exposure": "Physical, external"},
        {"entry_point": "OBD-II connector: CAN message injection", "vector": "CAN message injection from the diagnostic connector", "asset_tags": ["can_signals", "diag_access"], "exposure": "Physical, external"},
        {"entry_point": "OBD-II connector: DoIP and read data by identifier", "vector": "Unauthorised access and data read-out; request flooding", "asset_tags": ["telematics_data", "diag_access"], "exposure": "Physical, external"},
    ],
    "CAN": [
        {"entry_point": "Body CAN (unauthenticated frames)", "vector": "Message injection and replay", "asset_tags": ["can_signals"], "exposure": "Physical or via compromised node"},
        {"entry_point": "Powertrain CAN via gateway", "vector": "Pivot from a compromised ECU, flooding", "asset_tags": ["can_signals"], "exposure": "Via gateway routing"},
    ],
    "ETH": [
        {"entry_point": "100BASE-T1 link to head unit and ADAS controller", "vector": "Rogue device, spoofed SOME/IP service, eavesdropping", "asset_tags": ["eth_services"], "exposure": "Physical or via compromised node"},
        {"entry_point": "Automotive Ethernet switch / VLANs", "vector": "VLAN hopping and misconfiguration", "asset_tags": ["eth_services"], "exposure": "Via compromised node"},
    ],
    "OTA": [
        {"entry_point": "OTA client: update download channel", "vector": "Spoofed server, man-in-the-middle, tampered package", "asset_tags": ["ota_package", "backend_link"], "exposure": "Remote, network"},
        {"entry_point": "OTA client: manifest handling and version check", "vector": "Manifest manipulation, rollback to vulnerable version", "asset_tags": ["update_manifest", "tcu_firmware"], "exposure": "Remote, network"},
    ],
    "BACKEND": [
        {"entry_point": "Cellular modem: TLS link to OEM backend", "vector": "Credential theft, forged remote commands, data exposure", "asset_tags": ["backend_link", "telematics_data"], "exposure": "Remote, network"},
    ],
    "HW": [
        {"entry_point": "JTAG / UART debug ports", "vector": "Firmware dump, key extraction", "asset_tags": ["tcu_firmware", "key_material"], "exposure": "Physical"},
    ],
}

# Name normalisation (report: normalisation of signal, ECU and interface names).
ALIASES = {
    r"telematics control unit|telematics unit|tcu-gen2|tcu gen2": "TCU",
    r"on[- ]board diagnostics?|obd-?ii connector": "OBD-II",
    r"over[- ]the[- ]air": "OTA",
    r"hardware security module": "HSM",
}


def normalise_names(text: str) -> str:
    for pat, repl in ALIASES.items():
        text = re.sub(pat, repl, text, flags=re.IGNORECASE)
    return text
