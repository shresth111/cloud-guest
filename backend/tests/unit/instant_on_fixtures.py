"""Recorded-shape fixtures for the Aruba Instant On portal API.

Built from the field names in ``wyfy-ops/aruba-ap21/REAL_DATA_SPIKE.md``
section 2.2 and ``RECON.md`` (live reads of the Wyfy test site,
2026-10-01/02) -- names and envelope (``{"elements": [...]}``) as measured,
values invented. Nothing here is a real token, secret or customer MAC.

Where a value was UNMEASURED on hardware (client signal, the alert time
format) the fixture says so; hardware check H1 replaces them.
"""

from __future__ import annotations

SITE_ID = "3f6c2a10-7b1d-4c9e-9a55-0d2e8b7c4f11"

INVENTORY = {
    "elements": [
        {
            # RECON section 1 shape: name = serial, model AP-503, status up.
            "name": "TESTSERIAL01",
            "serialNumber": "TESTSERIAL01",
            "macAddress": "02:00:5e:10:00:01",
            "model": "AP-503",
            "status": "up",
            "state": "active",
            "ipAddress": "192.0.2.10",
            "softwareVersion": "3.4.2.0-97182",
            "uptimeInSeconds": 7215,
            "operationalStateDurationInSeconds": 7215,
        }
    ]
}

# Bundle client model (SPIKE 2.2). Values UNMEASURED: no client had
# associated when the spike ran.
CLIENT_SUMMARY = {
    "elements": [
        {
            "macAddress": "02:11:22:33:44:55",
            "ipAddress": "172.30.1.23",
            "clientId": "c-1",
            "clientName": "Guest-Phone",
            "clientType": "smartphone",
            "hostName": "guest-phone",
            "connectionDurationInSeconds": 600,
            "wirelessNetworkId": "net-1",
            "wirelessNetworkName": "WYFY_ARUBA",
            "wirelessRadioId": "radio-5",
            "wirelessBands": ["fiveGHz"],
            "signalQuality": "good",
            "snrInDb": 38,
            "health": "good",
            "status": "connected",
            "downstreamDataTransferredInBytes": 1048576,
            "upstreamDataTransferredInBytes": 262144,
            "downstreamThroughputInBitsPerSecond": 800000,
            "upstreamThroughputInBitsPerSecond": 120000,
            "isWatchlisted": False,
        },
        {
            # A wired client: no wirelessNetworkId.
            "macAddress": "02-AA-BB-CC-DD-EE",
            "ipAddress": "172.30.1.2",
            "clientName": "Printer",
            "connectionDurationInSeconds": 86400,
        },
    ]
}

NETWORKS_SUMMARY = {
    "elements": [
        {
            "id": "net-1",
            "networkName": "WYFY_ARUBA",
            "isEnabled": True,
            "type": "guest",
            "isGuestPortalEnabled": True,
        }
    ]
}

ALERTS = {
    "elements": [
        {
            # RECON: one deviceDown raised+cleared around a power cycle.
            "id": "a-1",
            "type": "deviceDown",
            "severity": "major",
            "status": "cleared",
            "isCleared": True,
            "raisedTime": 1759370000000,  # format UNMEASURED; epoch ms here
            "clearedTime": "2026-10-02T01:30:00Z",
            "duration": 120,
            "deviceName": "TESTSERIAL01",
        }
    ]
}

SYSTEM_HEALTH = {"healthScore": 100, "status": "good"}

CLIENT_USAGE = {
    "elements": [
        {
            "clientId": "c-1",
            "clientName": "Guest-Phone",
            "clientCurrentlyActive": True,
            "dataTransferredDuringLast24HoursInBytes": 5242880,
            "applicationCategory": "allAppCategories",
        }
    ]
}

SITES = {"elements": [{"id": SITE_ID, "name": "test-site"}]}

PORTAL_SETTINGS = {
    "restApiUrl": "https://portal.instant-on.hpe.com/api/",
    "ssoFqdn": "https://sso.arubainstanton.com",
    "ssoClientIdAuthZ": "test-public-client-id",
}

RESOURCE_BODIES = {
    "inventory": INVENTORY,
    "clientSummary": CLIENT_SUMMARY,
    "networksSummary": NETWORKS_SUMMARY,
    "alerts": ALERTS,
    "systemHealth": SYSTEM_HEALTH,
    "usage": CLIENT_USAGE,
}
