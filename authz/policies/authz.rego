package apisix.authz

import future.keywords

default allow = false
default reason = "none"

headers := input.request.headers
authorization := headers.authorization
device_id := headers["x-device-id"]
device_nonce := headers["x-device-nonce"]
device_timestamp := headers["x-device-timestamp"]
device_signature := headers["x-device-signature"]

# ─── Cas 0 : Always allow HEAD ──────────────────────────────
allow if {
    input.request.method == "HEAD"
}

# ─── Cas 1 : utilisateur direct avec device actif ──────────────────────────────
# ─── Cas 2 : device actif + signature vérifiée (device-bound session) ──────────
# ─── Cas 3 : device actif avec signature enregistrée → signature obligatoire ───
allow if {
    device_active
    not device_signature_required
}

allow if {
    device_active
    device_signature_required
    device_signature_verified
}
# ─── Signature device requise si le device a une clé publique enregistrée ──────
device_signature_required if {
    device_response.status_code == 200
    device_response.body.public_key != null
    device_response.body.public_key != ""
}

# ─── Appel HTTP partagé : status du device ─────────────────────────────────────
device_response := response if {
    response := http.send({
        "method":  "GET",
        "url":     sprintf("%s/devices/%s/status", [opa.runtime().env.DEVICE_SERVICE_URL, device_id]),
        "headers": {
            "Accept": "application/json",
            "Authorization": authorization,
        },
        "cache":   true,
        "timeout": "2s",
    })
}

# ─── Appel HTTP : trust score du device ────────────────────────────────────────
trust_response := response if {
    response := http.send({
        "method":  "GET",
        "url":     sprintf("%s/devices/%s/trust", [opa.runtime().env.DEVICE_SERVICE_URL, device_id]),
        "headers": {
            "Accept": "application/json",
            "Authorization": authorization,
        },
        "cache":   true,
        "timeout": "2s",
    })
}

# ─── Appel HTTP : vérification signature X-Device-* ───────────────────────────
# Service B forward les headers dans headers
# OPA délègue la vérification crypto au device-service
verify_response := response if {
    device_signature
    response := http.send({
        "method":  "POST",
        "url":     sprintf("%s/devices/%s/verify", [opa.runtime().env.DEVICE_SERVICE_URL, device_id]),
        "headers": {
            "Accept":       "application/json",
            "Content-Type": "application/json",
            "Authorization": authorization,
        },
        "body": {
            "device_id": device_id,
            "nonce":     device_nonce,
            "timestamp": device_timestamp,
            "signature": device_signature,
        },
        "timeout": "2s",
    })
}

# # ─── Règles device de base ─────────────────────────────────────────────────────
device_id_provided if {
    not device_id == ""
}

device_active if {
    device_id_provided
    device_response.status_code == 200
    device_response.body.status == "active"
}

# ─── Vérification signature device ────────────────────────────────────────────
device_signature_verified if {
    verify_response.status_code == 200
    verify_response.body.verified == true
}

# ─── Raisons du refus (pour les logs d'audit) ─────────────────────────────────
reason := "device_revoked" if {
    device_response.body.status == "revoked"
}

reason := "device_suspended" if {
    device_response.body.status == "suspended"
}

reason := "device_pending_approval" if {
    device_response.body.status == "pending_approval"
}

reason := "device_signature_invalid" if {
    device_active
    device_signature
    not device_signature_verified
}

reason := "device_not_active" if {
    not headers
    not device_active
}

reason := "missing header" if {
    not device_id_provided
}