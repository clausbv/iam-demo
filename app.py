"""
IAM Demo Portal — OIDC Authorization Code + PKCE flow
Suporta Okta si Entra ID cu acelasi cod. Diferenta = doar config-ul.

Ruleaza:  python app.py
Deschide:  http://localhost:5000
"""
import os
import json
import time
import base64
from functools import wraps

from flask import Flask, session, redirect, url_for, request, jsonify, render_template
from authlib.integrations.flask_client import OAuth
from authlib.jose import jwt, JsonWebKey
import requests

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "schimba-asta-in-productie")

# ---------------------------------------------------------------------------
# CONFIG — completeaza din .env sau direct aici pentru fiecare IdP.
# "discovery" e URL-ul .well-known/openid-configuration. Authlib citeste de
# acolo TOATE endpoint-urile (authorize, token, jwks) automat. Asta e "OIDC
# discovery" — motivul pentru care acelasi cod merge pe ambele.
# ---------------------------------------------------------------------------
PROVIDERS = {
    "okta": {
        "client_id":     os.environ.get("OKTA_CLIENT_ID", ""),
        "client_secret": os.environ.get("OKTA_CLIENT_SECRET", ""),
        # ex: https://integrator-6711838.okta.com/oauth2/default/.well-known/openid-configuration
        "discovery":     os.environ.get("OKTA_DISCOVERY", ""),
    },
    "entra": {
        "client_id":     os.environ.get("ENTRA_CLIENT_ID", ""),
        "client_secret": os.environ.get("ENTRA_CLIENT_SECRET", ""),
        # ex: https://login.microsoftonline.com/<TENANT_ID>/v2.0/.well-known/openid-configuration
        "discovery":     os.environ.get("ENTRA_DISCOVERY", ""),
    },
}

oauth = OAuth(app)

# Inregistram fiecare provider. server_metadata_url = discovery.
# PKCE se activeaza cu code_challenge_method S256 — Authlib genereaza
# automat verifier-ul si challenge-ul.
for name, cfg in PROVIDERS.items():
    if cfg["discovery"]:
        oauth.register(
            name=name,
            client_id=cfg["client_id"],
            client_secret=cfg["client_secret"],
            server_metadata_url=cfg["discovery"],
            client_kwargs={
                "scope": "openid profile email",
                "code_challenge_method": "S256",  # <-- PKCE
            },
        )


# ---------------------------------------------------------------------------
# HELPER: decodeaza un JWT FARA sa-l valideze (doar ca sa-l afisam frumos).
# Validarea reala o face Authlib la login + functia verify_access_token de jos.
# ---------------------------------------------------------------------------
def decode_jwt_unverified(token):
    try:
        header_b64, payload_b64, _ = token.split(".")
        def _pad(s):
            return s + "=" * (-len(s) % 4)
        header = json.loads(base64.urlsafe_b64decode(_pad(header_b64)))
        payload = json.loads(base64.urlsafe_b64decode(_pad(payload_b64)))
        return {"header": header, "payload": payload}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# VALIDAREA "ca un Resource Server real": semnatura prin JWKS + iss + aud + exp.
# Asta e partea care conteaza la interviu — nu doar decodarea.
# ---------------------------------------------------------------------------
def verify_access_token(provider_name, token):
    cfg = PROVIDERS[provider_name]
    # 1. Ia metadata (contine jwks_uri + issuer)
    meta = requests.get(cfg["discovery"], timeout=10).json()
    jwks = requests.get(meta["jwks_uri"], timeout=10).json()
    key_set = JsonWebKey.import_key_set(jwks)

    # 2. Decodeaza + verifica semnatura cu cheia publica din JWKS
    claims = jwt.decode(token, key_set)

    # 3. Verifica claims: iss corect, exp nu a trecut
    errors = []
    if claims.get("iss") != meta["issuer"]:
        errors.append(f"iss mismatch: {claims.get('iss')} != {meta['issuer']}")
    if claims.get("exp", 0) < time.time():
        errors.append("token expirat (exp < now)")
    # aud: pe access token difera intre Okta si Entra — il aratam, nu blocam
    return {"claims": dict(claims), "errors": errors}


# ---------------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    configured = [n for n, c in PROVIDERS.items() if c["discovery"]]
    return render_template("index.html",
                           configured=configured,
                           user=session.get("user"),
                           provider=session.get("provider"))


@app.route("/login/<provider>")
def login(provider):
    if provider not in PROVIDERS:
        return "Provider necunoscut", 404
    session["provider"] = provider
    client = oauth.create_client(provider)
    redirect_uri = url_for("callback", provider=provider, _external=True)
    # Aici Authlib genereaza code_verifier (in sesiune) + code_challenge (in URL)
    return client.authorize_redirect(redirect_uri)


@app.route("/callback/<provider>")
def callback(provider):
    client = oauth.create_client(provider)
    # authorize_access_token: schimba ?code=... pe token FOLOSIND code_verifier.
    # Tot aici Authlib valideaza id_token-ul (semnatura, iss, aud, nonce).
    token = client.authorize_access_token()

    id_token = token.get("id_token")
    access_token = token.get("access_token")

    session["user"] = token.get("userinfo") or {}
    session["access_token"] = access_token
    session["tokens_decoded"] = {
        "id_token": decode_jwt_unverified(id_token) if id_token else None,
        "access_token": decode_jwt_unverified(access_token) if access_token else None,
    }
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("index"))
    return render_template("dashboard.html",
                           user=session["user"],
                           provider=session.get("provider"),
                           tokens=session.get("tokens_decoded", {}),
                           raw_access=session.get("access_token", ""))


@app.route("/validate")
def validate():
    """Ruleaza validarea completa (JWKS + iss + exp) pe access token-ul curent."""
    if "access_token" not in session:
        return redirect(url_for("index"))
    result = verify_access_token(session["provider"], session["access_token"])
    return render_template("validate.html", result=result, provider=session["provider"])


# ---------------------------------------------------------------------------
# ENDPOINT PROTEJAT — accepta doar Bearer token valid. Asta e "API protection".
# Testeaza cu:  curl -H "Authorization: Bearer <token>" http://localhost:5000/api/me
# ---------------------------------------------------------------------------
def require_bearer(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "lipseste Bearer token"}), 401
        token = auth.split(" ", 1)[1]
        provider = session.get("provider") or request.args.get("provider")
        if not provider:
            return jsonify({"error": "specifica ?provider=okta|entra"}), 400
        result = verify_access_token(provider, token)
        if result["errors"]:
            return jsonify({"error": "token invalid", "detalii": result["errors"]}), 401
        request.token_claims = result["claims"]
        return f(*args, **kwargs)
    return wrapper


@app.route("/api/me")
@require_bearer
def api_me():
    return jsonify({
        "mesaj": "Token valid. Ai acces la resursa protejata.",
        "sub": request.token_claims.get("sub"),
        "scope": request.token_claims.get("scp") or request.token_claims.get("scope"),
        "claims": request.token_claims,
    })


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
