#!/usr/bin/env python3
import requests
import json
import logging
import time
import argparse
import re
import os
from dotenv import load_dotenv

# --- Configuration ---
load_dotenv()

OKTA_DOMAIN = os.getenv("OKTA_DOMAIN")
OKTA_API_TOKEN = os.getenv("OKTA_API_TOKEN")

AUTHENTIK_BASE_URL = os.getenv("AUTHENTIK_BASE_URL")
AUTHENTIK_API_TOKEN = os.getenv("AUTHENTIK_API_TOKEN")

# UUIDs from your Authentik flows
AUTH_FLOW_UUID = os.getenv("AUTH_FLOW_UUID")
INVALIDATION_FLOW_UUID = os.getenv("INVALIDATION_FLOW_UUID")

CERT_PATH = os.getenv("CERT_PATH")

# Basic check for essential variables
if not all([OKTA_API_TOKEN, AUTHENTIK_API_TOKEN]):
    logging.error("Critical tokens are missing. Check your local .env file.")
    exit(1)


# === Logging ===
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# === Headers ===
okta_headers = {
    "Authorization": f"SSWS {OKTA_API_TOKEN}",
    "Accept": "application/json"
}

authentik_headers = {
    "Authorization": f"Bearer {AUTHENTIK_API_TOKEN}",
    "Content-Type": "application/json"
}

# === CLI Args ===
parser = argparse.ArgumentParser(description="Migrate Okta OIDC apps to Authentik")
parser.add_argument("--dry-run", action="store_true", help="Simulate migration without creating anything")
args = parser.parse_args()
dry_run = args.dry_run

# === Helper Functions ===

def slug(name: str) -> str:
    """Converts a name string into a URL-friendly slug."""
    name = name.lower().strip()
    slug = re.sub(r'[^a-z0-9_-]', '-', name)
    slug = re.sub(r'-+', '-', slug)
    return slug.strip('-')

def get_okta_oidc_apps():
    """Fetches all OIDC/OAuth2 applications from the Okta B2E."""
    logging.info("Fetching OIDC apps from Okta...")
    apps = []
    url = f"{OKTA_DOMAIN}/api/v1/apps?limit=200"
    while url:
        # Use CERT_PATH for verification if provided, otherwise use default
        verify_cert = CERT_PATH if CERT_PATH else True
        resp = requests.get(url, headers=okta_headers, verify=verify_cert)
        resp.raise_for_status()
        items = resp.json()
        for app in items:
            if app.get("signOnMode") in ("OPENID_CONNECT", "OIDC", "OAUTH2"):
                apps.append(app)
        
        # Handle Pagination
        url = None
        if "link" in resp.headers:
            for link in resp.headers["link"].split(","):
                if 'rel="next"' in link:
                    url = link[link.find("<")+1 : link.find(">")]
    
    logging.info(f"Found {len(apps)} OIDC apps.")
    return apps

def get_oidc_details(app):
    """Extracts required OIDC details from Okta app object."""
    settings = app.get("settings", {})
    # Okta can store client data under 'oauthClient' or 'client'
    oauth_client = settings.get("oauthClient", {}) or settings.get("client", {})
    
    # Okta can store redirect URIs under 'redirect_uris' or 'redirectUri'
    redirect_uris = oauth_client.get("redirect_uris") or oauth_client.get("redirectUri") or []
    
    # Ensure redirect_uris is a list, even if it was a single string in some Okta fields
    if isinstance(redirect_uris, str):
        redirect_uris = [redirect_uris]

    return {
        "redirect_uris": redirect_uris,
        "raw": app
    }

def create_oidc_provider(app_label: str, oidc_details: dict):
    """Creates a new OIDC provider in Authentik."""
    provider_slug = slugify(app_label)
    redirect_uris = oidc_details["redirect_uris"]

    if not redirect_uris:
        logging.warning(f"Skipping {app_label}: Missing redirect_uris.")
        if dry_run:
            logging.debug(f"[{app_label}] OIDC raw: {json.dumps(oidc_details['raw'], indent=2)}")
        return None

    # Authentik requires redirect URIs to be a list of objects
    redirect_uris_payload = [{"url": uri, "matching_mode": "strict"} for uri in redirect_uris]

    provider_payload = {
        "name": provider_slug,
        "authorization_flow": AUTH_FLOW_UUID,
        "invalidation_flow": INVALIDATION_FLOW_UUID,
        "redirect_uris": redirect_uris_payload,
        "client_type": "confidential",
        "response_types": ["code"],
        "redirect_behavior": "default",
        "name_claim": "name",
        "sub_mode": "persistent",
    }

    if dry_run:
        logging.info(f"[Dry-run] Would create OIDC Provider '{app_label}'. Payload preview: {json.dumps(provider_payload)}")
        return {"name": provider_slug, "pk": f"dryprov-{provider_slug}", "client_id": "<dry>", "client_secret": "<dry>"}

    url = f"{AUTHENTIK_BASE_URL}/api/v3/providers/oauth2/"
    
    verify_cert = CERT_PATH if CERT_PATH else True
    resp = requests.post(url, headers=authentik_headers, json=provider_payload, verify=verify_cert)
    
    if resp.status_code >= 400:
        logging.error(f"Failed to create OIDC provider '{app_label}': {resp.status_code} -> {resp.text}")
        try:
            logging.error(f"Error Details: {resp.json()}")
        except json.JSONDecodeError:
            logging.error("Response was not JSON.")
        resp.raise_for_status()

    provider = resp.json()
    logging.info(f"Created OIDC Provider '{app_label}' (slug: {provider.get('name')})")
    logging.info(f"Client ID: {provider.get('client_id')}")
    logging.info(f"Client Secret: {provider.get('client_secret')}")
    return provider

def create_authentik_application(name: str, provider_id):
    """Creates an Authentik Application and links it to the new provider."""
    url = f"{AUTHENTIK_BASE_URL}/api/v3/core/applications/"
    app_slug = slugify(name)
    app_payload = {
        "name": name,
        "slug": app_slug,
        "provider": provider_id,
        "open_in_new_tab": True,
        "policy_engine_mode": "all" # All policies
    }

    if dry_run:
        logging.info(f"[Dry-run] Would create Application '{name}': {json.dumps(app_payload)}")
        return {"name": name, "slug": app_slug, "id": f"dryapp-{app_slug}"}

    verify_cert = CERT_PATH if CERT_PATH else True
    resp = requests.post(url, headers=authentik_headers, json=app_payload, verify=verify_cert)
    
    if resp.status_code >= 400:
        logging.error(f"Failed to create application '{name}': {resp.status_code} -> {resp.text}")
        resp.raise_for_status()

    app = resp.json()
    logging.info(f"✔ Created Application '{name}' (slug: {app.get('slug')})")
    return app

def main():
    """Main execution function to orchestrate the migration."""
    logging.info("-" * 50)
    logging.info(f"Starting Okta to Authentik OIDC Migration. (Dry-run: {dry_run})")
    logging.info("-" * 50)

    try:
        apps = get_okta_oidc_apps()
    except Exception as e:
        logging.critical(f"FATAL: Could not connect to Okta API. Check OKTA_DOMAIN, OKTA_API_TOKEN, and CERT_PATH. Error: {e}")
        return

    results = []

    for app in apps:
        label = app.get("label") or app.get("name") or "unnamed-app"
        logging.info(f"\nProcessing OIDC app: {label}")

        try:
            oidc_details = get_oidc_details(app)
            provider = create_oidc_provider(label, oidc_details)
            if not provider:
                continue

            provider_id = provider.get("pk") or provider.get("name") # Use PK if available, fallback to name/slug
            application = create_authentik_application(label, provider_id)

            results.append({
                "okta_app": label,
                "redirect_uris": oidc_details["redirect_uris"],
                "authentik_provider": provider_id,
                "authentik_client_id": provider.get("client_id"),
                "authentik_client_secret": provider.get("client_secret"),
                "authentik_app_slug": application.get("slug")
            })

        except Exception as e:
            logging.error(f"Failed on app '{label}'. Review detailed error and skip: {e}")

        time.sleep(0.5)

    logging.info("\n" + "=" * 50)
    if not dry_run:
        output_file = "migrated_okta_oidc_to_authentik.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        logging.info(f"OIDC migration done. Output written to {output_file}")
    else:
        logging.info("Dry-run complete. No changes were made to Authentik.")
    logging.info("=" * 50)


if __name__ == "__main__":
    main()
