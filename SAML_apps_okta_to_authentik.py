#!/usr/bin/env python3
import requests
import json
import logging
import time
import argparse
import os
from dotenv import load_dotenv

# --- Configuration ---
load_dotenv()

OKTA_DOMAIN = os.getenv("OKTA_DOMAIN")
OKTA_API_TOKEN = os.getenv("OKTA_API_TOKEN")

AUTHENTIK_BASE_URL = os.getenv("AUTHENTIK_BASE_URL")
AUTHENTIK_API_TOKEN = os.getenv("AUTHENTIK_API_TOKEN")

AUTH_FLOW_UUID = os.getenv("AUTH_FLOW_UUID")
INVALIDATION_FLOW_UUID = os.getenv("INVALIDATION_FLOW_UUID")

CERT_PATH = os.getenv("CERT_PATH")

# Basic check for essential variables
if not all([OKTA_API_TOKEN, AUTHENTIK_API_TOKEN, AUTH_FLOW_UUID, INVALIDATION_FLOW_UUID]):
    logging.error("Critical tokens or flow UUIDs are missing. Check your local .env file.")
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
parser = argparse.ArgumentParser(description="Migrate Okta SAML Apps to Authentik")
parser.add_argument("--dry-run", action="store_true", help="Simulate migration without creating anything")
args = parser.parse_args()
dry_run = args.dry_run

# === Helper Functions ===

def get_okta_saml_apps():
    """Fetches all SAML_2_0 applications from the Okta API."""
    logging.info("Fetching SAML apps from Okta...")
    apps = []
    url = f"{OKTA_DOMAIN}/api/v1/apps?limit=200"
    
    # Determine verification method
    verify_cert = CERT_PATH if CERT_PATH and CERT_PATH.lower() != 'false' else True
    
    while url:
        resp = requests.get(url, headers=okta_headers, verify=verify_cert)
        resp.raise_for_status()
        data = resp.json()
        for app in data:
            if app.get("signOnMode") == "SAML_2_0":
                apps.append(app)
        
        # Handle Pagination
        url = None
        if "link" in resp.headers:
            for link in resp.headers["link"].split(","):
                if 'rel="next"' in link:
                    url = link[link.find("<")+1:link.find(">")]
                    
    logging.info(f"Found {len(apps)} SAML apps.")
    return apps

def get_saml_details(app_id):
    """Retrieves detailed settings for a single SAML app."""
    url = f"{OKTA_DOMAIN}/api/v1/apps/{app_id}"
    
    # Determine verification method
    verify_cert = CERT_PATH if CERT_PATH and CERT_PATH.lower() != 'false' else True
    
    resp = requests.get(url, headers=okta_headers, verify=verify_cert)
    resp.raise_for_status()
    full = resp.json()

    settings = full.get("settings", {})
    app_settings = settings.get("app", {})
    signon_settings = settings.get("signOn", {})

    # Attempt to extract ACS URL from various common fields
    acs_url = signon_settings.get("ssoAcsUrl") or \
              app_settings.get("acsUrl") or \
              signon_settings.get("destination") or \
              app_settings.get("AssertionConsumerServiceUrl")

    # Attempt to extract Audience/Entity ID from various common fields
    audience = signon_settings.get("audience") or \
               app_settings.get("audience") or \
               app_settings.get("audienceUri") or \
               signon_settings.get("recipient") or \
               app_settings.get("entityId")

    nameid_format = app_settings.get("nameIdFormat") or signon_settings.get("subjectNameIdFormat")

    return {
        "acs_url": acs_url,
        "audience": audience,
        "nameid_format": nameid_format,
        "raw": full
    }

def create_saml_provider(app_label, saml_details):
    """Creates a new SAML provider in Authentik."""
    provider_slug = app_label.lower().replace(" ", "-")
    acs_url = saml_details["acs_url"]
    audience = saml_details["audience"]

    if not acs_url or not audience:
        logging.warning(f"Skipping {app_label}: Missing acs_url or audience.")
        if dry_run:
            logging.debug(f"[{app_label}] Full data: {json.dumps(saml_details['raw'], indent=2)}")
        return None

    provider_payload = {
        "name": provider_slug,
        "authorization_flow": AUTH_FLOW_UUID,
        "invalidation_flow": INVALIDATION_FLOW_UUID,
        "acs_url": acs_url,
        "issuer": audience,
        "property_mappings": [],  # Property mappings must be added manually/separately
        "user_matching_mode": "email_link", # Common default
        "sp_binding": "post",
        "digest_algorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        "signing_kid": None # Let Authentik choose a signing key
    }

    if dry_run:
        logging.info(f"[Dry-run] Would create SAML Provider for {app_label} (Slug: {provider_slug})")
        return {"name": provider_slug, "pk": f"dryprov-{provider_slug}"}

    url = f"{AUTHENTIK_BASE_URL}/api/v3/providers/saml/"
    verify_cert = CERT_PATH if CERT_PATH and CERT_PATH.lower() != 'false' else True
    
    resp = requests.post(url, headers=authentik_headers, json=provider_payload, verify=verify_cert)
    
    if resp.status_code >= 400:
        logging.error(f"Failed to create provider '{app_label}': {resp.status_code} -> {resp.text}")
        try:
            logging.error(f"Error Details: {resp.json()}")
        except json.JSONDecodeError:
            pass
        resp.raise_for_status()

    provider = resp.json()
    logging.info(f"Created SAML Provider '{app_label}' (slug: {provider['name']})")
    return provider

def create_authentik_application(name, provider_id):
    """Creates an Authentik Application and links it to the new provider."""
    url = f"{AUTHENTIK_BASE_URL}/api/v3/core/applications/"
    app_slug = name.lower().replace(" ", "-")
    app_payload = {
        "name": name,
        "slug": app_slug,
        "provider": provider_id,
        "open_in_new_tab": True,
        "policy_engine_mode": "all",
    }

    if dry_run:
        logging.info(f"[Dry-run] Would create Application '{name}' (Slug: {app_slug})")
        return {"name": name, "slug": app_slug, "id": f"dryapp-{app_slug}"}

    verify_cert = CERT_PATH if CERT_PATH and CERT_PATH.lower() != 'false' else True
    resp = requests.post(url, headers=authentik_headers, json=app_payload, verify=verify_cert)
    
    if resp.status_code >= 400:
        logging.error(f"Failed to create application '{name}': {resp.status_code} -> {resp.text}")
        resp.raise_for_status()

    app = resp.json()
    logging.info(f"Created Application '{name}' (slug: {app['slug']})")
    return app

def main():
    """Main execution function to orchestrate the SAML migration."""
    logging.info("-" * 50)
    logging.info(f"Starting Okta to Authentik SAML Migration. (Dry-run: {dry_run})")
    logging.info("-" * 50)
    
    try:
        okta_apps = get_okta_saml_apps()
    except Exception as e:
        logging.critical(f"FATAL: Could not connect to Okta API. Error: {e}")
        return
        
    created = []

    for app in okta_apps:
        label = app.get("label") or "untitled"
        logging.info(f"\nProcessing app: {label}")

        try:
            saml_details = get_saml_details(app["id"])
            provider = create_saml_provider(label, saml_details)
            if not provider:
                continue

            provider_id = provider.get("pk") or provider.get("name")
            application = create_authentik_application(label, provider_id)

            created.append({
                "okta_app": label,
                "acs_url": saml_details["acs_url"],
                "audience": saml_details["audience"],
                "authentik_provider_id": provider_id,
                "authentik_app_slug": application.get("slug"),
                "authentik_metadata_url": f"{AUTHENTIK_BASE_URL}/api/v3/providers/saml/{provider_id}/metadata/"
            })

        except Exception as e:
            logging.error(f"Failed on app '{label}': {e}")

        time.sleep(0.5)

    logging.info("\n" + "=" * 50)
    if not dry_run:
        output_file = "migrated_okta_to_authentik_saml.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(created, f, indent=2)
        logging.info(f"SAML migration done. Data written to {output_file}")
        logging.warning("REMINDER: You must manually configure SAML Property Mappings in Authentik and update application metadata.")
    else:
        logging.info("Dry-run complete. No changes were made to Authentik.")
    logging.info("=" * 50)

if __name__ == "__main__":
    main()
