# okta-authentik-migration

This project contains two Python scripts designed to automate the discovery of applications in Okta and provision the corresponding Providers and Applications in Authentik.

1. Software Requirements
- Python 3 installed on your system.

- Okta API Token.

- Authentik API Token.

- Authentik Flow UUIDs.
  
2. For security, all sensitive data is loaded from a local .env file which is excluded from Git by the .gitignore file.

3. The scripts rely on requests (for API communication) and python-dotenv (for secure secrets loading).
