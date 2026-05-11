# Watchtower

A simple Flask uptime monitoring MVP for tracking websites, response times, status codes, and recent incidents.

## Features

- Add websites to monitor
- Run a check for one website or all websites
- Store check history in SQLite
- Show current up, warning, and down counts
- Clean responsive dashboard UI

## Run Locally

1. Create a virtual environment:

   ```powershell
   python -m venv .venv
   ```

2. Activate it:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, use:

   ```powershell
   .\.venv\Scripts\activate.bat
   ```

3. Install dependencies:

   ```powershell
   pip install -r requirements.txt
   ```

4. Start the app:

   ```powershell
   python run_dev.py
   ```

5. Open the local app:

   ```text
   http://127.0.0.1:5002
   ```

## Test URLs

- `https://jxyf99.github.io/portfolio/`
- `https://phishcheck-qnp6.onrender.com`
- `https://bugboard-no3e.onrender.com`
- `https://example.com`

## Notes

This MVP only checks websites when you click a button. A future version could add scheduled background checks, email alerts, team accounts, charts, and hosted deployment.

## Security Notes

- Set `SECRET_KEY` in Render environment variables so CSRF/session protection uses a production secret.
- Watchtower only allows public `http` and `https` targets on ports 80 and 443.
- Localhost, private networks, link-local metadata addresses, internal hostnames, embedded credentials, and unsafe redirects are blocked before checks run.
