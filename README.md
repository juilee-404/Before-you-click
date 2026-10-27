# Before You Click — Link Safety Checker

A beginner-friendly Python + Flask cybersecurity PBL project.

## What it does

The app analyzes a URL using explainable heuristic checks:

- HTTPS presence
- IP-address destinations
- Punycode
- URL shorteners
- suspicious TLDs
- excessive subdomains
- suspicious keywords
- `@` symbols
- username information
- long URLs and query strings
- possible brand-lookalike patterns

It produces a 0–100 heuristic risk score and explains the signals.

## Important limitation

This is an educational heuristic checker. It does NOT guarantee that a website is safe or malicious. A real security product would need threat-intelligence feeds, reputation databases, sandboxing, continuous updates and much more.

This first version intentionally does not automatically open arbitrary URLs on the server.

## Run locally

### 1. Install Python

Install Python 3.13 or another supported Python 3 version.

Check:

```bash
python --version
```

On Windows, this may also work:

```bash
py --version
```

### 2. Open the project in VS Code

Open the `before_you_click` folder.

### 3. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use Command Prompt:

```cmd
python -m venv .venv
.venv\Scripts\activate
```

### 4. Install packages

```bash
pip install -r requirements.txt
```

### 5. Run

```bash
python app.py
```

Open:

http://127.0.0.1:5000

## Deploy to Render

Push the project to GitHub.

Then create a Render Web Service from the repository.

Build command:

```bash
pip install -r requirements.txt
```

Start command:

```bash
gunicorn app:app
```

The included `render.yaml` already contains these settings.

## Project structure

```text
before_you_click/
│
├── app.py
├── requirements.txt
├── render.yaml
├── .python-version
├── .gitignore
├── README.md
│
├── templates/
│   └── index.html
│
└── static/
    ├── style.css
    └── app.js
```
