# Social Media Privacy Risk Assessment Framework

A beginner-friendly defensive cybersecurity project based on a questionnaire-driven
social-media privacy risk framework.

## Features

- 40+ privacy questions
- 10 risk categories
- Configurable weighted 0–100 scoring model
- LOW / MODERATE / HIGH / CRITICAL classification
- Privacy findings and recommendations
- Privacy improvement simulator
- SQLite storage of minimal assessment metadata
- 1,000-record synthetic CSV generator
- Downloadable synthetic dataset
- Automated tests
- No social-media scraping
- No passwords, private messages, exact addresses, or real phone numbers required

## Technology

- Python
- Flask
- SQLite
- HTML/CSS/JavaScript
- pytest

## Run on Windows

```powershell
py -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open:

http://127.0.0.1:5000

## Run on Linux/macOS

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Generate synthetic dataset

The dashboard contains a button that creates and downloads 1,000 fictional records.
You can also run:

```bash
python -c "from app import generate_synthetic_dataset; print(generate_synthetic_dataset(1000))"
```

## Run tests

```bash
pytest -q
```

## Ethical scope

This project is designed for defensive cybersecurity and privacy education.
It uses synthetic or voluntarily provided assessment responses and does not scrape,
track, enumerate, or profile real social-media users.

The risk weights and thresholds are educational assumptions and should be calibrated
before any professional risk decision.
