<<<<<<< HEAD
# AI Test Case Generator — v6

A Flask web app that generates comprehensive, industry-standard test cases
from plain-English requirements.

---

## What's new in v6

- **Requirement Name first, Requirement Details below** — the input form
  and results page now match the specification exactly.
- **AI-powered generation via Claude (Anthropic API)** — when
  `ANTHROPIC_API_KEY` is set, each requirement is sent to Claude Sonnet
  and gets its own unique, real-world test cases tailored to that specific
  requirement. No merging across requirements.
- **Graceful fallback** — if the API key is absent or the call fails, the
  original keyword-rule engine (v5) is used automatically.
- **Per-requirement result blocks** — results page shows:
  1. Requirement Name (large heading)
  2. Requirement Details (indented block)
  3. Full test case table for that requirement only
  Then a divider, then the next requirement block.

---

## Setup

```bash
pip install -r requirements.txt
```

### With AI generation (recommended)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python app.py
```

### Without API key (rule-based fallback)

```bash
python app.py
```

---

## Running

```
python app.py
```

Open http://127.0.0.1:5000 in your browser.

---

## Project structure

```
ai_test_case_generator_v6/
├── app.py                  Flask routes + Excel download
├── test_generator.py       AI + rule-based test case engine
├── requirements.txt
├── templates/
│   ├── index.html          Input form
│   └── results.html        Results page
└── static/
    ├── style.css
    ├── bg_main.png
    └── bg_results.png
```

---

## Excel download

After generation, click **Download Excel (.xlsx)** to get a workbook with:
- A cover sheet listing all requirements and total test count
- One sheet per requirement with full test case table
=======
# ai-test-case-generator
Developed a Flask-based web application that converts plain-English requirements into industry-standard test cases using AI-powered generation with a rule-based fallback. Integrated a results dashboard and one-click Excel export to streamline QA workflows and improve testing efficiency.
>>>>>>> c36a2360993e959a352b62d4411d9caee34c364d
