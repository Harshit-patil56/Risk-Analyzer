# Risk Analyzer

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white) ![Node.js](https://img.shields.io/badge/Node.js-339933?style=flat-square&logo=nodedotjs&logoColor=white) ![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white) ![Next.js](https://img.shields.io/badge/Next.js-000000?style=flat-square&logo=nextdotjs&logoColor=white)

Risk Analyzer is a security intelligence tool designed to detect phishing, scams, and fraudulent activity across multiple digital channels. It combines machine learning models with rule-based heuristics and external threat intelligence to provide explainable risk scores for URLs, emails, social media content, and QR codes.

## Core Features

* **URL Analysis:** Checks domain reputation, TLD safety, and brand impersonation patterns.
* **Content Scanning:** Detects urgency, threatening language, and scam indicators in emails and social media posts.
* **QR Code Decoding:** Extracts URLs from QR images and subjects them to the full security pipeline.
* **Explainable Scoring:** Provides a 0-100 risk rating with specific reasons for each flag.
* **External Intelligence:** Optional integration with Google Safe Browsing and VirusTotal for verified threat data.

## Project Structure

* `backend/`: FastAPI server handling ML inference and scoring logic.
* `frontend/`: Next.js dashboard for interactive scanning and reporting.
* `extension/`: Manifest v3 browser extension for real-time protection.

## Technical Specifications

The system utilizes three specialized machine learning models located in the `backend/models/` directory:

* **Phishing Model (Gradient Boosting):** Analyzes URL structures and metadata.
* **Social/Email Model (Logistic Regression):** Processes text content via TF-IDF vectorization to identify phishing language.
* **Transaction Model (XGBoost):** Identifies patterns indicative of financial fraud.

## Requirements

* Python 3.10+
* Node.js 18+
* (Optional) API Keys for Google Safe Browsing and VirusTotal

## Setup Guide

### 1. Backend Setup

Navigate to the backend directory, set up a virtual environment, and install dependencies.

```bash
cd backend
python -m venv .venv

# Activate venv (Unix)
source .venv/bin/activate

# Activate venv (Windows)
.venv\Scripts\activate

pip install -r requirements.txt
python main.py
```

### 2. Frontend Setup

Navigate to the frontend directory and start the development server.

```bash
cd frontend
npm install
npm run dev
```
