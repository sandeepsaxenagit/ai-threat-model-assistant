# 🛡️ AI Threat Modeling Assistant (Rule-Based)

This tool helps you identify risks in AI/ML systems based on deterministic rules mapped to:

- OWASP ML/LLM Top 10
- MITRE ATLAS tactics
- NIST CIA + Abuse categories
- Compliance (HIPAA, PCI, SOC2)

## 🚀 Features

- No OpenAI API required
- Streamlit UI + local rule engine
- Visual output (CIA radar, MITRE bar chart)
- Attack path simulation per threat

## 📦 Install and Run Locally

```bash
pip install -r requirements.txt
streamlit run main.py

