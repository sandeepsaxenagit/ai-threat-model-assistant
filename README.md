# AI Threat Modeling Assistant

A deterministic AI/ML threat modeling engine that identifies security risks across LLMs, traditional machine learning systems, and agentic AI workflows.

🌐 **Live Tool:** https://aimlthreats.com

Unlike LLM-based tools, this engine uses a rule-based approach to produce consistent, explainable, and audit-friendly threat models.

---

##  Why this tool?

AI systems introduce new and evolving attack surfaces:

- Prompt injection  
- Data poisoning  
- Model extraction  
- Adversarial inputs  
- Agentic misuse and tool abuse  

Most teams struggle to:

- Identify relevant threats for their AI architecture  
- Map risks to compliance frameworks  
- Understand how to test and validate security controls  

This tool bridges that gap using deterministic logic instead of black-box AI.

---

##  Key Design Principle

This tool is **rule-based, not generative AI**.

### Why?

- No hallucinated threats  
- Fully explainable logic  
- Consistent outputs  
- Suitable for audits and compliance  
- Deterministic behavior across runs  

---

## ⚙️ Features

- ✅ Supports multiple AI types:
  - LLMs  
  - Traditional ML  
  - Agentic AI systems  

- 🔍 Threat identification based on system inputs  

- 🧩 Mapping to security frameworks:
  - OWASP Top 10 (LLM & ML)  
  - MITRE ATLAS  
  - NIST AI RMF (CIA + Abuse)  

- 🔗 Attack chain detection (deterministic patterns)  

- 🧪 “How to Test” guidance for each finding  

- 📊 Severity scoring with contextual adjustments  

- 📄 Clean, structured report output  

---

## How it works

1. User provides system details:
   - AI type (LLM / ML / Agentic)  
   - Data sensitivity  
   - Exposure (public/internal)  
   - Controls (validation, logging, etc.)  

2. Rules engine evaluates:
   - Threat conditions  
   - Control gaps  
   - Risk scoring  

3. Findings are:
   - Mapped to OWASP / MITRE / NIST  
   - Grouped into deterministic attack chains (when applicable)  

4. Output includes:
   - Severity (Low / Medium / High / Critical)  
   - Description of risk  
   - How to test  
   - Mitigation guidance  

---

## Example Output

- ### Scenario:
- AI Type: LLM  
- Exposure: Public  
- Input Validation: No  
- Output Filtering: No  
- Sensitive Data: Yes  

---

### Findings:

- Missing Input Validation → High  
- Missing Output Filtering → High  
- Sensitive Data Exposure Risk → High  

---

### Attack Chain (Triggered):

**Chain: Untrusted Input → Unsafe Processing → Data Exposure**
