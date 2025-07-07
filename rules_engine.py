# rules_engine.py

def evaluate_threats(inputs):
    threats = []

    # 1. Prompt Injection
    if inputs["input_validation"] == "None" and inputs["exposure"] == "Public":
        threats.append({
            "id": "prompt_injection",
            "threat": "Prompt Injection Risk",
            "description": "Unvalidated public inputs may lead to prompt injection or override of system instructions.",
            "owasp": "LLM01: Prompt Injection",
            "mitre": "TA0001: Initial Access",
            "nist": ["Integrity", "Abuse"],
            "mitigation": "Use input validation and prompt templating. Employ LLM firewalls.",
            "compliance": ["HIPAA", "SOC2"],
            "attack_path": [
                "Step 1: User submits malicious prompt",
                "Step 2: Prompt bypasses validation",
                "Step 3: Model executes injected instruction",
                "Step 4: Sensitive data leaked or task hijacked"
            ]
        })

    # 2. Plugin Abuse
    if inputs["plugin_access"] == "Yes" and inputs["sandboxing"] == "No":
        threats.append({
            "id": "plugin_abuse",
            "threat": "Unsafe Plugin Access",
            "description": "Plugins can be abused by LLMs to take unexpected actions without containment.",
            "owasp": "LLM07: Insecure Plugin Design",
            "mitre": "TA0002: Execution",
            "nist": ["Confidentiality", "Abuse"],
            "mitigation": "Isolate plugin environments and monitor plugin interactions.",
            "compliance": ["SOC2"],
            "attack_path": [
                "Step 1: User triggers plugin through prompt",
                "Step 2: Plugin executed without restrictions",
                "Step 3: Access to internal or sensitive systems",
                "Step 4: Data leaked or destructive actions taken"
            ]
        })

    # 3. RAG External Data Injection / SSRF
    if inputs["external_sources"] == "Yes":
        threats.append({
            "id": "rag_ssrf",
            "threat": "External Data Injection / SSRF",
            "description": "Use of external data via RAG can allow attackers to inject malicious content or trigger SSRF.",
            "owasp": "LLM06: Sensitive Information Disclosure",
            "mitre": "TA0009: Collection",
            "nist": ["Confidentiality", "Integrity"],
            "mitigation": "Validate and sanitize external inputs. Apply domain allowlists.",
            "compliance": ["HIPAA", "SOC2"],
            "attack_path": [
                "Step 1: Model fetches external content",
                "Step 2: Attacker injects crafted URL or payload",
                "Step 3: SSRF triggered internally",
                "Step 4: Internal metadata or secrets exposed"
            ]
        })

    # 4. Data Poisoning
    if inputs["user_influence"] == "Yes":
        threats.append({
            "id": "data_poisoning",
            "threat": "Training Data Poisoning",
            "description": "Users influence training data and poison model outputs.",
            "owasp": "ML02: Data Poisoning",
            "mitre": "TA0042: Resource Development",
            "nist": ["Integrity"],
            "mitigation": "Review feedback pipelines and sanitize input sources.",
            "compliance": ["HIPAA"],
            "attack_path": [
                "Step 1: Attacker submits poisoned inputs",
                "Step 2: Model retrained on unclean data",
                "Step 3: Prediction logic skewed or backdoored",
                "Step 4: Model makes manipulated decisions"
            ]
        })

    # 5. Autonomous Output Exploitation
    if inputs["auto_action"] == "Yes" and inputs["output_filtering"] == "None":
        threats.append({
            "id": "output_misuse",
            "threat": "Autonomous Output Exploitation",
            "description": "Outputs from model automatically trigger real-world actions without validation.",
            "owasp": "ML08: Model Misuse",
            "mitre": "TA0006: Execution",
            "nist": ["Integrity", "Availability"],
            "mitigation": "Enable review pipelines, human-in-the-loop control.",
            "compliance": ["SOC2", "PCI"],
            "attack_path": [
                "Step 1: LLM generates unsafe response",
                "Step 2: Output used for decision/action",
                "Step 3: Automation triggers external system",
                "Step 4: Results in harm, loss or abuse"
            ]
        })

    # 6. No Logging
    if inputs["logging"] == "No":
        threats.append({
            "id": "no_logging",
            "threat": "Lack of Forensics & Detection",
            "description": "No logging means undetected threats and no evidence after incidents.",
            "owasp": "LLM09: Logging Failures",
            "mitre": "TA0005: Defense Evasion",
            "nist": ["Availability"],
            "mitigation": "Enable secure logging with anomaly detection and audits.",
            "compliance": ["SOC2", "PCI"],
            "attack_path": [
                "Step 1: Malicious input or activity",
                "Step 2: No logs are stored",
                "Step 3: Admins unaware of issue",
                "Step 4: Incident undetected or unresolved"
            ]
        })

    # 7. No WAF or API Gateway
    if inputs["waf"] == "No" and inputs["exposure"] == "Public":
        threats.append({
            "id": "no_waf",
            "threat": "API Abuse / Reconnaissance",
            "description": "Public-facing AI API without WAF is open to bots, scans, and brute force.",
            "owasp": "API7: Security Misconfiguration",
            "mitre": "TA0001: Reconnaissance",
            "nist": ["Abuse", "Availability"],
            "mitigation": "Use rate limits, CAPTCHA, WAFs and bot filters.",
            "compliance": ["SOC2"],
            "attack_path": [
                "Step 1: Attacker enumerates API",
                "Step 2: Sends abnormal requests",
                "Step 3: No controls block traffic",
                "Step 4: Exploits found or DoS occurs"
            ]
        })

    # 8. Toxic or Unsafe Output to Anonymous Users
    if "Anonymous" in inputs["users"] and inputs["output_filtering"] == "None":
        threats.append({
            "id": "toxic_output",
            "threat": "Toxic Output to Anonymous Users",
            "description": "Anonymous users may trigger harmful, offensive, or biased model outputs.",
            "owasp": "LLM04: Toxicity and Bias",
            "mitre": "TA0040: Impact",
            "nist": ["Abuse"],
            "mitigation": "Use content moderation APIs or response filters.",
            "compliance": ["HIPAA", "SOC2"],
            "attack_path": [
                "Step 1: Anonymous user prompts model",
                "Step 2: Unmoderated content generated",
                "Step 3: Harmful or biased response shown",
                "Step 4: Legal or reputational damage"
            ]
        })

    # 9. Open Source Supply Chain Risk
    if inputs["model_source"] == "Open-source" and inputs["input_validation"] == "None":
        threats.append({
            "id": "supply_chain",
            "threat": "Model Supply Chain Vulnerability",
            "description": "Open-source models may have embedded backdoors or vulnerable dependencies.",
            "owasp": "ML01: Supply Chain Vulnerability",
            "mitre": "TA0043: Supply Chain Compromise",
            "nist": ["Integrity"],
            "mitigation": "Verify weights, scan packages, and review contributors.",
            "compliance": ["SOC2"],
            "attack_path": [
                "Step 1: Developer imports open-source model",
                "Step 2: Model includes unknown dependency or backdoor",
                "Step 3: Model executes unauthorized actions",
                "Step 4: Internal data accessed or logic subverted"
            ]
        })

    # 10. Model Inversion
    if "PII" in inputs["training_data"]:
        threats.append({
            "id": "model_inversion",
            "threat": "Model Inversion Attack",
            "description": "Attackers can reconstruct parts of training data by querying model outputs.",
            "owasp": "ML03: Model Inversion",
            "mitre": "TA0009: Collection",
            "nist": ["Confidentiality"],
            "mitigation": "Add noise, use DP training, limit exposure.",
            "compliance": ["HIPAA", "GDPR"],
            "attack_path": [
                "Step 1: Attacker queries model iteratively",
                "Step 2: Model returns encoded patterns",
                "Step 3: Outputs correlated to PII",
                "Step 4: Partial records reconstructed"
            ]
        })

    # 11. Membership Inference
    if inputs["model_type"] == "Classifier" and "PII" in inputs["training_data"]:
        threats.append({
            "id": "membership_inference",
            "threat": "Membership Inference Attack",
            "description": "Attacker can infer whether specific record was used in training.",
            "owasp": "ML05: Membership Inference",
            "mitre": "TA0009: Collection",
            "nist": ["Confidentiality"],
            "mitigation": "Regularize model, test shadow models, limit overfitting.",
            "compliance": ["HIPAA", "GDPR"],
            "attack_path": [
                "Step 1: Attacker submits real vs fake input",
                "Step 2: Observes model confidence/response",
                "Step 3: Measures overfitting pattern",
                "Step 4: Confirms record was trained on"
            ]
        })

    # 12. Overfitting and Generalization Risk
    if inputs["model_updates"] == "No":
        threats.append({
            "id": "overfitting",
            "threat": "Model Overfitting & Concept Drift",
            "description": "Stale model may be overfit and perform poorly on new data.",
            "owasp": "ML09: Model Performance Issues",
            "mitre": "TA0008: Lateral Movement",
            "nist": ["Availability", "Integrity"],
            "mitigation": "Update models regularly, monitor accuracy in production.",
            "compliance": ["SOC2"],
            "attack_path": [
                "Step 1: Model is rarely updated",
                "Step 2: New data deviates from training",
                "Step 3: Accuracy drops or bad decisions made",
                "Step 4: Business logic breaks or losses occur"
            ]
        })

    # 13. Missing Model Documentation
    if inputs.get("model_source") != "Proprietary" and inputs.get("description") == "":
        threats.append({
            "id": "missing_model_card",
            "threat": "Lack of Model Documentation",
            "description": "Lack of transparency increases risk and reduces trust in AI outputs.",
            "owasp": "LLM08: Explainability Failure",
            "mitre": "TA0004: Privilege Escalation",
            "nist": ["Abuse", "Integrity"],
            "mitigation": "Create model cards and risk assessments for each model.",
            "compliance": ["SOC2", "GDPR"],
            "attack_path": [
                "Step 1: Team deploys undocumented model",
                "Step 2: Users rely blindly on outputs",
                "Step 3: Bias or risk goes unmeasured",
                "Step 4: Incident happens without traceability"
            ]
        })

    return threats

