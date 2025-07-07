# rules_engine.py

def evaluate_threats(inputs):
    threats = []

    # 1. Prompt Injection
    if inputs["input_validation"] == "None" and inputs["exposure"] == "Public":
        threats.append({
            "id": "prompt_injection",
            "threat": "Prompt Injection Risk",
            "description": "Unvalidated public inputs may lead to prompt injection or prompt override.",
            "owasp": "LLM01: Prompt Injection",
            "mitre": "TA0001: Initial Access",
            "nist": ["Integrity", "Abuse"],
            "mitigation": "Enforce input validation, use prompt templates, apply LLM firewall.",
            "compliance": ["HIPAA", "SOC2"],
            "attack_path": [
                "Step 1: User submits malicious prompt",
                "Step 2: Prompt bypasses validation",
                "Step 3: Model executes unintended behavior",
                "Step 4: Sensitive info leaked or function hijacked"
            ]
        })

    # 2. Autonomous Execution without Filter
    if inputs["auto_action"] == "Yes" and inputs["output_filtering"] == "None":
        threats.append({
            "id": "auto_action_exploit",
            "threat": "Unsafe Autonomous Execution",
            "description": "Model outputs are used to trigger actions without review.",
            "owasp": "ML08: Model Misuse",
            "mitre": "TA0006: Execution",
            "nist": ["Integrity", "Availability"],
            "mitigation": "Use output validation and human-in-the-loop checks.",
            "compliance": ["PCI", "SOC2"],
            "attack_path": [
                "Step 1: LLM generates unverified response",
                "Step 2: Output is used to trigger system action",
                "Step 3: Unintended command or data overwrite",
                "Step 4: Denial of service or corruption"
            ]
        })

    # 3. Data Poisoning
    if inputs["user_influence"] == "Yes":
        threats.append({
            "id": "data_poisoning",
            "threat": "Training Data Poisoning",
            "description": "Users can manipulate model behavior via poisoned data.",
            "owasp": "ML02: Data Poisoning",
            "mitre": "TA0042: Resource Development",
            "nist": ["Integrity"],
            "mitigation": "Review feedback loops, validate training sources.",
            "compliance": ["HIPAA"],
            "attack_path": [
                "Step 1: User submits malicious training input",
                "Step 2: Input included in retraining",
                "Step 3: Model learns manipulated behavior",
                "Step 4: Model misbehaves during inference"
            ]
        })

    # 4. Plugin Misuse
    if inputs["plugin_access"] == "Yes" and inputs["sandboxing"] == "No":
        threats.append({
            "id": "plugin_misuse",
            "threat": "Unsafe Plugin/Tool Access",
            "description": "LLM can trigger plugins without sandboxing, risking system misuse.",
            "owasp": "LLM07: Insecure Plugin Design",
            "mitre": "TA0002: Execution",
            "nist": ["Confidentiality", "Integrity"],
            "mitigation": "Sandbox plugin/tool executions; apply allow/deny lists.",
            "compliance": ["SOC2"],
            "attack_path": [
                "Step 1: User prompt triggers plugin execution",
                "Step 2: Plugin runs in unconfined environment",
                "Step 3: Attacker abuses access or lateral movement",
                "Step 4: Data exfiltration or impact"
            ]
        })

    # 5. SSRF via RAG or scraping
    if inputs["external_sources"] == "Yes":
        threats.append({
            "id": "rag_ssrf",
            "threat": "External Data Injection / SSRF",
            "description": "Model uses untrusted external data, opening it to SSRF or content injection.",
            "owasp": "LLM06: Sensitive Information Disclosure",
            "mitre": "TA0009: Collection",
            "nist": ["Confidentiality", "Integrity"],
            "mitigation": "Sanitize retrieved data, apply domain allowlists.",
            "compliance": ["HIPAA", "SOC2"],
            "attack_path": [
                "Step 1: Model fetches external data via RAG",
                "Step 2: Malicious source responds with payload",
                "Step 3: LLM processes or reveals that data",
                "Step 4: Leaks internal metadata or behavior"
            ]
        })

    # 6. Output without filtering to anonymous users
    if "Anonymous" in inputs["users"] and inputs["output_filtering"] == "None":
        threats.append({
            "id": "toxic_output",
            "threat": "Toxic or Biased Output Exposure",
            "description": "Anonymous users may receive unsafe, toxic, or biased content from unfiltered outputs.",
            "owasp": "LLM04: Toxicity and Bias",
            "mitre": "TA0040: Impact",
            "nist": ["Abuse", "Confidentiality"],
            "mitigation": "Use output moderation APIs, red teaming, and safe fine-tuning.",
            "compliance": ["HIPAA", "SOC2"],
            "attack_path": [
                "Step 1: Anonymous user sends query",
                "Step 2: LLM replies without moderation",
                "Step 3: User sees toxic or unsafe content",
                "Step 4: Potential legal, brand or compliance impact"
            ]
        })

    return threats

