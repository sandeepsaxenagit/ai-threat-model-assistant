# rules_engine.py

def evaluate_threats(inputs):
    threats = []

    def add_threat(threat_id, title, description, owasp, mitre, nist, mitigation, compliance, attack_path):
        threats.append({
            "id": threat_id,
            "threat": title,
            "description": description,
            "owasp": owasp,
            "mitre": mitre,
            "nist": nist,
            "mitigation": mitigation,
            "compliance": compliance,
            "attack_path": attack_path
        })

    # === Prompt Injection
    if inputs["input_validation"] == "None" and inputs["prompt_template"] == "Free-form":
        add_threat(
            "prompt_injection",
            "Prompt Injection Risk",
            "Free-form prompts with no input validation make the model vulnerable to prompt injection.",
            "LLM01: Prompt Injection",
            "TA0001: Initial Access",
            ["Integrity", "Abuse"],
            "Use input validation, prompt templating, and LLM firewall.",
            ["HIPAA", "SOC2"],
            [
                "Step 1: User submits malicious input",
                "Step 2: Prompt overrides system instruction",
                "Step 3: Model executes harmful instruction",
                "Step 4: Data leaked or logic hijacked"
            ]
        )

    # === Plugin abuse
    if inputs["plugin_access"] == "Yes" and inputs["sandboxing"] == "No":
        add_threat(
            "plugin_abuse",
            "Plugin Abuse via LLM",
            "Unrestricted plugin access can allow LLMs to invoke dangerous tools without guardrails.",
            "LLM07: Insecure Plugin Design",
            "TA0002: Execution",
            ["Confidentiality", "Abuse"],
            "Isolate plugin access using sandboxes or allowlists.",
            ["SOC2"],
            [
                "Step 1: Prompt activates plugin",
                "Step 2: Plugin executes command",
                "Step 3: No isolation prevents misuse",
                "Step 4: System/data compromised"
            ]
        )

    # === RAG / SSRF
    if inputs["external_sources"] == "Yes":
        add_threat(
            "rag_ssrf",
            "External Data Injection / SSRF",
            "Models fetching real-time external content are vulnerable to injection or SSRF.",
            "LLM06: Sensitive Info Disclosure",
            "TA0009: Collection",
            ["Confidentiality", "Integrity"],
            "Validate fetched content, apply domain allowlists.",
            ["HIPAA", "SOC2"],
            [
                "Step 1: Model fetches malicious URL",
                "Step 2: External site returns payload",
                "Step 3: Content shown without sanitization",
                "Step 4: Internal IPs or metadata exposed"
            ]
        )

    # === Data poisoning
    if inputs["user_influence"] == "Yes":
        add_threat(
            "data_poisoning",
            "Training Data Poisoning",
            "User-contributed data may be poisoned to manipulate model behavior.",
            "ML02: Data Poisoning",
            "TA0042: Resource Development",
            ["Integrity"],
            "Validate training inputs, isolate feedback loops.",
            ["HIPAA"],
            [
                "Step 1: User submits adversarial input",
                "Step 2: Input becomes part of training set",
                "Step 3: Model learns corrupted pattern",
                "Step 4: Predictions become manipulated"
            ]
        )

    # === Direct model querying
    if inputs["direct_query"] == "Yes" and inputs["output_filtering"] == "None":
        add_threat(
            "direct_access_risk",
            "Direct Model Exposure Risk",
            "Allowing users to query the model directly with no output filtering leads to risk of abuse.",
            "LLM04: Toxic Output",
            "TA0001: Initial Access",
            ["Abuse", "Confidentiality"],
            "Filter outputs using moderation APIs. Avoid exposing internals.",
            ["HIPAA", "SOC2"],
            [
                "Step 1: User submits probing prompt",
                "Step 2: Model replies with raw output",
                "Step 3: Offensive or unsafe data returned",
                "Step 4: Legal or reputational harm"
            ]
        )

    # === Autonomous decision-making
    if inputs["auto_action"] == "Yes" and inputs["can_override"] == "No":
        add_threat(
            "auto_action_exploit",
            "Uncontrolled Automation",
            "Model outputs trigger actions automatically with no override, leading to unsafe execution.",
            "ML08: Model Misuse",
            "TA0006: Execution",
            ["Integrity", "Availability"],
            "Add human-in-the-loop or override option.",
            ["SOC2"],
            [
                "Step 1: Model generates recommendation",
                "Step 2: System triggers action immediately",
                "Step 3: No override possible",
                "Step 4: Risky action occurs automatically"
            ]
        )

    # === No WAF / API Gateway
    if inputs["waf"] == "No" and inputs["exposure"] == "Public":
        add_threat(
            "no_waf",
            "No WAF on Public API",
            "Public-facing inference API is not protected by WAF, leaving it open to enumeration and brute-force.",
            "API7: Security Misconfiguration",
            "TA0001: Reconnaissance",
            ["Abuse", "Availability"],
            "Use WAFs or API Gateway with rate-limiting.",
            ["SOC2"],
            [
                "Step 1: Attacker sends crafted input repeatedly",
                "Step 2: Model returns varying behavior",
                "Step 3: Attacker infers model logic",
                "Step 4: Enumeration or brute-force succeeds"
            ]
        )

    # === Output override disabled
    if inputs["can_override"] == "No":
        add_threat(
            "no_override",
            "No Output Override Option",
            "Inability to override model outputs can cause risks in automation and accountability.",
            "ML08: Misuse",
            "TA0040: Impact",
            ["Availability", "Abuse"],
            "Allow manual override of outputs or decisions.",
            ["HIPAA"],
            [
                "Step 1: Model makes poor prediction",
                "Step 2: Output used directly in system",
                "Step 3: No human override in place",
                "Step 4: Unsafe outcome or system disruption"
            ]
        )

    # === No logging
    if inputs["logging"] == "No":
        add_threat(
            "no_logging",
            "Lack of Forensics",
            "No monitoring or logs prevents post-incident analysis or detection.",
            "LLM09: Logging Failures",
            "TA0005: Defense Evasion",
            ["Availability"],
            "Enable logging, alerts, and behavioral analytics.",
            ["SOC2", "PCI"],
            [
                "Step 1: Model behavior anomaly occurs",
                "Step 2: No logs are generated",
                "Step 3: No alert sent to SOC",
                "Step 4: Exploitation goes undetected"
            ]
        )

    # === No red teaming
    if inputs["red_team"] == "No":
        add_threat(
            "no_red_team",
            "No Red Team Assessment",
            "Absence of red teaming means blind spots remain in model behavior.",
            "LLM10: Insecure Deployment",
            "TA0043: Development",
            ["Abuse", "Integrity"],
            "Conduct red teaming at regular intervals to discover bypasses.",
            ["SOC2"],
            [
                "Step 1: Model deployed to prod",
                "Step 2: No adversarial testing performed",
                "Step 3: Malicious inputs not identified",
                "Step 4: Attack paths go unnoticed"
            ]
        )

    # === No adversarial testing
    if inputs["adversarial_testing"] == "No":
        add_threat(
            "no_adv_test",
            "Adversarial Testing Missing",
            "Model hasn't been tested against adversarial attacks like evasion or extraction.",
            "ML10: Evasion",
            "TA0005: Defense Evasion",
            ["Integrity"],
            "Use adversarial examples and testing suites.",
            ["SOC2"],
            [
                "Step 1: Attacker crafts edge-case input",
                "Step 2: Model misclassifies or leaks info",
                "Step 3: No detection in place",
                "Step 4: Business or user impacted"
            ]
        )

    # === Model Overfitting
    if inputs["model_updates"] == "No":
        add_threat(
            "overfitting",
            "Overfitting & Concept Drift",
            "Outdated models tend to overfit or perform poorly on new data.",
            "ML09: Poor Performance",
            "TA0008: Lateral Movement",
            ["Availability", "Integrity"],
            "Retrain frequently, monitor accuracy over time.",
            ["SOC2"],
            [
                "Step 1: Model isn't retrained for long",
                "Step 2: New data patterns emerge",
                "Step 3: Model fails on novel input",
                "Step 4: Incorrect predictions or user impact"
            ]
        )

    # === No Guardrails
    if "None" in inputs["llm_firewall"]:
        add_threat(
            "no_guardrails",
            "No LLM Moderation/Guardrails",
            "Lack of guardrails makes model prone to prompt injection, toxic output, and jailbreaks.",
            "LLM02: Model Hallucination",
            "TA0001: Initial Access",
            ["Abuse", "Integrity"],
            "Use OpenAI moderation API, Rebuff, PromptArmor, etc.",
            ["SOC2"],
            [
                "Step 1: User crafts exploit input",
                "Step 2: No filter catches it",
                "Step 3: Model responds insecurely",
                "Step 4: User misled or exploit occurs"
            ]
        )

    # === Missing Model Card
    if inputs.get("description", "").strip() == "" and inputs.get("model_card", "No") == "No":
        add_threat(
            "no_model_doc",
            "No Model Documentation / Card",
            "Lack of transparency into model capabilities or limitations increases risk and reduces accountability.",
            "LLM08: Explainability Failure",
            "TA0004: Privilege Escalation",
            ["Abuse", "Integrity"],
            "Maintain a model card with intended use, risks, and versioning.",
            ["SOC2", "GDPR"],
            [
                "Step 1: Model lacks metadata or explainability",
                "Step 2: End-users rely on opaque outputs",
                "Step 3: Bias/unfair behavior not traceable",
                "Step 4: Legal, ethical or reputational risk"
            ]
        )

    return threats

