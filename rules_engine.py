# rules_engine.py

def evaluate_threats(inputs):
    basic_threats = []
    chained_threats = []

    def add_basic(threat_id, title, description, owasp, mitre, nist, mitigation, compliance, attack_path):
        basic_threats.append({
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

    def add_chained(threat_id, title, description, owasp, mitre, nist, mitigation, compliance, attack_path):
        chained_threats.append({
            "id": threat_id,
            "threat": title + " 🔗 (Threat Chain)",
            "description": description,
            "owasp": owasp,
            "mitre": mitre,
            "nist": nist,
            "mitigation": mitigation,
            "compliance": compliance,
            "attack_path": attack_path
        })

    # ============================
    # Individual Threats (Expanded)
    # ============================

    if inputs["model_card"] == "No":
        add_basic(
            "no_model_card",
            "Lack of Model Documentation",
            "Without a model card, it's difficult to track purpose, limitations, and risks.",
            "LLM08: Explainability Failure",
            "TA0040: Impact",
            ["Abuse", "Integrity"],
            "Create and maintain a model card describing intended use, data, and limitations.",
            ["SOC2", "GDPR"],
            [
                "Step 1: Model is undocumented",
                "Step 2: Auditors can't trace assumptions or data",
                "Step 3: Model behaves in unexpected ways",
                "Step 4: Accountability and compliance suffer"
            ]
        )

    if inputs["rl_feedback"] == "No":
        add_basic(
            "no_rlhf",
            "No Reinforcement Learning from Human Feedback (RLHF)",
            "Without RLHF, LLMs may generate unsafe, biased, or undesired responses.",
            "LLM03: Unaligned Objectives",
            "TA0004: Privilege Escalation",
            ["Abuse", "Integrity"],
            "Use RLHF or fine-tuning to align model outputs to intended behavior.",
            ["HIPAA"],
            [
                "Step 1: Model generates unaligned output",
                "Step 2: Feedback loop is absent",
                "Step 3: Behavior drifts without correction",
                "Step 4: Risky predictions reach users"
            ]
        )

    if inputs["direct_query"] == "Yes":
        add_basic(
            "direct_query",
            "Direct Model Exposure",
            "Allowing direct query access increases risk of jailbreaking and extraction attacks.",
            "LLM01: Prompt Injection",
            "TA0001: Initial Access",
            ["Abuse", "Confidentiality"],
            "Use proxy layers, templates, and query moderation.",
            ["SOC2"],
            [
                "Step 1: Attacker queries model directly",
                "Step 2: Sends probing or jailbreaking prompt",
                "Step 3: Model responds without filtering",
                "Step 4: Information disclosure or misuse"
            ]
        )

    if inputs["real_time"] == "Yes":
        add_basic(
            "realtime_risk",
            "Real-Time Inference Exposure",
            "Real-time inference may expose the system to fast-changing threats and timing attacks.",
            "LLM09: Inference Risks",
            "TA0002: Execution",
            ["Availability", "Integrity"],
            "Add caching, throttling, and time-based detection for inference abuse.",
            ["SOC2"],
            [
                "Step 1: Real-time input from user",
                "Step 2: Model executes without buffering",
                "Step 3: Attackers race inputs to abuse state",
                "Step 4: System becomes unstable or tricked"
            ]
        )

    if "PII" in inputs["training_data"] or "PHI" in inputs["training_data"]:
        add_basic(
            "pii_in_training",
            "Sensitive Data in Training Set",
            "Training on PII/PHI without safeguards may lead to memorization and leakage.",
            "ML01: Training Data Leakage",
            "TA0009: Collection",
            ["Confidentiality"],
            "Use anonymization, differential privacy, or synthetic data alternatives.",
            ["HIPAA", "GDPR"],
            [
                "Step 1: PII included in training set",
                "Step 2: Model memorizes sensitive text",
                "Step 3: Prompt elicits PII from model",
                "Step 4: Privacy and compliance breach"
            ]
        )

    if "Code" in inputs["outputs"]:
        add_basic(
            "code_output",
            "LLM Generating Executable Code",
            "Code generation opens risks of injection, unsafe logic, or dependency abuse.",
            "LLM06: Output Misuse",
            "TA0007: Execution",
            ["Integrity", "Abuse"],
            "Apply code linting, sandbox execution, and restrict eval.",
            ["SOC2"],
            [
                "Step 1: Model generates user-supplied code",
                "Step 2: App integrates code directly",
                "Step 3: No validation or review",
                "Step 4: Arbitrary command execution risk"
            ]
        )

    if inputs["external_systems"] == "Yes":
        add_basic(
            "external_system_access",
            "Model Access to External Systems",
            "If the model can call external systems, it may be used to trigger actions beyond intended scope.",
            "LLM07: Insecure Integration",
            "TA0006: Execution",
            ["Integrity", "Abuse"],
            "Restrict access and apply least privilege to external system connectors.",
            ["SOC2"],
            [
                "Step 1: Model responds with trigger phrase",
                "Step 2: External call initiated",
                "Step 3: Unintended system behavior",
                "Step 4: Escalation or data exposure"
            ]
        )

    # ============================
    # Chained Threats (New Combos)
    # ============================

    if (
        inputs["plugin_access"] == "Yes" and
        inputs["sandboxing"] == "No" and
        inputs["logging"] == "No"
    ):
        add_chained(
            "plugin_chain",
            "Plugin Abuse + No Isolation + No Logs",
            "Plugins are accessible with no sandboxing or monitoring, enabling stealthy command execution.",
            "LLM07: Insecure Plugin Design",
            "TA0009: Collection",
            ["Confidentiality", "Integrity"],
            "Isolate plugin execution and ensure all invocations are logged.",
            ["SOC2"],
            [
                "Step 1: User triggers plugin with prompt",
                "Step 2: Plugin runs in unsafe context",
                "Step 3: Actions not logged or alerted",
                "Step 4: Data leak or privilege abuse unnoticed"
            ]
        )

    if (
        inputs["external_sources"] == "Yes" and
        inputs["input_validation"] == "None" and
        "None" in inputs["llm_firewall"]
    ):
        add_chained(
            "rag_chain",
            "Unvalidated External Source Injection",
            "Combining RAG with no validation and no guardrails can allow attackers to poison external sources and exploit model behavior.",
            "LLM06: Sensitive Info Disclosure",
            "TA0001: Initial Access",
            ["Confidentiality", "Abuse"],
            "Validate external data and use guardrails to prevent misuse.",
            ["HIPAA", "SOC2"],
            [
                "Step 1: Model fetches untrusted URL",
                "Step 2: Malicious prompt delivered via source",
                "Step 3: Model processes and replies to payload",
                "Step 4: Internal IP or token leaked"
            ]
        )

    if (
        inputs["user_influence"] == "Yes" and
        inputs["model_updates"] == "No" and
        inputs["auto_action"] == "Yes"
    ):
        add_chained(
            "feedback_loop",
            "Poisoned Feedback + Stale Model + Auto-Action",
            "Poisoned data influences decision logic in an outdated model whose output is used in automation.",
            "ML02: Data Poisoning",
            "TA0042: Resource Development",
            ["Integrity", "Availability"],
            "Block feedback loops from influencing production without validation.",
            ["HIPAA", "SOC2"],
            [
                "Step 1: Poisoned feedback accepted into training",
                "Step 2: Model logic changed",
                "Step 3: Output used directly by system",
                "Step 4: Unsafe or harmful action occurs"
            ]
        )

    if (
        inputs["exposure"] == "Public" and
        inputs["waf"] == "No" and
        inputs["prompt_template"] == "Free-form" and
        inputs["output_filtering"] == "No"
    ):
        add_chained(
            "open_api_chain",
            "Fully Open LLM Endpoint Attack Chain",
            "A public-facing, unprotected API with unfiltered output and free prompts is vulnerable to a full prompt injection kill chain.",
            "LLM01: Prompt Injection",
            "TA0001: Initial Access",
            ["Integrity", "Abuse"],
            "Restrict exposure, template prompts, and enable WAF and output filters.",
            ["HIPAA", "SOC2"],
            [
                "Step 1: External actor sends prompt injection",
                "Step 2: Input reaches model unaltered",
                "Step 3: Unfiltered response served",
                "Step 4: Jailbreak, override or info disclosure"
            ]
        )

    return {
        "basic": basic_threats,
        "chained": chained_threats
    }

