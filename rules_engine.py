# rules_engine.py

def evaluate_threats(inputs):
    threats = []

    def add_threat(threat_id, title, description, owasp, mitre, nist, mitigation, compliance, attack_path, correlated=False):
        threats.append({
            "id": threat_id,
            "threat": title + (" 🔗 (Correlated)" if correlated else ""),
            "description": description,
            "owasp": owasp,
            "mitre": mitre,
            "nist": nist,
            "mitigation": mitigation,
            "compliance": compliance,
            "attack_path": attack_path
        })

    # === Correlated Threat: Plugin + No Sandbox + No Logging ===
    if (
        inputs["plugin_access"] == "Yes" and
        inputs["sandboxing"] == "No" and
        inputs["logging"] == "No"
    ):
        add_threat(
            "plugin_exfiltration",
            "Plugin Misuse and Exfiltration via LLM",
            "Plugins are accessible without sandboxing or logging, enabling attackers to trigger tool misuse and avoid detection.",
            "LLM07: Insecure Plugin Design",
            "TA0009: Collection",
            ["Confidentiality", "Abuse", "Integrity"],
            "Use sandboxed plugin runners and enable logging with anomaly detection.",
            ["SOC2"],
            [
                "Step 1: User submits plugin-invoking prompt",
                "Step 2: Plugin executes in unconfined environment",
                "Step 3: Sensitive data accessed or modified",
                "Step 4: No logs generated → attack unnoticed"
            ],
            correlated=True
        )

    # === Correlated Threat: Public API + No WAF + Free-form Prompt + Output Filter Disabled ===
    if (
        inputs["exposure"] == "Public" and
        inputs["waf"] == "No" and
        inputs["prompt_template"] == "Free-form" and
        inputs["output_filtering"] == "No"
    ):
        add_threat(
            "open_api_abuse",
            "Open API Prompt Exploitation Chain",
            "With no WAF or output filters and public exposure, the system is susceptible to full prompt injection chains.",
            "LLM01: Prompt Injection",
            "TA0001: Initial Access",
            ["Integrity", "Abuse"],
            "Protect APIs with WAF, enforce prompt templating, and enable output filtering.",
            ["HIPAA", "SOC2"],
            [
                "Step 1: Attacker sends crafted prompt to public API",
                "Step 2: Prompt bypasses WAF (absent)",
                "Step 3: Model returns unfiltered, unsafe output",
                "Step 4: System misuse or data leak occurs"
            ],
            correlated=True
        )

    # === Correlated Threat: External Sources + No Input Validation + No Guardrails ===
    if (
        inputs["external_sources"] == "Yes" and
        inputs["input_validation"] == "None" and
        "None" in inputs["llm_firewall"]
    ):
        add_threat(
            "external_injection",
            "External Source Injection via RAG",
            "Using external sources without validation or guardrails introduces risk of indirect prompt injection or SSRF.",
            "LLM06: Sensitive Info Disclosure",
            "TA0009: Collection",
            ["Confidentiality", "Integrity"],
            "Use allowlists for external domains, input sanitization, and guardrails.",
            ["HIPAA", "SOC2"],
            [
                "Step 1: Model fetches unvalidated external content",
                "Step 2: Content includes prompt injection or malicious link",
                "Step 3: Model executes or displays malicious payload",
                "Step 4: Internal resources or users impacted"
            ],
            correlated=True
        )

    # === Correlated Threat: User Influence + No Retraining + Output Auto-Applied ===
    if (
        inputs["user_influence"] == "Yes" and
        inputs["model_updates"] == "No" and
        inputs["auto_action"] == "Yes"
    ):
        add_threat(
            "feedback_poisoning_loop",
            "Feedback Loop Poisoning + Autonomous Execution",
            "User-influenced poisoned data combined with outdated models and auto-executing outputs can lead to malicious behavior chains.",
            "ML02: Data Poisoning",
            "TA0042: Resource Development",
            ["Integrity", "Availability"],
            "Separate training from live feedback, validate inputs, and add output review.",
            ["HIPAA", "SOC2"],
            [
                "Step 1: Malicious user poisons feedback loop",
                "Step 2: Model not retrained/validated",
                "Step 3: Output auto-executed into systems",
                "Step 4: Harmful action taken based on poisoned logic"
            ],
            correlated=True
        )

    # === Correlated Threat: Anonymous + No Output Filter + No Guardrails ===
    if (
        "Anonymous" in inputs["users"] and
        inputs["output_filtering"] == "No" and
        "None" in inputs["llm_firewall"]
    ):
        add_threat(
            "unsafe_anonymous",
            "Toxic Output to Anonymous Users",
            "Anonymous users can exploit lack of filtering and guardrails to generate toxic, harmful, or biased outputs.",
            "LLM04: Toxicity and Bias",
            "TA0040: Impact",
            ["Abuse"],
            "Use output filtering, moderation APIs, and restrict anonymous queries.",
            ["HIPAA", "SOC2"],
            [
                "Step 1: Anonymous user sends malicious or sensitive prompt",
                "Step 2: Model replies without moderation",
                "Step 3: Unsafe output visible to end-user",
                "Step 4: Legal or PR consequences follow"
            ],
            correlated=True
        )

    # === Insert base rule threats (non-correlated ones) ===
    # You can re-import or reuse your existing base rules below here (like individual prompt injection, no logging, etc.)
    # This way, even if correlation fails, each input is still evaluated individually
    # This is especially useful for completeness and backward compatibility

    return threats

