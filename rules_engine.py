def evaluate_threats(inputs):
    basic_threats = []
    chained_threats = []

    def add_basic(threat_id, title, description, owasp, mitre, nist, mitigation, compliance, attack_path, reason):
        basic_threats.append({
            "id": threat_id,
            "threat": title,
            "description": description,
            "owasp": owasp,
            "mitre": mitre,
            "nist": nist,
            "mitigation": mitigation,
            "compliance": compliance,
            "attack_path": attack_path,
            "reason": reason
        })

    def add_chained(threat_id, title, description, owasp, mitre, nist, mitigation, compliance, attack_path, reason):
        chained_threats.append({
            "id": threat_id,
            "threat": title + " 🔗 (Threat Chain)",
            "description": description,
            "owasp": owasp,
            "mitre": mitre,
            "nist": nist,
            "mitigation": mitigation,
            "compliance": compliance,
            "attack_path": attack_path,
            "reason": reason
        })

    # ============================\
    # Individual Threats (Expanded)\
    # ============================\

    # Lack of Model Documentation (LLM08 / ML10 related)
    if inputs["model_card"] == "No":
        owasp_id = "LLM08: Explainability Failure" if inputs["ai_type"] in ["LLM", "Generative AI"] else "ML10: Lack of Governance"
        reason = f"You indicated that 'Model documentation is NOT maintained (Model Card: {inputs['model_card']})'."
        add_basic(
            "no_model_card",
            "Lack of Model Documentation",
            "Without a model card or proper documentation, it's difficult to track purpose, limitations, risks, and changes.",
            owasp_id,
            "TA0040: Impact",
            ["Abuse", "Integrity", "Confidentiality"],
            "Maintain comprehensive model documentation (e.g., Model Cards, datasheets).",
            ["SOC2"],
            ["Step 1: Model deployed without clear documentation", "Step 2: Misunderstanding of model capabilities or data biases", "Step 3: Unintended or harmful use in production"],
            reason
        )

    # Sensitive Information Disclosure (LLM06 / ML06 related)
    if (
        ("PII" in inputs["training_data"] or "PHI" in inputs["training_data"]) and
        inputs["output_filtering"] == "No"
    ):
        owasp_id = "LLM06: Sensitive Information Disclosure" if inputs["ai_type"] in ["LLM", "Generative AI"] else "ML06: Data Leakage (Sensitive Data Exposure)"
        reason = f"Your training data includes {', '.join([d for d in inputs['training_data'] if d in ['PII', 'PHI']])} and 'Output filtering is NOT performed ({inputs['output_filtering']})'."
        add_basic(
            "sensitive_info_disclosure",
            "Sensitive Information Disclosure",
            "Model may leak PII/PHI from training data or external sources if outputs are not filtered.",
            owasp_id,
            "TA0006: Credential Access",
            ["Confidentiality"],
            "Implement robust output filtering and anonymization. Ensure sensitive data is not over-retained.",
            ["GDPR", "HIPAA", "CCPA"],
            ["Step 1: User queries model", "Step 2: Model generates output containing sensitive training data/inferences", "Step 3: Sensitive data exposed to unauthorized user"],
            reason
        )

    # Data Poisoning / Integrity (LLM03 / ML01 related)
    if (
        inputs["user_influence"] == "Yes" or
        (inputs["real_time"] == "Yes" and "Public" in inputs["training_data"])
    ):
        owasp_id = "LLM03: Training Data Poisoning" if inputs["ai_type"] in ["LLM", "Generative AI"] else "ML01: Training Data Poisoning"
        reason_parts = []
        if inputs["user_influence"] == "Yes":
            reason_parts.append(f"'Users can influence training or inference data ({inputs['user_influence']})'")
        if inputs["real_time"] == "Yes" and "Public" in inputs["training_data"]:
            reason_parts.append(f"'Real-time inputs are used ({inputs['real_time']})' with 'Public' training data")
        reason = " and ".join(reason_parts) + ". This increases the risk of malicious data injection."
        add_basic(
            "data_poisoning",
            "Training Data Poisoning",
            "Malicious actors can inject poisoned data into training or fine-tuning datasets, compromising model integrity.",
            owasp_id,
            "TA0003: Persistence",
            ["Integrity", "Availability"],
            "Implement strict data validation, anomaly detection, and provenance tracking for training data. Regularly audit datasets.",
            ["SOC2"],
            ["Step 1: Malicious data introduced into training pipeline", "Step 2: Model is trained on poisoned data", "Step 3: Model behavior is altered, leading to incorrect or harmful outputs"],
            reason
        )
    
    # Direct Query / Prompt Injection (LLM01 / ML03 related)
    if inputs["direct_query"] == "Yes" and inputs["input_validation"] == "No":
        owasp_id = "LLM01: Prompt Injection" if inputs["ai_type"] in ["LLM", "Generative AI"] else "ML03: Inference API Abuse"
        reason = f"Users can 'Directly query the model ({inputs['direct_query']})' and 'Inputs are NOT validated before inference ({inputs['input_validation']})'."
        add_basic(
            "direct_query_vulnerability",
            "Direct Query Vulnerability / Prompt Injection",
            "Unvalidated direct queries can lead to prompt injection, bypassing safety measures or extracting sensitive info.",
            owasp_id,
            "TA0001: Initial Access",
            ["Integrity", "Confidentiality"],
            "Implement strong input validation and sanitization. Use templated prompts where possible.",
            ["PCI"],
            ["Step 1: Malicious input sent to model API", "Step 2: Input processed without validation", "Step 3: Model executes unintended commands or reveals internal data"],
            reason
        )

    # Insecure Plugins/Tools (LLM07 related)
    if inputs["plugin_access"] == "Yes" and inputs["sandboxing"] == "No":
        reason = f"The 'Model can access tools/plugins ({inputs['plugin_access']})' but 'Plugin/tool execution is NOT sandboxed ({inputs['sandboxing']})'."
        add_basic(
            "insecure_plugins",
            "Insecure Plugin/Tool Design",
            "Unsandboxed execution of plugins/tools can lead to privilege escalation or unauthorized actions.",
            "LLM07: Insecure Plugin Design",
            "TA0004: Privilege Escalation",
            ["Integrity", "Confidentiality", "Availability"],
            "Enforce strict sandboxing, least privilege, and validation for all plugin/tool execution.",
            ["SOC2"],
            ["Step 1: Model accesses malicious plugin/tool", "Step 2: Plugin executes outside of sandbox", "Step 3: Unauthorized system access or data manipulation occurs"],
            reason
        )
    
    # Excessive Agency / External System Access (LLM08 related)
    if inputs["external_systems"] == "Yes" and inputs["can_override"] == "No":
        reason = f"The 'Model can access external systems ({inputs['external_systems']})' but its 'Outputs CANNOT be overridden ({inputs['can_override']})'."
        add_basic(
            "external_system_access",
            "Excessive Agency / Uncontrolled External System Access",
            "Model's unmonitored access to external systems without human oversight can lead to unintended actions.",
            "LLM08: Excessive Agency",
            "TA0005: Defense Evasion",
            ["Integrity", "Availability"],
            "Implement human-in-the-loop controls, strict access policies for external systems, and audit trails.",
            ["HIPAA", "GDPR"],
            ["Step 1: Model decides to interact with external system", "Step 2: Action performed without review/override", "Step 3: Harmful or unauthorized operation occurs on external system"],
            reason
        )

    # Inadequate Logging and Monitoring (ML09 / General)
    if inputs["logging"] == "No":
        reason = f"'Logs & Monitoring are NOT enabled ({inputs['logging']})'."
        add_basic(
            "inadequate_logging",
            "Inadequate Logging and Monitoring",
            "Lack of logging hinders incident response, threat detection, and forensic analysis.",
            "ML09: Inadequate Logging and Monitoring",
            "TA0007: Collection",
            ["Availability", "Confidentiality", "Integrity"],
            "Implement comprehensive logging for all model inputs, outputs, decisions, and system events. Establish monitoring alerts.",
            ["SOC2", "PCI"],
            ["Step 1: Security incident occurs", "Step 2: No logs are available or logs are insufficient", "Step 3: Incident goes undetected or cannot be investigated"],
            reason
        )
    
    # Insecure ML Deployment (ML08 / General)
    if inputs["exposure"] == "Public" and inputs["access_control"] == "None":
        reason = f"The model has 'Public' exposure and 'Access Control is None ({inputs['access_control']})'."
        add_basic(
            "insecure_deployment",
            "Insecure ML Deployment",
            "Public exposure without proper access controls makes the model vulnerable to unauthorized access and abuse.",
            "ML08: Insecure ML Deployment",
            "TA0001: Initial Access",
            ["Confidentiality", "Integrity", "Availability"],
            "Implement strong authentication, authorization (RBAC/ABAC), and network security measures.",
            ["PCI", "SOC2"],
            ["Step 1: Attacker discovers public endpoint", "Step 2: No access controls in place", "Step 3: Attacker gains unauthorized access to model or data"],
            reason
        )

    # Model Theft (LLM10 / ML02 related)
    if inputs["model_source"] == "Proprietary" and inputs["exposure"] == "Public" and inputs["access_control"] == "None":
        owasp_id = "LLM10: Model Theft" if inputs["ai_type"] in ["LLM", "Generative AI"] else "ML02: Model Theft"
        reason = f"Your 'Model Source is Proprietary ({inputs['model_source']})', it has 'Public' exposure, and 'Access Control is None ({inputs['access_control']})'."
        add_basic(
            "model_theft_risk",
            "Model Theft Risk",
            "Proprietary models exposed publicly without access control are at high risk of intellectual property theft via API access.",
            owasp_id,
            "TA0006: Credential Access",
            ["Confidentiality"],
            "Implement robust API security, rate limiting, and obfuscation techniques. Restrict access to authorized users.",
            ["SOC2"],
            ["Step 1: Attacker queries publicly exposed model", "Step 2: Attacker uses queries to reconstruct model architecture/weights", "Step 3: Proprietary model is stolen"],
            reason
        )

    # Inadequate Adversarial Security Posture
    # Using 'adversarial_test_types' and 'adversarial_test_tools' multiselect, so checking if 'None' is in them.
    # The previous logic implicitly assumed a single radio button, now it's more specific.
    if (
        "None" in inputs["adversarial_test_types"] and
        "None" in inputs["adversarial_test_tools"] and
        inputs["red_team"] == "No" 
    ):
        reason = f"No 'Adversarial testing types ({inputs['adversarial_test_types']})' or 'tools ({inputs['adversarial_test_tools']})' are performed, and 'Red teaming is NOT conducted ({inputs['red_team']})'."
        add_basic(
            "inadequate_adversarial_security_posture",
            "Inadequate Adversarial Security Posture",
            "Lack of adversarial testing and red teaming indicates a weak defense against sophisticated AI attacks.",
            "ML04: Adversarial Examples",
            "TA0005: Defense Evasion",
            ["Integrity", "Availability"],
            "Establish a comprehensive adversarial testing program, including red teaming, and implement specific adversarial defenses.",
            ["SOC2"],
            ["Step 1: Attacker crafts adversarial input", "Step 2: Model's defenses are insufficient", "Step 3: Model misclassifies or generates harmful output"],
            reason
        )
    
    # Compliance Gaps (New threats based on compliance selection and missing controls)
    if "HIPAA" in inputs["compliance"] and "PHI" in inputs["training_data"] and inputs["output_filtering"] == "No":
        reason = f"You follow 'HIPAA' compliance but have 'PHI' in 'Training Data' and 'Output filtering is NOT performed ({inputs['output_filtering']})'."
        add_basic(
            "hipaa_data_leakage_risk",
            "HIPAA Compliance Gap: PHI Leakage Risk",
            "Handling PHI without output filtering poses a significant HIPAA violation risk.",
            "LLM06: Sensitive Information Disclosure",
            "TA0006: Credential Access",
            ["Confidentiality"],
            "Ensure all outputs are rigorously filtered for PHI before disclosure. Implement data anonymization techniques.",
            ["HIPAA"],
            ["Step 1: PHI present in training data", "Step 2: Model output not filtered", "Step 3: PHI inadvertently exposed, leading to HIPAA violation"],
            reason
        )
    
    if "GDPR" in inputs["compliance"] and "PII" in inputs["training_data"] and inputs["access_control"] == "None":
        reason = f"You follow 'GDPR' compliance but have 'PII' in 'Training Data' and 'Access Control is None ({inputs['access_control']})'."
        add_basic(
            "gdpr_access_violation_risk",
            "GDPR Compliance Gap: PII Access Violation",
            "Handling PII without proper access controls risks GDPR violations related to data access and security.",
            "ML05: Unauthorized Access to ML Models",
            "TA0001: Initial Access",
            ["Confidentiality"],
            "Implement strict access controls and data minimization for PII. Ensure data subjects' rights are supported.",
            ["GDPR"],
            ["Step 1: PII present in data", "Step 2: Unauthorized access to system/model", "Step 3: PII is exposed, leading to GDPR violation"],
            reason
        )

    # Lack of Output Traceability (New)
    if inputs["output_watermark"] == "No":
        reason = f"'Output traceable/watermarked is NOT enabled ({inputs['output_watermark']})'."
        add_basic(
            "lack_of_output_traceability",
            "Lack of Output Traceability/Watermarking",
            "Without watermarking or traceability, it's hard to distinguish model-generated content from human-generated content, enabling misuse.",
            "LLM09: Overreliance",
            "TA0040: Impact",
            ["Integrity", "Abuse"],
            "Implement digital watermarking or clear provenance metadata for all model outputs.",
            ["None"],
            ["Step 1: Model generates content", "Step 2: Content is indistinguishable from human work", "Step 3: Content is used to mislead, defraud, or spread misinformation"],
            reason
        )
    
    # New Infra Security Threats
    if inputs["data_encrypted_at_rest"] == "No" or inputs["artifacts_encrypted_at_rest"] == "No":
        reason_parts = []
        if inputs["data_encrypted_at_rest"] == "No":
            reason_parts.append(f"training/inference data is NOT encrypted at rest ({inputs['data_encrypted_at_rest']})")
        if inputs["artifacts_encrypted_at_rest"] == "No":
            reason_parts.append(f"model artifacts are NOT encrypted at rest ({inputs['artifacts_encrypted_at_rest']})")
        reason = " and ".join(reason_parts) + "."
        add_basic(
            "unencrypted_data_artifacts",
            "Unencrypted Data & Model Artifacts at Rest",
            "Sensitive training/inference data and valuable model artifacts are vulnerable if not encrypted at rest.",
            "ML06: Data Leakage (Sensitive Data Exposure)",
            "TA0007: Collection",
            ["Confidentiality"],
            "Ensure all data and model artifacts are encrypted using strong encryption standards.",
            ["PCI", "HIPAA", "SOC2"],
            ["Step 1: Data/artifacts stored on disk", "Step 2: Storage accessed by unauthorized entity", "Step 3: Sensitive data/IP is exfiltrated"],
            reason
        )

    if inputs["env_patching_scanning"] == "No":
        reason = f"The 'Model's environment is NOT regularly patched and scanned ({inputs['env_patching_scanning']})'."
        add_basic(
            "unpatched_unscanned_env",
            "Unpatched/Unscanned Model Environments",
            "Environments hosting the AI model (VMs, containers) are vulnerable to known exploits if not regularly patched and scanned.",
            "ML08: Insecure ML Deployment",
            "TA0002: Execution",
            ["Integrity", "Confidentiality", "Availability"],
            "Implement continuous vulnerability scanning and patch management for all AI infrastructure.",
            ["SOC2"],
            ["Step 1: Attacker identifies vulnerable component", "Step 2: Exploit deployed against unpatched environment", "Step 3: System compromise, data breach, or denial of service"],
            reason
        )

    if inputs["secrets_managed_securely"] == "No":
        reason = f"'Secrets (API keys, credentials) are NOT managed securely ({inputs['secrets_managed_securely']})'."
        add_basic(
            "insecure_secrets_management",
            "Insecure Secrets Management",
            "API keys, credentials, and other secrets for accessing data or services are not securely managed.",
            "ML06: Data Leakage (Sensitive Data Exposure)",
            "TA0006: Credential Access",
            ["Confidentiality"],
            "Utilize dedicated secrets management solutions (e.g., AWS Secrets Manager, HashiCorp Vault) and follow least privilege principles.",
            ["PCI", "SOC2"],
            ["Step 1: Hardcoded or insecurely stored secret discovered", "Step 2: Attacker gains access to secret", "Step 3: Unauthorized access to external services or sensitive data"],
            reason
        )

    if inputs["network_segmentation"] == "No" and inputs["exposure"] == "Public":
        reason = f"'Network segmentation is NOT applied to model deployment environments ({inputs['network_segmentation']})' for a 'Publicly exposed' model."
        add_basic(
            "lack_of_network_segmentation",
            "Lack of Network Segmentation for Publicly Exposed Models",
            "A publicly exposed model without network segmentation allows lateral movement in case of compromise.",
            "ML08: Insecure ML Deployment",
            "TA0008: Lateral Movement",
            ["Confidentiality", "Integrity", "Availability"],
            "Implement strict network segmentation (VPCs, subnets, firewalls) to isolate model environments.",
            ["PCI", "SOC2"],
            ["Step 1: Publicly exposed model is compromised", "Step 2: Attacker moves freely within network due to flat network", "Step 3: Broader system compromise or data exfiltration"],
            reason
        )
    
    # ============================\
    # Chained Threats (Complex)\
    # ============================\

    # Data Leakage Chain (ML06 related)
    if (
        ("PII" in inputs["training_data"] or "PHI" in inputs["training_data"]) and
        inputs["user_influence"] == "Yes" and
        inputs["output_filtering"] == "No" and
        "None" in inputs["adversarial_test_types"] # Checking if 'None' is explicitly selected
    ):
        reason = f"You have {', '.join([d for d in inputs['training_data'] if d in ['PII', 'PHI']])} in training data, 'Users can influence data ({inputs['user_influence']})', 'Output filtering is NOT performed ({inputs['output_filtering']})', and 'No adversarial testing is performed ({'None' in inputs['adversarial_test_types']})'."
        add_chained(
            "data_leakage_chain",
            "Data Leakage Through Data Poisoning Chain",
            "A public model with sensitive training data, susceptible to user influence, and lacking output filtering, can be poisoned to leak sensitive information, especially if adversarial testing is not performed.",
            "ML06: Data Leakage (Sensitive Data Exposure)",
            "TA0007: Collection",
            ["Confidentiality", "Integrity"],
            "Implement rigorous data validation, output filtering, and regular adversarial testing to prevent data leakage.",
            ["GDPR", "HIPAA", "CCPA"],
            [
                "Step 1: Malicious user injects data/prompts into training/inference",
                "Step 2: Model incorporates poisoned data or is influenced to reveal information",
                "Step 3: Unfiltered output contains sensitive data",
                "Step 4: Sensitive data is exfiltrated by attacker"
            ],
            reason
        )

    # Feedback Poisoning Chain (LLM03/ML01 and LLM08/ML10 related)
    if (
        inputs["user_influence"] == "Yes" and
        inputs["real_time"] == "Yes" and
        inputs["auto_action"] == "Yes" and
        inputs["rl_feedback"] == "Yes"
    ):
        reason = f"'Users can influence data ({inputs['user_influence']})' with 'Real-time inputs ({inputs['real_time']})', 'Outputs are auto-used in decisions ({inputs['auto_action']})', and 'RLHF is used ({inputs['rl_feedback']})'."
        add_chained(
            "feedback_poisoning_chain",
            "Reinforcement Learning Feedback Poisoning Attack Chain",
            "In real-time systems, user-influenced feedback (e.g., RLHF) can be poisoned, leading to automated harmful actions if outputs are auto-used.",
            "LLM03: Training Data Poisoning",
            "TA0003: Persistence",
            ["Integrity", "Availability", "Abuse"],
            "Block feedback loops from influencing production without validation. Implement human oversight and robust anomaly detection in feedback systems.",
            ["HIPAA", "SOC2"],
            [
                "Step 1: Poisoned feedback accepted into training",
                "Step 2: Model logic changed",
                "Step 3: Output used directly by system",
                "Step 4: Unsafe or harmful action occurs"
            ],
            reason
        )

    # Fully Open LLM Endpoint Attack Chain (LLM01/ML03 related)
    if (
        inputs["exposure"] == "Public" and
        inputs["waf"] == "No" and
        inputs["prompt_template"] == "Free-form" and
        inputs["output_filtering"] == "No" and
        inputs["access_control"] == "None" # Added access_control to the chain logic
    ):
        reason = f"The model has 'Public' exposure, 'No WAF or API Gateway ({inputs['waf']})', uses 'Free-form' prompt strategy, 'Output filtering is NOT performed ({inputs['output_filtering']})', and 'Access Control is None ({inputs['access_control']})'."
        add_chained(
            "open_api_chain",
            "Fully Open LLM Endpoint Attack Chain",
            "A public-facing, unprotected API with unfiltered output, free prompts, and no access control is highly vulnerable to prompt injection, jailbreaking, and data exfiltration.",
            "LLM01: Prompt Injection",
            "TA0001: Initial Access",
            ["Integrity", "Abuse", "Confidentiality"], # Added Confidentiality to NIST
            "Restrict exposure, enforce strong access controls, template prompts, and enable WAF and output filters. Do not deploy sensitive models without robust security.",
            ["HIPAA", "SOC2", "PCI"],
            [
                "Step 1: External actor sends prompt injection",
                "Step 2: Input reaches model unaltered due to lack of input validation", # Clarified attack path
                "Step 3: Unfiltered response served containing sensitive information or malicious commands", # Clarified attack path
                "Step 4: Jailbreak, override, or info disclosure/arbitrary code execution occurs" # Clarified attack path
            ],
            reason
        )
    
    # Plugin Execution Vulnerability Chain (LLM07 related)
    if (
        inputs["plugin_access"] == "Yes" and
        inputs["sandboxing"] == "No" and
        inputs["external_systems"] == "Yes" and
        inputs["logging"] == "No"
    ):
        reason = f"The 'Model can access tools/plugins ({inputs['plugin_access']})' but 'Plugin execution is NOT sandboxed ({inputs['sandboxing']})'. It also 'Can access external systems ({inputs['external_systems']})' and 'Logs & Monitoring are NOT enabled ({inputs['logging']})'."
        add_chained(
            "plugin_chain",
            "Insecure Plugin Execution Chain",
            "A model with unsandboxed access to plugins, capable of interacting with external systems, and lacking logging, creates a severe chain for arbitrary code execution and data exfiltration.",
            "LLM07: Insecure Plugin Design",
            "TA0004: Privilege Escalation",
            ["Integrity", "Confidentiality", "Availability"],
            "Strictly sandbox all plugin execution, apply least privilege to external system access, and enable comprehensive logging for all model and plugin activities.",
            ["SOC2", "PCI"],
            [
                "Step 1: Malicious input triggers vulnerable plugin execution",
                "Step 2: Plugin operates outside sandbox, gaining system access",
                "Step 3: Attacker uses plugin to interact with external systems",
                "Step 4: Data exfiltration or arbitrary code execution occurs on external systems"
            ],
            reason
        )

    return {
        "basic": basic_threats,
        "chained": chained_threats
    }
