from collections import Counter
import streamlit as st

# Apply caching to evaluate_threats to prevent redundant computation
@st.cache_data(show_spinner="Analyzing threats and generating report... This may take a moment.")
def evaluate_threats(inputs):
    basic_threats = []
    chained_threats = []
    compliance_gaps = set() # To store explicit compliance gaps

    # --- Pre-calculate essential boolean flags for strict conditions ---
    has_pii_in_training_data = "PII" in inputs.get("training_data", [])
    has_phi_in_training_data = "PHI" in inputs.get("training_data", [])
    
    # Flags for AI types (using consistent string literals from main.py)
    is_traditional_ml = (inputs.get("ai_type") == "Traditional ML")
    is_generative_ai = (inputs.get("ai_type") == "Generative AI (e.g., Image/Audio Generation)")
    is_llm = (inputs.get("ai_type") == "Large Language Model (LLM)")
    is_agentic_ai = (inputs.get("ai_type") == "Agentic AI (e.g., Autonomous Agents)")
    
    # Combined flag for AI types with LLM/Generative capabilities (includes Agentic AI implicitly)
    is_llm_gen_agentic_type = is_generative_ai or is_llm or is_agentic_ai

    # Agentic sensitive data flag
    is_agentic_sensitive_data_yes = (is_agentic_ai and inputs.get("agentic_sensitive_data") == "Yes")


    # Helper function to infer relevant compliance frameworks
    def infer_relevant_compliances(inputs):
        relevant_compliances = set()

        # Strict inference for data-centric compliances: ONLY if PII/PHI is actually present
        if has_pii_in_training_data or is_agentic_sensitive_data_yes:
            relevant_compliances.add("GDPR")
            relevant_compliances.add("CCPA")
        if has_phi_in_training_data or is_agentic_sensitive_data_yes:
            relevant_compliances.add("HIPAA")

        # PCI DSS: If recommendations are an output AND users are customers/anonymous (implying commercial interaction)
        if ("Recommendations" in inputs.get("outputs", []) and ("Customers" in inputs.get("users", []) or "Anonymous" in inputs.get("users", []))):
            relevant_compliances.add("PCI DSS")

        # General security/governance standards if foundational controls are mentioned
        if inputs.get("model_card") == "Yes" or inputs.get("logging") == "Yes" or inputs.get("auditing") == "Yes" or \
           inputs.get("data_encrypted_at_rest") == "Yes" or inputs.get("access_control") != "None":
            relevant_compliances.add("SOC2")
            relevant_compliances.add("ISO 27001")
        
        # Specific to LLMs/Generative AIs or if regulatory environment is implied
        if is_llm_gen_agentic_type:
            relevant_compliances.add("NIST AI RMF")
            relevant_compliances.add("EU AI Act (Future)")

        return sorted(list(relevant_compliances))

    # --- Step 1: Infer applicable compliances ---
    inferred_compliances = infer_relevant_compliances(inputs)

    # Helper function to add basic threats and contribute to overall compliance gaps
    def add_basic(threat_id, title, description, owasp, mitre, nist, mitigation, attack_path, reason, severity="Medium"): # Added severity
        # IMPORTANT: owasp_id will be added to found_owasp_ids IF this threat is added.
        # So, if this threat should NOT show for Traditional ML, its 'add_basic' call must be inside
        # an 'if is_llm_gen_agentic_type' guard.

        threat_compliance_risks = set() # Specific compliances directly impacted by THIS threat instance
        
        # --- Data & Privacy Compliance Gaps (Strictly conditioned on data presence flags) ---
        if "GDPR" in inferred_compliances and (has_pii_in_training_data or is_agentic_sensitive_data_yes):
            threat_compliance_risks.add("GDPR")
            if inputs.get("output_filtering") == "No": compliance_gaps.add(f"GDPR: PII/Sensitive data leakage risk due to lack of output filtering.")
            if inputs.get("data_encrypted_at_rest") == "No": compliance_gaps.add(f"GDPR: PII/Sensitive data not encrypted at rest.")
            if inputs.get("access_control") == "None": compliance_gaps.add(f"GDPR: PII/Sensitive data exposed due to missing access controls.")
        if "CCPA" in inferred_compliances and (has_pii_in_training_data or is_agentic_sensitive_data_yes):
            threat_compliance_risks.add("CCPA")
            if inputs.get("output_filtering") == "No": compliance_gaps.add(f"CCPA: PII/Sensitive data leakage risk due to lack of output filtering.")
            if inputs.get("data_encrypted_at_rest") == "No": compliance_gaps.add(f"CCPA: PII/Sensitive data not encrypted at rest.")
            if inputs.get("access_control") == "None": compliance_gaps.add(f"CCPA: PII/Sensitive data exposed due to missing access controls.")
        
        if "HIPAA" in inferred_compliances and (has_phi_in_training_data or is_agentic_sensitive_data_yes):
            threat_compliance_risks.add("HIPAA")
            if inputs.get("output_filtering") == "No": compliance_gaps.add(f"HIPAA: PHI leakage risk due to lack of output filtering.")
            if inputs.get("data_encrypted_at_rest") == "No": compliance_gaps.add(f"HIPAA: PHI not encrypted at rest.")
            if inputs.get("access_control") == "None": compliance_gaps.add(f"HIPAA: PHI exposed due to missing access controls.")
        
        if "PCI DSS" in inferred_compliances:
            threat_compliance_risks.add("PCI DSS")
            if inputs.get("data_encrypted_at_rest") == "No": compliance_gaps.add(f"PCI DSS: Unencrypted data at rest.")
            if inputs.get("access_control") == "None": compliance_gaps.add(f"PCI DSS: Insufficient access control.")
            if inputs.get("waf") == "No": compliance_gaps.add(f"PCI DSS: Missing WAF/API Gateway for public exposure.")
            if inputs.get("network_segmentation") == "No": compliance_gaps.add(f"PCI DSS: Lack of network segmentation.")

        # --- General Security Controls (SOC2 / ISO 27001) Gaps ---
        if "SOC2" in inferred_compliances or "ISO 27001" in inferred_compliances:
            if "SOC2" in inferred_compliances: threat_compliance_risks.add("SOC2")
            if "ISO 27001" in inferred_compliances: threat_compliance_risks.add("ISO 27001")

            if inputs.get("logging") == "No": compliance_gaps.add(f"SOC2/ISO 27001: Inadequate logging and monitoring.")
            if inputs.get("auditing") == "No": compliance_gaps.add(f"SOC2/ISO 27001: No regular security audits or penetration testing.")
            if inputs.get("model_card") == "No": compliance_gaps.add(f"SOC2: Lack of model documentation (governance gap).")
            if inputs.get("incident_response") == "No": compliance_gaps.add(f"SOC2: Insufficient incident response plan.")
            if inputs.get("secrets_managed_securely") == "No": compliance_gaps.add(f"SOC2/ISO 27001: Insecure secrets management.")
            if inputs.get("env_patching_scanning") == "No": compliance_gaps.add(f"SOC2/ISO 27001: Unpatched/unscanned environments.")
            if inputs.get("network_segmentation") == "No": compliance_gaps.add(f"SOC2/ISO 27001: Lack of network segmentation.")
            if inputs.get("access_control") == "None": compliance_gaps.add(f"SOC2/ISO 27001: Insufficient access control.")

        # --- AI-Specific Governance (NIST AI RMF / EU AI Act) Gaps ---
        if "NIST AI RMF" in inferred_compliances or "EU AI Act (Future)" in inferred_compliances:
            if "NIST AI RMF" in inferred_compliances: threat_compliance_risks.add("NIST AI RMF")
            if "EU AI Act (Future)" in inferred_compliances: threat_compliance_risks.add("EU AI Act (Future)")

            if inputs.get("explainability") == "No": compliance_gaps.add(f"NIST AI RMF/EU AI Act: Lack of explainability for AI decisions.")
            if inputs.get("model_card") == "No": compliance_gaps.add(f"NIST AI RMF/EU AI Act: Insufficient model documentation.")
            if inputs.get("user_influence") == "Yes" and inputs.get("output_filtering") == "No": compliance_gaps.add(f"NIST AI RMF/EU AI Act: Risk of bias/harm from unmitigated user influence on outputs.")
            if inputs.get("auto_action") == "Yes" and inputs.get("can_override") == "No": compliance_gaps.add(f"NIST AI RMF/EU AI Act: Automated decisions without human oversight/override.")
            if inputs.get("output_watermarking") == "No": compliance_gaps.add(f"NIST AI RMF/EU AI Act: Lack of output traceability/watermarking.")
            if inputs.get("rl_feedback") == "Yes" and inputs.get("user_influence") == "Yes": compliance_gaps.add(f"NIST AI RMF/EU AI Act: RLHF with potential for feedback poisoning.")
            
            # Agentic AI specific gaps (only if AI type is Agentic AI)
            if is_agentic_ai: # Use specific flag
                if inputs.get("agentic_autonomous") == "Yes" and inputs.get("agentic_hitl") == "No": compliance_gaps.add(f"NIST AI RMF/EU AI Act: Uncontrolled autonomous actions in Agentic AI.")
                if inputs.get("agentic_logging") == "No": compliance_gaps.add(f"NIST AI RMF/EU AI Act: Insufficient logging in Agentic AI systems.")
                if inputs.get("agentic_malicious_input_detection") == "No": compliance_gaps.add(f"NIST AI RMF/EU AI Act: Agentic AI vulnerable to adversarial attacks.")
                if inputs.get("agentic_sensitive_data") == "Yes" and inputs.get("data_encrypted_at_rest") == "No": compliance_gaps.add(f"NIST AI RMF/EU AI Act: Sensitive data exposure in Agentic AI due to lack of encryption.")
                if inputs.get("agentic_tool_access") == "Yes" and inputs.get("sandboxing") == "No": compliance_gaps.add(f"NIST AI RMF/EU AI Act: Insecure Agent tool/API interaction (lack of sandboxing).")


        basic_threats.append({
            "id": threat_id,
            "threat": title,
            "description": description,
            "owasp": owasp,
            "mitre": mitre,
            "nist": nist,
            "mitigation": mitigation,
            "compliance": sorted(list(threat_compliance_risks)), # Use set to avoid duplicates
            "attack_path": attack_path,
            "reason": reason,
            "severity": severity # Added severity
        })

    def add_chained(threat_id, title, description, owasp, mitre, nist, mitigation, attack_path, reason_components, severity="High"): # Default to High severity for chained
        threat_compliance_risks = set()
        
        # Determine and add relevant compliance frameworks to the threat's specific risks
        if "GDPR" in inferred_compliances and (has_pii_in_training_data or is_agentic_sensitive_data_yes): threat_compliance_risks.add("GDPR")
        if "CCPA" in inferred_compliances and (has_pii_in_training_data or is_agentic_sensitive_data_yes): threat_compliance_risks.add("CCPA")
        if "HIPAA" in inferred_compliances and (has_phi_in_training_data or is_agentic_sensitive_data_yes): threat_compliance_risks.add("HIPAA")
        if "PCI DSS" in inferred_compliances: threat_compliance_risks.add("PCI DSS")
        if "SOC2" in inferred_compliances: threat_compliance_risks.add("SOC2")
        if "ISO 27001" in inferred_compliances: threat_compliance_risks.add("ISO 27001")
        if "NIST AI RMF" in inferred_compliances: threat_compliance_risks.add("NIST AI RMF")
        if "EU AI Act (Future)" in inferred_compliances: threat_compliance_risks.add("EU AI Act (Future)")
        
        # Join reason components into a formatted string
        reason_string = " ➡️ ".join(reason_components) + "."

        chained_threats.append({
            "id": threat_id,
            "threat": title + " 🔗 (Threat Chain)",
            "description": description,
            "owasp": owasp,
            "mitre": mitre,
            "nist": nist,
            "mitigation": mitigation,
            "compliance": sorted(list(threat_compliance_risks)),
            "attack_path": attack_path,
            "reason": reason_string,
            "severity": severity # Added severity
        })

    # ====================================================================================================
    # INDIVIDUAL THREATS: CAREFULLY REVIEWED CONDITIONS AND OWASP ID ASSIGNMENTS FOR AI TYPE CONSISTENCY
    # ====================================================================================================

    # Lack of Model Documentation (LLM09 / ML10 related) - Conditional OWASP ID
    if inputs.get("model_card") == "No":
        owasp_id = "LLM09: Overreliance" if is_llm_gen_agentic_type else "ML10: Lack of Governance"
        reason = f"You indicated that 'Model documentation is NOT maintained (Model Card: {inputs.get('model_card')})'."
        add_basic(
            "no_model_card", "Lack of Model Documentation", "Without a model card or proper documentation, it's difficult to track purpose, limitations, risks, and changes, leading to overreliance or misuse.",
            owasp_id, "TA0040: Impact", ["Abuse", "Integrity", "Confidentiality"],
            "Maintain comprehensive model documentation (e.g., Model Cards, datasheets) detailing purpose, limitations, and risks.",
            ["Step 1: Model deployed without clear documentation", "Step 2: Misunderstanding of model capabilities or data biases by users or developers", "Step 3: Unintended, harmful, or non-compliant use in production leading to ethical or security failures"],
            reason
        )

    # Sensitive Information Disclosure (LLM06 / ML06 related) - Universal Threat, Conditional OWASP ID
    # Issue 2: Data Leakage Risk Logic
    is_external_user_risk = "Customers" in inputs.get("users", []) or "Anonymous" in inputs.get("users", [])
    is_external_hosting_risk = inputs.get("infra") != "On-prem"
    is_external_source_risk = inputs.get("external_sources") == "Yes" or inputs.get("external_systems") == "Yes" or inputs.get("exposure") == "Public" or inputs.get("exposure") == "Authenticated Users Only" # More precise "sharing"

    if (has_pii_in_training_data or has_phi_in_training_data or is_agentic_sensitive_data_yes) and inputs.get("output_filtering") == "No":
        # Only add data leakage threat if there's a clear external vector or non-private hosting
        if is_external_user_risk or is_external_hosting_risk or is_external_source_risk:
            owasp_id = "LLM06: Sensitive Information Disclosure" if is_llm_gen_agentic_type else "ML06: Data Leakage (Sensitive Data Exposure)"
            
            reason_parts = []
            if has_pii_in_training_data: reason_parts.append("PII in training data")
            if has_phi_in_training_data: reason_parts.append("PHI in training data")
            if is_agentic_sensitive_data_yes: reason_parts.append("Agentic AI handles sensitive data")
            reason_parts.append(f"Output filtering is NOT performed ({inputs.get('output_filtering')})")
            
            if is_external_user_risk: reason_parts.append(f"External user exposure ({inputs.get('users')})")
            if is_external_hosting_risk: reason_parts.append(f"Non-on-prem hosting ({inputs.get('infra')})")
            if is_external_source_risk: reason_parts.append(f"External exposure/sources ({inputs.get('exposure')}, {inputs.get('external_sources')}, {inputs.get('external_systems')})")
            
            reason = "Your project indicates: " + ", and ".join(reason_parts) + "."

            add_basic(
                "sensitive_info_disclosure", "Sensitive Information Disclosure", "Model may leak PII/PHI from training data or external sources if outputs are not filtered, posing significant privacy risks.",
                owasp_id, "TA0010: Exfiltration", ["Confidentiality"],
                "Implement robust output filtering and anonymization/redaction techniques. Ensure sensitive data is not over-retained and minimize its presence in training data.",
                ["Step 1: User queries model", "Step 2: Model generates output containing sensitive training data/inferences due to lack of filtering", "Step 3: Sensitive data exposed to unauthorized user, leading to a privacy breach"],
                reason, severity="High"
            )

    # Data Poisoning / Integrity (LLM03 / ML01 related) - Universal Threat, Conditional OWASP ID
    if (inputs.get("user_influence") == "Yes" or (inputs.get("real_time") == "Yes" and "Public" in inputs.get("training_data", [])) or inputs.get("rl_feedback") == "Yes"): # Added RLHF here
        owasp_id = "LLM03: Training Data Poisoning" if is_llm_gen_agentic_type else "ML01: Training Data Poisoning"
        reason_parts = []
        if inputs.get("user_influence") == "Yes": reason_parts.append(f"Users can influence training or inference data ({inputs.get('user_influence')})")
        if inputs.get("real_time") == "Yes" and "Public" in inputs.get("training_data", []): reason_parts.append(f"Real-time inputs are used ({inputs.get('real_time')}) with 'Public' training data")
        if inputs.get("rl_feedback") == "Yes": reason_parts.append(f"Reinforcement Learning from Human Feedback (RLHF) is used ({inputs.get('rl_feedback')})")
        reason = " and ".join(reason_parts) + ". This increases the risk of malicious data injection, compromising model integrity."
        add_basic(
            "data_poisoning", "Training Data Poisoning", "Malicious actors can inject poisoned data into training or fine-tuning datasets, compromising model integrity and leading to altered, incorrect, or harmful outputs.",
            owasp_id, "TA0003: Persistence", ["Integrity", "Availability"],
            "Implement strict data validation, anomaly detection, and provenance tracking for training data. Regularly audit datasets and monitor real-time inputs for suspicious patterns.",
            ["Step 1: Malicious data is subtly introduced into the training or inference pipeline by an attacker", "Step 2: Model is trained on or influenced by the poisoned data, leading to a compromise of its learned behavior or internal state", "Step 3: Model behavior is altered, resulting in incorrect, biased, or harmful outputs that persist over time"],
            reason, severity="High"
        )

    # Direct Query / Prompt Injection (LLM01 / ML03 related) - Universal Threat, Conditional OWASP ID
    if inputs.get("direct_query") == "Yes" and inputs.get("input_validation") == "No":
        owasp_id = "LLM01: Prompt Injection" if is_llm_gen_agentic_type else "ML03: Inference API Abuse"
        reason_parts = [f"Users can 'Directly query the model ({inputs.get('direct_query')})'"]
        reason_parts.append(f"Inputs are NOT validated before inference ({inputs.get('input_validation')})")
        if is_llm_gen_agentic_type: # Only add these parts to reason if it's an LLM-like type
            if inputs.get("prompt_template") == "Free-form": reason_parts.append(f"Prompt strategy is 'Free-form' ({inputs.get('prompt_template')})")
            if "None" in inputs.get("llm_firewall", []): reason_parts.append("No LLM Specific Guardrails are used")
        reason = " and ".join(reason_parts) + "."
        add_basic(
            "direct_query_vulnerability", "Direct Query Vulnerability / Prompt Injection", "Unvalidated direct queries can lead to prompt injection (for LLMs) or inference API abuse (for ML), bypassing safety measures or extracting sensitive information.",
            owasp_id, "TA0001: Initial Access", ["Integrity", "Confidentiality"],
            "Implement strong input validation and sanitization. Use templated prompts and LLM-specific guardrails (LLM Firewalls) where possible.",
            ["Step 1: Malicious input (e.g., a carefully crafted prompt) is sent to the model's API directly", "Step 2: The input is processed without adequate validation, allowing the malicious instructions to be interpreted as legitimate", "Step 3: Model executes unintended commands, reveals internal data (jailbreaking), or performs actions outside its intended scope"],
            reason, severity="High"
        )

    # Insecure Plugin Design / Access (LLM07 related) - LLM-Specific Threat, ADDED STRICT GUARD
    # This threat is ONLY added if is_llm_gen_agentic_type is true.
    if is_llm_gen_agentic_type and inputs.get("plugin_access") == "Yes" and inputs.get("sandboxing") == "No":
        owasp_id = "LLM07: Insecure Plugin Design"
        reason = f"The 'Model can access tools/plugins ({inputs.get('plugin_access')})' but 'Plugin/tool execution is NOT sandboxed ({inputs.get('sandboxing')})'."
        add_basic(
            "insecure_plugins", "Insecure Plugin/Tool Design/Access", "Unsandboxed execution of plugins/tools can lead to privilege escalation, unauthorized actions, or interaction with sensitive systems.",
            owasp_id, "TA0004: Privilege Escalation", ["Integrity", "Confidentiality", "Availability"],
            "Enforce strict sandboxing, least privilege, and rigorous validation for all plugin/tool execution and their configurations.",
            ["Step 1: Model is prompted or configured to use an external plugin or tool", "Step 2: The plugin executes without proper sandboxing, allowing it to bypass intended security boundaries", "Step 3: Unauthorized system access, data manipulation, or arbitrary code execution occurs, leveraging the model's access to the plugin"],
            reason, severity="Critical"
        )

    # Excessive Agency / Uncontrolled External System Access (LLM08 related) - LLM-Specific Threat, ADDED STRICT GUARD
    # This threat is ONLY added if is_llm_gen_agentic_type is true.
    if is_llm_gen_agentic_type and inputs.get("external_systems") == "Yes" and inputs.get("can_override") == "No":
        owasp_id = "LLM08: Excessive Agency"
        reason = f"The 'Model can access external systems ({inputs.get('external_systems')})' but its 'Outputs CANNOT be overridden by human review ({inputs.get('can_override')})', leading to uncontrolled actions."
        add_basic(
            "external_system_access", "Excessive Agency / Uncontrolled External System Access", "Model's unmonitored access to external systems without human oversight can lead to unintended, irreversible, or harmful actions.",
            owasp_id, "TA0005: Defense Evasion", ["Integrity", "Availability", "Confidentiality"],
            "Implement human-in-the-loop controls for critical actions, strict access policies for external systems (least privilege), and comprehensive audit trails of all external interactions.",
            ["Step 1: Model autonomously decides to interact with an external system (e.g., API, database, device)", "Step 2: The action is performed without human review or an ability to override the decision in critical scenarios", "Step 3: Harmful or unauthorized operations occur on the external system, potentially leading to financial loss, data corruption, or system compromise"],
            reason, severity="Critical"
        )

    # Inadequate Logging and Monitoring (ML09 / General) - Universal Threat, always uses ML09
    if inputs.get("logging") == "No":
        owasp_id = "ML09: Inadequate Logging and Monitoring"
        reason = f"'Logs & Monitoring are NOT enabled ({inputs.get('logging')})' for model inputs, outputs, and actions."
        add_basic(
            "inadequate_logging", "Inadequate Logging and Monitoring", "Lack of comprehensive logging and monitoring hinders incident response, threat detection, and forensic analysis, making it difficult to detect or recover from attacks.",
            owasp_id, "TA0007: Collection", ["Availability", "Confidentiality", "Integrity"],
            "Implement comprehensive logging for all model inputs, outputs, decisions, and system events. Establish real-time monitoring and alerting for anomalies and suspicious activities.",
            ["Step 1: A security incident or malicious activity occurs within the AI system", "Step 2: Due to insufficient logs or monitoring, the incident goes undetected, or critical forensic evidence is missing", "Step 3: Incident response is delayed or ineffective, allowing attackers to persist or escalate their actions, or making post-incident analysis impossible"],
            reason, severity="High"
        )

    # Insecure ML Deployment (ML08 / General) - Universal Threat, always uses ML08
    if inputs.get("exposure") == "Public" and inputs.get("access_control") == "None":
        owasp_id = "ML08: Insecure ML Deployment"
        reason = f"The model has 'Public' exposure and 'Access Control is None ({inputs.get('access_control')})'."
        add_basic(
            "insecure_deployment", "Insecure ML Deployment", "Public exposure without proper access controls makes the model vulnerable to unauthorized access, abuse, and potential intellectual property theft.",
            owasp_id, "TA0001: Initial Access", ["Confidentiality", "Integrity", "Availability"],
            "Implement strong authentication, fine-grained authorization (RBAC/ABAC), and network security measures (e.g., WAF, API Gateway, network segmentation) for public endpoints.",
            ["Step 1: An attacker discovers the publicly exposed model endpoint", "Step 2: With no access controls in place, the attacker gains unauthorized access to query or interact with the model", "Step 3: Attacker performs malicious activities such as reconnaissance, model abuse, or attempts to steal the model itself"],
            reason, severity="High"
        )

    # Model Theft (LLM10 / ML02 related) - Universal Threat, Conditional OWASP ID
    # Logic Fixed: OWASP ID is conditional on AI type
    if inputs.get("model_source") == "Proprietary" and inputs.get("exposure") == "Public" and inputs.get("access_control") == "None":
        owasp_id = "LLM10: Model Theft" if is_llm_gen_agentic_type else "ML02: Model Theft"
        reason = f"Your 'Model Source is Proprietary ({inputs.get('model_source')})', it has 'Public' exposure, and 'Access Control is None ({inputs.get('access_control')})'."
        add_basic(
            "model_theft_risk", "Model Theft Risk", "Proprietary models exposed publicly without access control are at high risk of intellectual property theft via API access, model inversion, or other techniques.",
            owasp_id, "TA0010: Exfiltration", ["Confidentiality"],
            "Implement robust API security, strong access controls, rate limiting, and obfuscation techniques. Restrict access to authorized users and consider watermarking models.",
            ["Step 1: Attacker queries publicly exposed model without authentication or authorization", "Step 2: Attacker uses a series of queries and analysis (e.g., model inversion, reconstruction attacks) to deduce model architecture, parameters, or training data characteristics", "Step 3: Proprietary model intellectual property is stolen or recreated, leading to competitive disadvantage or unauthorized use"],
            reason, severity="High"
        )

    # Inadequate Adversarial Security Posture (ML04 / General) - Universal Threat, always uses ML04
    if ("None" in inputs.get("adversarial_test_types", []) and "None" in inputs.get("adversarial_test_tools", []) and inputs.get("red_team") == "No"):
        owasp_id = "ML04: Adversarial Examples"
        reason = f"No 'Adversarial testing types ({', '.join(inputs.get('adversarial_test_types', []))})' or 'tools ({', '.join(inputs.get('adversarial_test_tools', []))})' are performed, and 'Red teaming is NOT conducted ({inputs.get('red_team')})'."
        add_basic(
            "inadequate_adversarial_security_posture", "Inadequate Adversarial Security Posture", "Lack of adversarial testing and red teaming indicates a weak defense against sophisticated AI attacks, making the model vulnerable to evasion or manipulation.",
            owasp_id, "TA0005: Defense Evasion", ["Integrity", "Availability"],
            "Establish a comprehensive adversarial testing program, including red teaming, data poisoning, and model evasion. Implement specific adversarial defenses (e.g., robust training, input sanitization).",
            ["Step 1: Attacker crafts adversarial input (e.g., a perturbed image, a disguised prompt)", "Step 2: Model's defenses are insufficient to detect or withstand the adversarial perturbation", "Step 3: Model misclassifies, generates harmful output, or behaves unexpectedly, allowing the attacker to bypass intended controls or achieve malicious goals"],
            reason, severity="Medium"
        )

    # Lack of Output Traceability (LLM09: Overreliance / ML10: Lack of Governance related) - Universal Threat, Conditional OWASP ID
    if inputs.get("output_watermarking") == "No":
        owasp_id = "LLM09: Overreliance" if is_llm_gen_agentic_type else "ML10: Lack of Governance"
        reason = f"'Output traceable/watermarked is NOT enabled ({inputs.get('output_watermarking')})'."
        add_basic(
            "lack_of_output_traceability", "Lack of Output Traceability/Watermarking", "Without watermarking or traceability, it's hard to distinguish model-generated content from human-generated content, enabling misuse such as misinformation or fraud.",
            owasp_id, "TA0040: Impact", ["Integrity", "Abuse"],
            "Implement digital watermarking, cryptographic signatures, or clear provenance metadata for all model outputs to ensure traceability and accountability.",
            ["Step 1: Model generates content (text, image, code)", "Step 2: The content is indistinguishable from human-created work due to lack of watermarking or provenance", "Step 3: Content is used to mislead, defraud, spread misinformation, or impersonate, impacting trust and potentially leading to legal/reputational harm"],
            reason, severity="Medium"
        )

    # Unencrypted Data & Model Artifacts at Rest - Universal Threat, always uses ML06
    if inputs.get("data_encrypted_at_rest") == "No" or inputs.get("artifacts_encrypted_at_rest") == "No":
        owasp_id = "ML06: Data Leakage (Sensitive Data Exposure)"
        reason_parts = []
        if inputs.get("data_encrypted_at_rest") == "No": reason_parts.append(f"training/inference data is NOT encrypted at rest ({inputs.get('data_encrypted_at_rest')})")
        if inputs.get("artifacts_encrypted_at_rest") == "No": reason_parts.append(f"model artifacts are NOT encrypted at rest ({inputs.get('artifacts_encrypted_at_rest')})")
        reason = " and ".join(reason_parts) + "."
        add_basic(
            "unencrypted_data_artifacts", "Unencrypted Data & Model Artifacts at Rest", "Sensitive training/inference data and valuable model artifacts are vulnerable to unauthorized access and exfiltration if not encrypted at rest.",
            owasp_id, "TA0010: Exfiltration", ["Confidentiality"],
            "Ensure all data and model artifacts are encrypted using strong, industry-standard encryption methods (e.g., AES-256) at rest.",
            ["Step 1: Sensitive data or valuable model artifacts are stored on persistent storage without encryption", "Step 2: An attacker gains unauthorized access to the storage infrastructure (e.g., compromised host, stolen disk)", "Step 3: Sensitive data or intellectual property is directly exfiltrated without decryption challenges"],
            reason, severity="High"
        )

    if inputs.get("env_patching_scanning") == "No":
        owasp_id = "ML08: Insecure ML Deployment"
        reason = f"The 'Model's environment (containers/VMs) is NOT regularly patched and scanned ({inputs.get('env_patching_scanning')})'."
        add_basic(
            "unpatched_unscanned_env", "Unpatched/Unscanned Model Environments", "Environments hosting the AI model (VMs, containers) are vulnerable to known exploits and misconfigurations if not regularly patched and scanned for vulnerabilities.",
            owasp_id, "TA0002: Execution", ["Integrity", "Confidentiality", "Availability"],
            "Implement continuous vulnerability scanning, patch management, and configuration management for all AI infrastructure components (VMs, containers, host OS).",
            ["Step 1: An attacker identifies a known vulnerability in the operating system, libraries, or applications within the model's environment", "Step 2: The environment has not been regularly patched or scanned, leaving the vulnerability exposed", "Step 3: Attacker exploits the vulnerability to gain remote code execution, elevate privileges, or disrupt the model's operation"],
            reason, severity="High"
        )

    if inputs.get("secrets_managed_securely") == "No":
        owasp_id = "ML06: Data Leakage (Sensitive Data Exposure)"
        reason = f"'Secrets (API keys, credentials) are NOT managed securely (e.g., using a secrets manager) ({inputs.get('secrets_managed_securely')})'."
        add_basic(
            "insecure_secrets_management", "Insecure Secrets Management", "API keys, credentials, and other sensitive secrets for accessing data or services are not securely managed, risking unauthorized access to integrated systems.",
            owasp_id, "TA0006: Credential Access", ["Confidentiality"],
            "Utilize dedicated secrets management solutions (e.g., AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) and follow least privilege principles for secret access.",
            ["Step 1: Hardcoded, insecurely stored, or improperly managed secrets (e.g., API keys, database credentials) are exposed in code repositories, configuration files, or logs", "Step 2: An attacker discovers and gains access to these exposed secrets", "Step 3: Attacker uses the compromised secrets to gain unauthorized access to external services, databases, or sensitive data, escalating the breach"],
            reason, severity="High"
        )

    if inputs.get("network_segmentation") == "No" and inputs.get("exposure") == "Public":
        owasp_id = "ML08: Insecure ML Deployment"
        reason = f"'Network segmentation is NOT applied to model deployment environments ({inputs.get('network_segmentation')})' for a 'Publicly exposed' model."
        add_basic(
            "lack_of_network_segmentation", "Lack of Network Segmentation for Publicly Exposed Models", "A publicly exposed model without network segmentation allows an attacker to move laterally within the network more easily in case of compromise, increasing blast radius.",
            owasp_id, "TA0008: Lateral Movement", ["Confidentiality", "Integrity", "Availability"],
            "Implement strict network segmentation (VPCs, subnets, firewalls, security groups) to isolate model deployment environments from other critical internal systems.",
            ["Step 1: The publicly exposed model or its hosting environment is initially compromised (e.g., via a successful attack)", "Step 2: Due to a flat or inadequately segmented network, the attacker can easily pivot and move laterally from the compromised AI environment to other internal systems", "Step 3: This lateral movement leads to a broader system compromise, exfiltration of more sensitive data, or disruption of other critical services"],
            reason, severity="High"
        )

    # --- NEW: Supply Chain Attack via Model Source (Fixed Logic Gap) - Universal Threat, Conditional OWASP ID ---
    if inputs.get("model_source") in ["Open-source", "Pretrained (Vendor)"]:
        owasp_id = "LLM05: Supply Chain Vulnerabilities" if is_llm_gen_agentic_type else "ML07: Supply Chain Vulnerabilities"
        reason = f"Model source is '{inputs.get('model_source')}', introducing reliance on external components which can be compromised upstream."
        add_basic(
            "supply_chain_attack_model_source", "Supply Chain Attack via Model Source",
            "Models sourced from open-source repositories or third-party vendors are vulnerable to poisoned models, backdoored weights, or compromised dependencies injected upstream.",
            owasp_id, "TA0001: Initial Access", ["Integrity", "Confidentiality", "Availability"],
            "Vet all third-party model components and dependencies. Implement software supply chain security practices, including integrity checks, SBOMs, and vulnerability scanning of dependencies.",
            ["Step 1: Malicious code/weights are injected into an upstream open-source model or vendor-pretrained model.", "Step 2: The compromised model is integrated into your AI system.", "Step 3: The attacker leverages the upstream compromise to execute arbitrary code, exfiltrate data, or alter model behavior in your production environment."],
            reason, severity="High"
        )
    
    # --- NEW: Insufficient Dynamic Model Monitoring (Fixed Logic Gap) - Universal Threat, always uses ML09 ---
    if inputs.get("model_updates") == "Yes" and inputs.get("logging") == "No":
        owasp_id = "ML09: Inadequate Logging and Monitoring" # Can be ML-specific or apply broadly
        reason = f"Model auto-updates are enabled ({inputs.get('model_updates')}), but logging and monitoring are NOT enabled ({inputs.get('logging')}), leaving dynamic behavior unchecked."
        add_basic(
            "insufficient_dynamic_monitoring", "Insufficient Dynamic Model Monitoring",
            "Models that auto-update (e.g., via continuous learning, RLHF) without comprehensive monitoring can drift into unsafe behaviors, introduce biases, or be compromised without detection.",
            owasp_id, "TA0007: Collection", ["Integrity", "Availability", "Abuse"],
            "Implement robust MLOps monitoring for model performance, drift, data integrity, and unexpected outputs, especially for continuously updated models.",
            ["Step 1: An auto-update is deployed, or the model continuously learns in production.", "Step 2: The model's behavior shifts (e.g., due to data drift, minor adversarial attacks, or subtle compromise).", "Step 3: Without adequate monitoring, this behavior drift goes unnoticed, leading to persistent errors, biases, or subtle malicious actions."],
            reason, severity="Medium"
        )

    # --- NEW: Unsafe Prompt Templating / Direct Prompt Injection (Fixed Logic Gap) - LLM-Specific Threat, ADDED STRICT GUARD ---
    # This threat is ONLY added if is_llm_gen_agentic_type is true.
    if is_llm_gen_agentic_type and inputs.get("prompt_template") == "Free-form" and inputs.get("input_validation") == "No":
        owasp_id = "LLM01: Prompt Injection"
        reason = f"AI Type is LLM/Generative/Agentic, uses 'Free-form' prompt strategy ({inputs.get('prompt_template')}) and inputs are NOT validated ({inputs.get('input_validation')})."
        add_basic(
            "unsafe_prompt_templating", "Unsafe Prompt Templating / Direct Prompt Injection Vulnerability",
            "Using free-form prompts without strict input validation greatly increases the risk of prompt injection attacks, allowing attackers to override safety measures or extract sensitive information.",
            owasp_id, "TA0001: Initial Access", ["Integrity", "Confidentiality"],
            "Prefer templated prompts where possible. Implement robust input validation, sanitization, and prompt defense techniques (e.g., prompt firewalls, input encoding).",
            ["Step 1: Attacker sends a malicious, free-form prompt directly to the model.", "Step 2: The model processes the unvalidated prompt, misinterpreting malicious instructions as legitimate requests.", "Step 3: The model is 'jailbroken', bypasses safety filters, performs unintended actions, or leaks sensitive information."],
            reason, severity="Critical"
        )

    # --- NEW: Lack of LLM Guardrails (Fixed Logic Gap) - LLM-Specific Threat, ADDED STRICT GUARD ---
    # This threat is ONLY added if is_llm_gen_agentic_type is true.
    if is_llm_gen_agentic_type and "None" in inputs.get("llm_firewall", []) and inputs.get("direct_query") == "Yes":
        owasp_id = "LLM01: Prompt Injection" # Can also link to LLM02, LLM06
        reason = f"AI Type is LLM/Generative/Agentic, no LLM Specific Guardrails Used ({inputs.get('llm_firewall', [])}), and users can directly query the model ({inputs.get('direct_query')})."
        add_basic(
            "lack_llm_guardrails", "Lack of LLM Specific Guardrails",
            "Without dedicated LLM guardrails (e.g., moderation APIs, prompt armor), models exposed to direct queries are highly vulnerable to prompt injection, jailbreaking, and content generation risks.",
            owasp_id, "TA0005: Defense Evasion", ["Integrity", "Confidentiality", "Abuse"],
            "Deploy and configure LLM-specific guardrails (e.g., content moderation APIs, prompt firewalls) to filter malicious inputs and outputs.",
            ["Step 1: Attacker sends a malicious prompt to the directly exposed LLM.", "Step 2: No LLM guardrails are in place to detect or block the malicious input/intent.", "Step 3: The LLM generates harmful, biased, or inappropriate content, or is jailbroken to bypass intended controls."],
            reason, severity="High"
        )

    # =============================
    # Agentic AI Specific Threats (New Section) - STRICTLY CONDITIONED ON AI TYPE
    # =============================
    # ENSURING ALL THREATS IN THIS SECTION ONLY APPLY IF is_agentic_ai IS TRUE
    if is_agentic_ai:
        # Uncontrolled Autonomous Actions
        if inputs.get("agentic_autonomous") == "Yes" and inputs.get("agentic_hitl") == "No":
            reason = f"The AI Type is 'Agentic AI' and it 'operates autonomously ({inputs.get('agentic_autonomous')})' but there are NO 'clear human-in-the-loop (HITL) review processes for sensitive agent actions ({inputs.get('agentic_hitl')})'."
            add_basic(
                "uncontrolled_autonomous_actions", "Uncontrolled Autonomous Actions", "Agentic AI operating autonomously without sufficient human oversight can lead to unintended, destructive, or misaligned actions, potentially causing real-world harm.",
                "LLM08: Excessive Agency", "TA0006: Impact", ["Integrity", "Availability", "Confidentiality"],
                "Implement robust human-in-the-loop (HITL) processes for critical decisions and actions, allowing for review and override. Establish clear boundaries, guardrails, and 'circuit breakers' for autonomous operation.",
                ["Step 1: Autonomous agent makes a decision or plans an action that is flawed, malicious (due to compromise), or outside its intended parameters", "Step 2: Without HITL or effective guardrails, the action is executed without human review or intervention", "Step 3: Leads to data corruption, system shutdown, unauthorized transactions, or other severe unintended consequences in the real or digital world"],
                reason, severity="Critical"
            )

        # Insecure Agent Tool/API Interaction
        if inputs.get("agentic_tool_access") == "Yes" and inputs.get("sandboxing") == "No":
             reason = f"The 'agent can access external tools or APIs ({inputs.get('agentic_tool_access')})' but 'plugin/tool execution is NOT sandboxed ({inputs.get('sandboxing')})'."
             add_basic(
                "insecure_agent_tool_api_interaction", "Insecure Agent Tool/API Interaction", "Agentic AI with unsandboxed access to external tools/APIs can be exploited for unauthorized operations, privilege escalation, or unintended side effects in integrated systems.",
                "LLM07: Insecure Plugin Design", "TA0004: Privilege Escalation", ["Confidentiality", "Integrity", "Availability"],
                "Apply least privilege principles to agent's tool access, implement granular access controls, and strictly sandbox all external tool/API interactions. Monitor agent-initiated API calls for anomalies.",
                ["Step 1: A malicious input or a compromised agent causes it to misuse an accessible external tool or API", "Step 2: The tool or API executes actions without proper sandboxing or validation of the agent's intent, leveraging the agent's permissions", "Step 3: Unauthorized actions such as data modification, sensitive data access, or system compromise occur via the external tool, leading to a broader breach"],
                reason, severity="Critical"
            )

        # Insufficient Observability in Agentic Systems
        if inputs.get("agentic_logging") == "No":
            reason = f"The 'agent's actions and decision-making processes are NOT fully logged and auditable ({inputs.get('agentic_logging')})'."
            add_basic(
                "insufficient_agentic_observability", "Insufficient Observability in Agentic Systems", "Lack of comprehensive logging and auditing for autonomous agent actions makes it difficult to detect, diagnose, and respond to incidents, leading to repudiation risks and hidden malicious activity.",
                "ML09: Inadequate Logging and Monitoring", "TA0007: Collection", ["Confidentiality", "Integrity", "Availability"],
                "Implement immutable, cryptographically signed logs for all agent actions, decisions, and external interactions. Ensure real-time monitoring and alerting for anomalous agent behavior patterns.",
                ["Step 1: An autonomous agent performs a malicious or erroneous action in complex, multi-step operations", "Step 2: Due to insufficient logs or fragmented audit trails, the action goes undetected, or critical forensic evidence is missing", "Step 3: Incident response is delayed or ineffective, allowing attackers to persist or escalate their actions, or making post-incident analysis impossible"],
                reason, severity="High"
            )

        # Sensitive Data Exposure by Agent
        if inputs.get("agentic_sensitive_data") == "Yes" and inputs.get("data_encrypted_at_rest") == "No":
            reason = f"The 'agent handles/processes sensitive data ({inputs.get('agentic_sensitive_data')})' but 'training/inference data is NOT encrypted at rest ({inputs.get('data_encrypted_at_rest')})'."
            add_basic(
                "sensitive_data_exposure_agent", "Sensitive Data Exposure by Agent", "Agentic AI handling sensitive information without proper encryption or data protection measures poses a high risk of data breaches, especially given its autonomous nature.",
                "LLM06: Sensitive Information Disclosure", "TA0010: Exfiltration", ["Confidentiality", "Integrity"],
                "Ensure all sensitive data processed, stored, or accessed by the agent is encrypted both at rest and in transit. Implement strict data minimization and access control policies for agent interactions with sensitive data.",
                ["Step 1: Agent accesses or processes sensitive data (PII/PHI) within its operating environment or through its data sources", "Step 2: The data is not adequately protected (e.g., unencrypted in memory or storage) during the agent's workflow", "Step 3: An attacker exploits a vulnerability (e.g., within the agent's memory, through its outputs, or compromised compromised storage) to intercept or exfiltrate the sensitive data"],
                reason, severity="High"
            )

        # Vulnerability to Agentic Adversarial Attacks
        if inputs.get("agentic_malicious_input_detection") == "No":
            reason = f"The 'agent does NOT have mechanisms to detect and mitigate malicious input (e.g., prompt injection, memory poisoning, goal hijacking) ({inputs.get('agentic_malicious_input_detection')})'."
            add_basic(
                "vulnerability_agentic_adversarial_attacks", "Vulnerability to Agentic Adversarial Attacks", "Agentic AI systems lacking robust defenses against malicious inputs (e.g., memory poisoning, intent breaking, goal hijacking) are susceptible to manipulation and unpredictable behavior, risking goal misalignment.",
                "LLM01: Prompt Injection", "TA0003: Persistence", ["Integrity", "Confidentiality", "Availability"],
                "Implement advanced input validation, memory sanitization, behavioral monitoring, and prompt guarding techniques to detect and prevent adversarial attacks against agentic systems. Regularly update models with adversarial training and apply robust input/output filters.",
                ["Step 1: Adversary injects malicious data or instructions into the agent's prompt, memory, or observation space (e.g., via crafted feedback)", "Step 2: Agent's internal state, reasoning, or goal is subtly or overtly altered, leading to goal hijacking or deceptive behavior", "Step 3: Agent performs actions beneficial to the attacker (e.g., data exfiltration, system compromise, or unintended real-world actions) or causes unintended harm, persisting over time"],
                reason, severity="Critical"
            )

    # =============================
    # Chained Threats (Original and Enhanced)
    # =============================

    # Data Exfiltration Chain
    if (inputs.get("external_systems") == "Yes" and inputs.get("data_encrypted_at_rest") == "No" and inputs.get("access_control") == "None"):
        reason_components = [
            f"Model can access external systems ({inputs.get('external_systems')})",
            f"Sensitive data is NOT encrypted at rest ({inputs.get('data_encrypted_at_rest')})",
            f"Access Control is None ({inputs.get('access_control')})"
        ]
        add_chained(
            "data_exfiltration_chain", "Data Exfiltration Chain", "A combination of unconstrained external system access, unencrypted sensitive data at rest, and weak access controls creates a high-risk chain for data exfiltration.",
            "LLM06: Sensitive Information Disclosure" if is_llm_gen_agentic_type else "ML06: Data Leakage (Sensitive Data Exposure)", # Conditional OWASP ID
            "TA0010: Exfiltration", ["Confidentiality", "Integrity"],
            "Implement strong access controls (e.g., RBAC, token-based), ensure all sensitive data is encrypted at rest and in transit, and strictly limit model's external system access to least privilege.",
            ["Step 1: An attacker gains initial access to the model or its environment (e.g., via vulnerable endpoint, compromised credentials).", "Step 2: The attacker leverages the model's unconstrained access to external systems or discovers unencrypted sensitive data at rest.", "Step 3: Sensitive data is successfully exfiltrated from the external system or the model's storage due to a lack of overlapping controls (encryption, access control)."],
            reason_components, severity="Critical"
        )

    # Model Manipulation & Misinformation Chain
    if (inputs.get("user_influence") == "Yes" and inputs.get("output_filtering") == "No" and inputs.get("explainability") == "No"):
        reason_components = [
            f"Users can influence training or inference data ({inputs.get('user_influence')})",
            f"Outputs are NOT filtered ({inputs.get('output_filtering')})",
            f"NO explainability/interpretability for model decisions ({inputs.get('explainability')})"
        ]
        add_chained(
            "model_misinformation_chain", "Model Manipulation & Misinformation Chain", "When users can influence model data (e.g., via feedback), outputs are unvalidated, and model explainability is missing, it creates a dangerous chain for model manipulation and widespread misinformation.",
            "LLM03: Training Data Poisoning" if is_llm_gen_agentic_type else "ML01: Training Data Poisoning", # Conditional OWASP ID
            "TA0005: Defense Evasion", ["Integrity", "Abuse"],
            "Implement robust data validation and anomaly detection for user-influenced data, rigorous output filtering, and enhance model explainability to detect and mitigate manipulation.",
            ["Step 1: A malicious user introduces subtle (or overt) biases or harmful content via feedback loops or user-generated data that influences the model.", "Step 2: The model integrates this poisoned data, leading to skewed behavior or the generation of misleading/harmful content.", "Step 3: Due to lack of output filtering and explainability, the misinformation or malicious output goes undetected and is disseminated, impacting users or systems and causing harm."],
            reason_components, severity="Critical"
        )

    # Insecure Plugin Execution Chain
    # This chained threat is ONLY added if is_llm_gen_agentic_type is true.
    if is_llm_gen_agentic_type and (inputs.get("plugin_access") == "Yes" and inputs.get("sandboxing") == "No" and inputs.get("external_systems") == "Yes" and inputs.get("logging") == "No"):
        reason_components = [
            f"Model can access tools/plugins ({inputs.get('plugin_access')})",
            f"Plugin execution is NOT sandboxed ({inputs.get('sandboxing')})",
            f"Can access external systems ({inputs.get('external_systems')})",
            f"Logs & Monitoring are NOT enabled ({inputs.get('logging')})"
        ]
        add_chained(
            "plugin_execution_chain", "Insecure Plugin Execution Chain", "A model with unsandboxed access to plugins, capable of interacting with external systems, and lacking comprehensive logging, creates a severe chain for arbitrary code execution and data exfiltration.",
            "LLM07: Insecure Plugin Design", # LLM-Specific OWASP ID
            "TA0004: Privilege Escalation", ["Integrity", "Confidentiality", "Availability"],
            "Strictly sandbox all plugin execution, apply least privilege to external system access, and enable comprehensive logging for all model and plugin activities to ensure auditability.",
            ["Step 1: A malicious input or a compromised model triggers the execution of a vulnerable or misused plugin.", "Step 2: The plugin operates outside a secure sandbox due to lack of isolation, allowing it to gain system-level access or unintended privileges.", "Step 3: The attacker leverages the compromised plugin to interact with external systems (e.g., databases, other services) that the model can access.", "Step 4: This leads to data exfiltration, arbitrary code execution on external systems, or broader system compromise, with limited audit trails due to lack of logging."],
            reason_components, severity="Critical"
        )
    
    # --- NEW CHAINED THREATS ---

    # Manipulation Chain (user_influence + rl_feedback + no explainability)
    if (inputs.get("user_influence") == "Yes" and inputs.get("rl_feedback") == "Yes" and inputs.get("explainability") == "No"):
        reason_components = [
            f"Users can influence data via feedback loops ({inputs.get('user_influence')})",
            f"Reinforcement Learning from Human Feedback (RLHF) is used ({inputs.get('rl_feedback')})",
            f"NO explainability/interpretability for model decisions ({inputs.get('explainability')})"
        ]
        add_chained(
            "manipulation_chain_rlhf", "Feedback Loop Manipulation & Misalignment Chain",
            "When user feedback directly influences model behavior (e.g., via RLHF) and explainability is lacking, malicious feedback can subtly manipulate the model's goals, leading to misaligned or harmful outcomes without clear detection.",
            "LLM03: Training Data Poisoning" if is_llm_gen_agentic_type else "ML01: Training Data Poisoning", # Conditional OWASP ID
            "TA0005: Defense Evasion", ["Integrity", "Abuse"],
            "Implement robust validation and filtering of human feedback. Ensure clear human oversight and anomaly detection in RLHF pipelines. Enhance model explainability to understand the impact of feedback.",
            ["Step 1: Malicious actors inject subtly poisoned feedback into the RLHF pipeline.", "Step 2: The model's behavior shifts in response to this feedback, subtly altering its objectives or introducing biases.", "Step 3: Lack of explainability prevents detection of this manipulation, leading to the model acting against its intended purpose or causing unintended harm."],
            reason_components, severity="Critical"
        )

    # Upstream Data Poisoning (model_updates + external_sources + no security controls)
    if (inputs.get("model_updates") == "Yes" and inputs.get("external_sources") == "Yes" and 
        ("None" in inputs.get("adversarial_test_types", []) or inputs.get("auditing") == "No")):
        reason_components = [
            f"Model auto-updates are enabled ({inputs.get('model_updates')})",
            f"Uses external sources (e.g., RAG) ({inputs.get('external_sources')})",
            f"Adversarial testing is NOT performed ({'None' in inputs.get('adversarial_test_types', [])})" if "None" in inputs.get("adversarial_test_types", []) else f"Auditing is NOT performed ({inputs.get('auditing')})"
        ]
        add_chained(
            "upstream_data_poisoning_chain", "Upstream/Dynamic Data Poisoning Chain",
            "A model that frequently updates and incorporates data from external sources is vulnerable to continuous data poisoning attacks from those sources, especially without robust adversarial testing or auditing.",
            "LLM03: Training Data Poisoning" if is_llm_gen_agentic_type else "ML01: Training Data Poisoning", # Conditional OWASP ID
            "TA0003: Persistence", ["Integrity", "Availability"],
            "Implement rigorous data provenance, integrity checks, and anomaly detection for all external data sources. Conduct continuous adversarial testing (data poisoning) and regular security audits of data pipelines.",
            ["Step 1: An attacker poisons data in an external source (e.g., public dataset, third-party API) consumed by the model.", "Step 2: The model automatically incorporates this poisoned data during its regular updates.", "Step 3: The model's integrity is continuously compromised, leading to persistent misbehavior, biases, or vulnerabilities, often undetected due to lack of testing/auditing."],
            reason_components, severity="High"
        )

    # --- NEW CHAINED THREATS BASED ON USER'S NEW SCENARIOS ---
    
    # 1. user_input_controls = None + feedback_loop = Yes (Reinforcement of malicious data)
    if (inputs.get("user_influence") == "Yes" and (inputs.get("access_control") == "None" or inputs.get("input_validation") == "No")):
        reason_components = [
            f"User feedback/influence is enabled ({inputs.get('user_influence')})",
            f"NO robust user input controls (Access Control: {inputs.get('access_control')}, Input Validation: {inputs.get('input_validation')})"
        ]
        add_chained(
            "feedback_loop_malicious_reinforcement", "Malicious Feedback Reinforcement Chain",
            "When user feedback mechanisms are active without strict input controls, malicious data can be continually reinforced into the model's learning, leading to persistent bias, manipulation, or performance degradation.",
            "LLM03: Training Data Poisoning" if is_llm_gen_agentic_type else "ML01: Training Data Poisoning", # Conditional OWASP ID
            "TA0003: Persistence", ["Integrity", "Availability", "Abuse"],
            "Implement strict input validation for all user feedback. Utilize anomaly detection in feedback loops. Ensure human review is present for sensitive feedback influencing model behavior.",
            ["Step 1: Malicious user provides poisoned feedback data.", "Step 2: Feedback is processed without adequate controls, leading to model learning from malicious data.", "Step 3: Malicious behavior or bias is reinforced over time, impacting model integrity and performance persistently."],
            reason_components, severity="High"
        )

    # 2. model_auto_updates = Yes + external_model_source = True (Poisoning via upstream)
    # This specifically links model_updates to model_source.
    if (inputs.get("model_updates") == "Yes" and inputs.get("model_source") in ["Open-source", "Pretrained (Vendor)"]):
        reason_components = [
            f"Model auto-updates are enabled ({inputs.get('model_updates')})",
            f"Model source is external ({inputs.get('model_source')})"
        ]
        add_chained(
            "upstream_model_poisoning_auto_update", "Upstream Model Poisoning via Auto-Updates Chain",
            "Models that auto-update from external sources (open-source, pre-trained vendors) are vulnerable to continuous data poisoning attacks from those sources, where compromised model artifacts can be automatically integrated.",
            "LLM05: Supply Chain Vulnerabilities" if is_llm_gen_agentic_type else "ML07: Supply Chain Vulnerabilities", # Conditional OWASP ID
            "TA0003: Persistence", ["Integrity", "Availability", "Confidentiality"],
            "Implement integrity checks for model artifacts. Vet all external model sources. Use trusted repositories and secure supply chain practices for model deployment pipelines.",
            ["Step 1: An external model source (e.g., open-source repository) is compromised with malicious model weights or artifacts.", "Step 2: Your model automatically updates itself from this compromised source.", "Step 3: The malicious model artifacts are integrated into your production model, leading to persistent vulnerabilities or backdoors."],
            reason_components, severity="High"
        )
    
    # 3. explainability_required = Yes + model_explainability = None (Compliance or lack of oversight)
    # This chained threat is ONLY added if explainability is missing AND relevant AI compliance is inferred.
    if inputs.get("explainability") == "No" and ("NIST AI RMF" in inferred_compliances or "EU AI Act (Future)" in inferred_compliances):
        reason_components = [
            f"NO explainability/interpretability for model decisions ({inputs.get('explainability')})",
            f"Relevant AI compliance frameworks are inferred (e.g., {', '.join([c for c in inferred_compliances if c in ['NIST AI RMF', 'EU AI Act (Future)']])})"
        ]
        add_chained(
            "explainability_compliance_gap", "Explainability Compliance Gap Chain",
            "A lack of model explainability/interpretability, combined with the applicability of AI-specific compliance frameworks, results in a significant compliance gap and hinders effective risk management and auditing.",
            "LLM08: Excessive Agency" if is_llm_gen_agentic_type else "ML10: Lack of Governance", # Conditional OWASP ID
            "TA0009: Collection", ["Integrity", "Abuse"],
            "Implement explainable AI (XAI) techniques. Ensure model documentation covers explainability aspects. Regularly audit model decisions for compliance with explainability requirements.",
            ["Step 1: A model makes a critical decision lacking clear rationale.", "Step 2: No explainability mechanism is in place to provide insights into this decision.", "Step 3: This lack of transparency leads to a violation of regulatory requirements (e.g., 'right to explanation') and prevents effective auditing or dispute resolution."],
            reason_components, severity="High"
        )


    return {
        "basic": basic_threats,
        "chained": chained_threats,
        "inferred_compliances": inferred_compliances,
        "compliance_gaps": sorted(list(compliance_gaps))
    }
