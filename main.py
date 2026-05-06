import json
import os
from collections import Counter
from contextlib import contextmanager
from datetime import datetime
from io import BytesIO

import plotly.graph_objects as go
import plotly.io as pio
import streamlit as st

from rules_engine import evaluate_threats, compute_risk_score

# ---------------------------------------------------------------------------
# Autosave — persist form answers across Streamlit server restarts
# ---------------------------------------------------------------------------
_ATM_AUTOSAVE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".atm_autosave.json"
)

def _autosave():
    """Write all current form answers to disk (called every render cycle).
    Navigation state (step_index, report_requested) is intentionally NOT
    saved — the app always opens on page 1 so the user fills in fresh."""
    try:
        payload = {k: st.session_state.get(k) for k in initial_values}
        with open(_ATM_AUTOSAVE, "w") as _fh:
            json.dump(payload, _fh, default=str)
    except Exception:
        pass

def _autoload():
    """Restore form answers saved by a previous server run.
    Type-validates each value against its default: if the default is a string
    but the saved value is an integer (stale Streamlit widget index), the saved
    value is discarded and the default is used instead.
    """
    try:
        if os.path.isfile(_ATM_AUTOSAVE):
            with open(_ATM_AUTOSAVE) as _fh:
                raw = json.load(_fh)
            if not isinstance(raw, dict):
                return {}
            cleaned = {}
            for k, v in raw.items():
                default = initial_values.get(k)
                # If the default is a string but we loaded an int/float,
                # the file stored a widget index — discard it.
                if isinstance(default, str) and not isinstance(v, str):
                    continue
                # If the default is a list but we loaded something else, skip.
                if isinstance(default, list) and not isinstance(v, list):
                    continue
                cleaned[k] = v
            return cleaned
    except Exception:
        pass
    return {}

def _autosave_clear():
    """Remove the autosave file (called when user resets all answers)."""
    try:
        if os.path.isfile(_ATM_AUTOSAVE):
            os.remove(_ATM_AUTOSAVE)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Default values for every input key the rule engine reads.
# Keep this in sync with rules_engine.evaluate_threats().
# ---------------------------------------------------------------------------
initial_values = {
    # Persona for UX (not consumed by rules engine, filtered out before evaluate_threats)
    "persona": "Security Engineer",

    # Project context
    "project_name": "",
    "description": "",
    "ai_type": "Traditional ML",
    "project_stage": "Development",
    "business_impact": "Moderate",
    "regulated_domain": [],
    "model_type": "Classifier",
    "model_source": "Open-source",
    "model_updates": "No",
    "model_supply_chain_controls": [],

    # Fine-tune specific
    "fine_tune_data_review": "Not Applicable",
    "fine_tune_base_model_trust": "Not Applicable",

    # Data & behavior
    "training_data": [],
    "data_sensitivity": [],
    "data_governance_controls": [],
    "unlearning_capability": "No",
    "external_sources": "No",
    "real_time": "No",
    "outputs": [],
    "output_destinations": [],
    "users": [],
    "direct_query": "No",
    "auto_action": "No",
    "plugin_access": "No",
    "external_systems": "No",
    "can_override": "No",
    "user_influence": "No",

    # RAG / retrieval / memory
    "rag_usage": "No",
    "rag_data_sources": [],
    "retrieval_access_control": "Not Applicable",
    "retrieval_content_filtering": "Not Applicable",
    "vector_db_isolation": "Not Applicable",
    "embedding_model_provenance": "Not Applicable",
    "embedding_inversion_controls": "Not Applicable",

    # Deployment
    "infra": "AWS",
    "exposure": "Public",
    "access_control": "None",
    "rate_limiting": "No",
    "tenant_isolation": "Not Applicable",
    "abuse_monitoring": "No",
    "cost_monitoring": "No",
    "ai_gateway": "No",
    "waf": "No",
    "network_segmentation": "No",
    "env_patching_scanning": "No",
    "ci_cd_security": "No",
    "backup_rollback": "No",
    "incident_response": "No",

    # Security controls
    "input_validation": "No",
    "output_filtering": "No",
    "prompt_template": "Not Applicable",
    "llm_firewall": [],
    "system_prompt_secrets": "Not Applicable",
    "system_prompt_protection": "Not Applicable",
    "hallucination_controls": "Not Applicable",
    "multimodal_injection_testing": "Not Applicable",
    "sandboxing": "No",
    "data_encrypted_at_rest": "No",
    "artifacts_encrypted_at_rest": "No",
    "secrets_managed_securely": "No",
    "logging": "No",
    "auditing": "No",
    "adversarial_test_types": [],
    "adversarial_test_tools": [],
    "red_team": "No",
    "safety_evals": "No",

    # Governance
    "model_card": "No",
    "rl_feedback": "No",
    "output_watermarking": "No",
    "explainability": "No",

    # Agentic
    "agentic_autonomous": "Not Applicable",
    "agentic_tool_access": "Not Applicable",
    "agentic_logging": "Not Applicable",
    "agentic_hitl": "Not Applicable",
    "agentic_sensitive_data": "Not Applicable",
    "agentic_malicious_input_detection": "Not Applicable",
    "agentic_memory": "Not Applicable",
    "agentic_memory_controls": "Not Applicable",
    "agentic_identity_scoped": "Not Applicable",
    "agentic_code_execution": "Not Applicable",
    "agentic_code_sandbox": "Not Applicable",
    "agentic_supply_chain_controls": "Not Applicable",
    "agentic_kill_switch": "Not Applicable",
    "agentic_multi_agent": "Not Applicable",
    "agentic_inter_agent_auth": "Not Applicable",
    "agentic_plan_inspection": "Not Applicable",
    "browser_agent_use": "No",

    # MCP
    "mcp_usage": "Not Applicable",
    "mcp_third_party_servers": "Not Applicable",
    "mcp_remote_servers": "Not Applicable",
    "mcp_tool_schema_integrity": "Not Applicable",
    "mcp_tool_output_sanitization": "Not Applicable",
    "mcp_authz": "Not Applicable",
    "mcp_human_approval": "Not Applicable",
    "mcp_server_isolation": "Not Applicable",

    # ---------------------------------------------------------------
    # 2026 ADVANCED COVERAGE (added April 2026)
    # ---------------------------------------------------------------
    # Wiring fix: rules_engine.py reads `data_validation` in 5+ rules
    # (data poisoning, RLHF, fine-tune, training-data integrity).
    # Previously phantom-read; now wired to a real question.
    "data_validation": "No",

    # Multi-modal injection (broader than just one yes/no)
    "vision_injection_testing": "Not Applicable",      # adversarial text in images
    "audio_injection_testing":  "Not Applicable",      # acoustic adversarial / Whisper attacks
    "document_pdf_injection":   "Not Applicable",      # PDF/doc prompt-injection sanitization
    "deepfake_detection":       "No",                  # impersonation / synthetic-voice defenses
    "c2pa_provenance":          "Not Applicable",      # C2PA digital content credentials
    "watermark_robustness":     "Not Applicable",      # watermark survives transformations

    # Generative-AI specific
    "training_data_ip_review":  "No",                  # copyright/IP risk of memorized training data
    "model_collapse_monitoring":"Not Applicable",      # monitoring for AI-on-AI training collapse

    # Fine-tune / customization risks
    "lora_adapter_validation":  "Not Applicable",      # PEFT/LoRA adapter source trust
    "alignment_regression_testing": "Not Applicable",  # safety eval re-run after fine-tune
    "jailbreak_transfer_testing":"Not Applicable",     # jailbreak transferability across models

    # Inference-time / shared infrastructure
    "kv_cache_isolation":       "Not Applicable",      # KV-cache leakage in multi-tenant inference

    # Agentic AI 2026 additions
    "agent_collusion_controls":      "Not Applicable", # multi-agent infection chain detection
    "agent_identity_verification":   "Not Applicable", # cryptographic agent identity (vs. just inter-agent auth)
    "agent_goal_drift_monitoring":   "Not Applicable", # long-horizon goal drift detection
    "agent_credential_acquisition":  "Not Applicable", # controls on agents requesting new privileges
    "agent_hitl_bypass_detection":   "Not Applicable", # detect agents trying to bypass HITL gates

    # MCP 2026 additions
    "mcp_federation_trust":     "Not Applicable",      # transitive trust in chained MCP servers
    "mcp_tool_description_validation":"Not Applicable",# validate JSON tool descriptions
    "mcp_prompt_in_result_filtering":"Not Applicable", # sanitize tool RESULTS for embedded prompts
    "mcp_transport_security":   "Not Applicable",      # TLS / signed transport (HTTP/SSE/stdio)
    "mcp_shadow_discovery":     "Not Applicable",      # detect unauthorized MCP server registration
    "mcp_audit_telemetry":      "Not Applicable",      # full MCP invocation logging

    # Governance, regulatory & supply-chain transparency
    "ai_bom":                   "No",                  # AI Bill of Materials maintained
    "ai_incident_response_plan":"No",                  # AI-specific (vs generic) incident plan
    "eu_ai_act_high_risk":      "Unknown",             # is this an EU AI Act high-risk system?
    "iso_42001_alignment":      "No",                  # ISO/IEC 42001 AI management alignment
    "third_party_audit_ready":  "No",                  # ready for external AI audits

    # Classical ML specific
    "adversarial_robustness_testing": "No",
    "membership_inference_controls":  "No",
    "model_inversion_controls":       "No",
    "feature_attribution_available":  "No",
    "ml_drift_monitoring":            "No",
    "ml_input_schema_validation":     "No",

    # Agentic — deployment-level controls (injected into Deployment step)
    "agent_action_rate_limit":        "No",   # per-action cap, separate from API rate limiting
    "agent_per_run_budget":           "No",   # max steps / tokens / cost per single agent run
    "agent_execution_isolation":      "No",   # agent runs in isolated infra vs. shared prod

    # Agentic — security-level controls (injected into Security step)
    "agent_scope_declared":           "No",   # explicit allowlist of tools/APIs the agent may call
    "agent_tool_output_sanitization": "No",   # tool results sanitized before LLM re-ingestion
    "agent_destructive_action_gate":  "No",   # send/delete/write actions require explicit approval

    # Agentic — data-scope controls (injected into Data & Behavior step)
    "agent_data_write_access":        "No",   # agent can modify/delete external data stores
    "agent_exfil_controls":           "No",   # controls to prevent agent from leaking data to external APIs
    # Reinforcement Learning — specific controls
    "rl_reward_hacking_tested":       "Not Applicable",  # reward function audited / red-teamed
    "rl_policy_drift_monitoring":     "Not Applicable",  # monitoring for policy degradation / env shift
    "rl_safe_rl_constraints":         "Not Applicable",  # safety constraints / shielding in the RL loop
    # Edge AI / IoT — specific controls
    "edge_ota_update_security":       "Not Applicable",  # OTA firmware/model update integrity checks
    "edge_physical_adversarial":      "Not Applicable",  # physical adversarial example / patch testing
    "edge_model_encryption":          "Not Applicable",  # model weights encrypted on device
}


# ---------------------------------------------------------------------------
# Pre-built Templates — one-click project bootstrapping
# ---------------------------------------------------------------------------
TEMPLATES = {
    "── Select a template ──": {},
    "Customer Chatbot (LLM)": {
        "project_name": "Customer Support Chatbot",
        "ai_type": "Large Language Model (LLM)",
        "model_type": "LLM (Generic)",
        "model_source": "Third-party API / SaaS",
        "project_stage": "Production",
        "business_impact": "High",
        "exposure": "Public",
        "direct_query": "Yes",
        "user_influence": "Yes",
        "external_sources": "No",
        "data_sensitivity": ["PII"],
        "users": ["Customers"],
        "input_validation": "No",
        "output_filtering": "No",
        "rate_limiting": "No",
        "auditing": "No",
        "secrets_managed_securely": "No",
        "data_encrypted_at_rest": "No",
    },
    "RAG Knowledge System": {
        "project_name": "Internal RAG Knowledge Assistant",
        "ai_type": "RAG / AI Search",
        "model_type": "RAG Application",
        "model_source": "Pretrained (Vendor)",
        "project_stage": "Pilot",
        "business_impact": "High",
        "exposure": "Authenticated Users Only",
        "direct_query": "Yes",
        "rag_usage": "Yes",
        "external_sources": "Yes",
        "data_sensitivity": ["PII", "Credentials/secrets"],
        "users": ["Internal employees"],
        "input_validation": "No",
        "output_filtering": "No",
        "retrieval_access_control": "No",
        "vector_db_isolation": "No",
        "secrets_managed_securely": "No",
    },
    "Agentic AI Assistant": {
        "project_name": "Autonomous AI Agent",
        "ai_type": "Agentic AI (e.g., Autonomous Agents)",
        "model_type": "Agentic Workflow / Autonomous Agent",
        "model_source": "Fine-tuned",
        "project_stage": "Development",
        "business_impact": "Critical",
        "exposure": "Internal-only",
        "agentic_autonomous": "Yes",
        "agentic_tool_access": "Yes",
        "agentic_hitl": "No",
        "agentic_memory": "Yes",
        "agentic_code_execution": "Yes",
        "direct_query": "Yes",
        "auto_action": "Yes",
        "external_systems": "Yes",
        "plugin_access": "Yes",
        "input_validation": "No",
        "output_filtering": "No",
        "secrets_managed_securely": "No",
        "users": ["Internal employees"],
    },
    "ML Fraud Detection": {
        "project_name": "ML Fraud Detection Model",
        "ai_type": "Traditional ML",
        "model_type": "Classifier",
        "model_source": "Internally trained from scratch",
        "project_stage": "Production",
        "business_impact": "Critical",
        "exposure": "Back-office batch job",
        "data_sensitivity": ["Financial/payment data", "PII"],
        "external_sources": "Yes",
        "real_time": "Yes",
        "users": ["Internal employees"],
        "input_validation": "No",
        "output_filtering": "No",
        "model_card": "No",
        "data_encrypted_at_rest": "No",
        "secrets_managed_securely": "No",
        "auditing": "No",
    },
    "Generative AI (Image/Media)": {
        "project_name": "Generative AI Media System",
        "ai_type": "Generative AI (e.g., Image/Audio Generation)",
        "model_type": "Multimodal Model",
        "model_source": "Open-source",
        "project_stage": "Pilot",
        "business_impact": "High",
        "exposure": "Public",
        "direct_query": "Yes",
        "user_influence": "Yes",
        "external_sources": "No",
        "data_sensitivity": [],
        "users": ["Customers", "Anonymous"],
        "output_filtering": "No",
        "rate_limiting": "No",
        "auditing": "No",
        "model_card": "No",
    },
    "MCP Tool-Integrated Assistant": {
        "project_name": "MCP-Integrated AI Assistant",
        "ai_type": "Agentic AI (e.g., Autonomous Agents)",
        "model_type": "MCP / Tool-Integrated Assistant",
        "model_source": "Third-party API / SaaS",
        "project_stage": "Development",
        "business_impact": "High",
        "exposure": "Internal-only",
        "mcp_usage": "Yes",
        "mcp_third_party_servers": "Yes",
        "mcp_authz": "No",
        "mcp_human_approval": "No",
        "direct_query": "Yes",
        "auto_action": "Yes",
        "external_systems": "Yes",
        "plugin_access": "Yes",
        "secrets_managed_securely": "No",
        "auditing": "No",
        "users": ["Internal employees"],
    },
}


# ---------------------------------------------------------------------------
# Option lists
# ---------------------------------------------------------------------------
AI_TYPE_OPTIONS = [
    "Traditional ML",
    # Engine has dedicated branches for these classical-ML sub-types — surface
    # them in the selector so the specialization isn't dead code. They all
    # resolve to the "ml" profile downstream.
    "Computer Vision",
    "NLP (Non-LLM)",
    "Recommendation System",
    "Anomaly Detection / Fraud Detection",
    "Generative AI (e.g., Image/Audio Generation)",
    "Large Language Model (LLM)",
    "RAG / AI Search",
    "Multimodal AI",
    "Agentic AI (e.g., Autonomous Agents)",
]

# Suggested defaults for the model-type field per AI type — keeps the
# questionnaire coherent when a non-default ai_type is selected.
AI_TYPE_DEFAULT_MODEL_TYPE = {
    "Traditional ML":                     "Classifier",
    "Computer Vision":                    "CNN / Computer Vision",
    "NLP (Non-LLM)":                      "Transformer",
    "Recommendation System":              "Recommender System",
    "Anomaly Detection / Fraud Detection":"Clustering / Anomaly Detection",
    "Generative AI (e.g., Image/Audio Generation)": "Multimodal Model",
    "Large Language Model (LLM)":         "LLM (Generic)",
    "RAG / AI Search":                    "RAG Application",
    "Multimodal AI":                      "Multimodal Model",
    "Agentic AI (e.g., Autonomous Agents)": "Agentic Workflow / Autonomous Agent",
}

MODEL_TYPE_OPTIONS = [
    "Classifier",
    "Regression",
    "Clustering / Anomaly Detection",
    "Recommender System",
    "CNN / Computer Vision",
    "Transformer",
    "Embedding / Vector Search",
    "LLM (Generic)",
    "LLM (Custom/Fine-tuned)",
    "RAG Application",
    "Multimodal Model",
    "Agentic Workflow / Autonomous Agent",
    "Multi-Agent System",
    "MCP / Tool-Integrated Assistant",
    "Reinforcement Learning System",
    "Edge AI / IoT Model",
    "Other Custom",
]

MODEL_SOURCE_OPTIONS = [
    "Open-source",
    "Pretrained (Vendor)",
    "Fine-tuned",
    "Proprietary",
    "Internally trained from scratch",
    "Third-party API / SaaS",
    "Marketplace model",
    "Unknown",
]

PROJECT_STAGE_OPTIONS = ["Idea / PoC", "Development", "Pilot", "Production", "Retired / Decommissioning"]
BUSINESS_IMPACT_OPTIONS = ["Low", "Moderate", "High", "Critical"]

INFRA_OPTIONS = [
    "AWS", "GCP", "Azure", "On-prem", "Edge",
    "Hybrid / multi-cloud", "SaaS / vendor-hosted", "Developer workstation / local",
]
EXPOSURE_OPTIONS = [
    "Public", "Internal-only", "Authenticated Users Only",
    "Partner / third-party API", "Back-office batch job",
    "Embedded in product", "Developer-only / experimental",
]
ACCESS_CONTROL_OPTIONS = [
    "None", "Token-based", "Role-based", "Attribute/policy-based",
    "SSO/OIDC", "mTLS/service identity", "Network-only allowlist",
]

# Every control / yes-no question accepts "Not Applicable" so the user can
# explicitly mark a question as irrelevant to their system. The engine scores
# NA as 0 (no gap) and skips firing rules that depend on a missing control.
CONTROL_OPTIONS = ["Yes", "Partial", "No", "Unknown", "Not Applicable"]
YN_OPTIONS      = ["Yes", "No", "Not Applicable"]

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
# Bug 11: distinct, easy-to-tell-apart colors for severity charts
SEVERITY_COLORS = {
    "Critical": "#7f1d1d",  # deep maroon
    "High":     "#ef4444",  # bright red
    "Medium":   "#f59e0b",  # amber
    "Low":      "#10b981",  # emerald
}

# ---------------------------------------------------------------------------
# OWASP framework description maps (current 2025 IDs)
# ---------------------------------------------------------------------------
OWASP_LLM_TOP_10_DESCRIPTION_MAP = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

OWASP_ML_TOP_10_DESCRIPTION_MAP = {
    "ML01": "Input Manipulation Attack",
    "ML02": "Data Poisoning Attack",
    "ML03": "Model Inversion Attack",
    "ML04": "Membership Inference Attack",
    "ML05": "Model Theft",
    "ML06": "AI Supply Chain Attacks",
    "ML07": "Transfer Learning Attack",
    "ML08": "Model Skewing",
    "ML09": "Output Integrity Attack",
    "ML10": "Model Poisoning",
}

OWASP_AGENTIC_TOP_10_DESCRIPTION_MAP = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

OWASP_MCP_TOP_10_DESCRIPTION_MAP = {
    "MCP01": "Token Mismanagement and Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Software Supply Chain Attacks and Dependency Tampering",
    "MCP05": "Command Injection and Execution",
    "MCP06": "Intent Flow Subversion",
    "MCP07": "Insufficient Authentication and Authorization",
    "MCP08": "Lack of Audit and Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection and Over-Sharing",
}


pio.templates.default = "plotly_white"
st.set_page_config(
    page_title="Threat Modelling of AI / ML Project",
    page_icon="[AI]",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------------------------
# State and selection helpers
# ---------------------------------------------------------------------------
def _type_valid(default, value):
    """Return True if value is type-compatible with default.
    Rejects integers/floats saved when a selectbox stored its index instead of
    its string label — the most common form of autosave corruption."""
    if isinstance(default, str):
        return isinstance(value, str)
    if isinstance(default, list):
        return isinstance(value, list)
    if isinstance(default, bool):
        return isinstance(value, bool)
    return True  # don't restrict other types


def initialize_state():
    # ── Streamlit widget-GC guard ──────────────────────────────────────────────
    # Streamlit removes widget keys from session_state when the widget is not
    # rendered (e.g. ai_type selectbox only exists on the Project step).  On
    # page 3+ the key disappears and initialize_state would reset it to the
    # default "Traditional ML", collapsing the whole architecture selection.
    #
    # Fix: we maintain shadow non-widget copies (_arch_*) that Streamlit never
    # GC-s. When a widget key is missing we restore from the shadow copy before
    # anything else runs.
    _ARCH_KEYS = {
        "ai_type":      "Traditional ML",
        "model_type":   "Classifier",
        "model_source": "Open-source",
    }
    for key, fallback in _ARCH_KEYS.items():
        shadow = f"_arch_{key}"
        if key not in st.session_state:
            # Widget was GC-d — restore from shadow (or fall back to default)
            st.session_state[key] = st.session_state.get(shadow, fallback)
        else:
            # Widget is present — refresh the shadow so it stays current
            st.session_state[shadow] = st.session_state[key]

    # project_name is a text_input that Streamlit GC-s whenever Step 1 is not
    # rendered.  Guard it with the same shadow pattern so the user's typed name
    # survives navigation to other steps.
    _pn_shadow = "_shadow_project_name"
    if "project_name" not in st.session_state:
        st.session_state["project_name"] = st.session_state.get(_pn_shadow, "")
    else:
        st.session_state[_pn_shadow] = st.session_state["project_name"]

    # Set defaults for keys not yet in session state.
    for key, default_value in initial_values.items():
        if key not in st.session_state:
            st.session_state[key] = default_value
        elif not _type_valid(default_value, st.session_state[key]):
            # Existing session-state value is wrong type (e.g. integer index
            # instead of string label) — reset to the safe default.
            st.session_state[key] = default_value

    if "report_requested" not in st.session_state:
        st.session_state.report_requested = False
    if "step_index" not in st.session_state:
        st.session_state.step_index = 0

    # On the very first render after a server restart, restore from autosave.
    # The _autosave_loaded flag ensures we only do this once per session.
    if not st.session_state.get("_autosave_loaded"):
        saved = _autoload()
        for k, v in saved.items():
            if k in initial_values:   # restore form answers only
                st.session_state[k] = v
        # Navigation always resets to step 0 on a fresh load
        st.session_state["step_index"] = 0
        st.session_state["report_requested"] = False
        st.session_state["_autosave_loaded"] = True
        # Initialise shadow keys from the just-loaded autosave values
        for key in _ARCH_KEYS:
            st.session_state[f"_arch_{key}"] = st.session_state.get(key, _ARCH_KEYS[key])
        # Seed the project_name shadow so it survives GC on the first render
        st.session_state["_shadow_project_name"] = st.session_state.get("project_name", "")


def option_index(options, current_value, default_index=0):
    return options.index(current_value) if current_value in options else default_index


def is_llm_like_selection():
    return (
        st.session_state.ai_type
        in [
            "Large Language Model (LLM)",
            "Generative AI (e.g., Image/Audio Generation)",
            "RAG / AI Search",
            "Multimodal AI",
            "Agentic AI (e.g., Autonomous Agents)",
        ]
        or st.session_state.model_type
        in [
            "LLM (Generic)",
            "LLM (Custom/Fine-tuned)",
            "RAG Application",
            "Multimodal Model",
            "Agentic Workflow / Autonomous Agent",
            "Multi-Agent System",
            "MCP / Tool-Integrated Assistant",
        ]
    )


def is_rag_selection():
    return (
        st.session_state.rag_usage == "Yes"
        or st.session_state.ai_type == "RAG / AI Search"
        or st.session_state.model_type in ["RAG Application", "Embedding / Vector Search"]
    )


def is_multimodal_selection():
    return (
        st.session_state.ai_type == "Multimodal AI"
        or st.session_state.model_type == "Multimodal Model"
    )


def is_agentic_selection():
    return (
        st.session_state.ai_type == "Agentic AI (e.g., Autonomous Agents)"
        or st.session_state.model_type
        in ["Agentic Workflow / Autonomous Agent", "Multi-Agent System"]
    )


def is_mcp_selection():
    return (
        st.session_state.get("mcp_usage") == "Yes"
        or st.session_state.model_type == "MCP / Tool-Integrated Assistant"
    )


def is_fine_tuned_selection():
    return st.session_state.model_source == "Fine-tuned"


def is_trad_ml_selection():
    return st.session_state.ai_type in [
        "Traditional ML",
        "Computer Vision",
        "NLP (Non-LLM)",
        "Recommendation System",
        "Anomaly Detection / Fraud Detection",
    ] or st.session_state.model_type in [
        # Names must exactly match MODEL_TYPE_OPTIONS
        "Classifier",
        "Regression",
        "Clustering / Anomaly Detection",
        "Recommender System",
        "CNN / Computer Vision",
        "Reinforcement Learning System",
        "Edge AI / IoT Model",
    ]


# ---------------------------------------------------------------------------
# Adaptive questionnaire helpers
# These predicates read from st.session_state and are used to:
#   - Filter options within a question (e.g. remove Garak if not LLM)
#   - Conditionally show/hide questions within a step
#   - Auto-clean stale answers after architecture changes
# ---------------------------------------------------------------------------

def _state_is_llm_like():
    """True if the selected AI type or model type is LLM / generative."""
    return is_llm_like_selection()


def _state_is_traditional_ml():
    """True if the selected AI type is Traditional ML (classifier, regression, etc.)."""
    return (
        st.session_state.ai_type == "Traditional ML"
        and st.session_state.model_type in [
            "Classifier", "Regression", "Clustering / Anomaly Detection",
            "Recommender System", "CNN / Computer Vision", "Transformer",
            "Embedding / Vector Search", "Reinforcement Learning System",
            "Edge AI / IoT Model", "Other Custom",
        ]
    )


def _state_has_external_users():
    """True if end-users include customers, anonymous, or partners."""
    users = st.session_state.get("users", [])
    return any(u in users for u in ["Customers", "Anonymous", "Partners"])


def _state_has_sensitive_data():
    """True if data_sensitivity includes PII, PHI, financial or credential data."""
    ds = st.session_state.get("data_sensitivity", [])
    return any(d in ds for d in ["PII", "PHI", "Financial/payment data", "Credentials/secrets",
                                   "Children/minors data", "Biometric data"])


def _state_has_tools_or_actions():
    """True if the system takes automatic actions or can call external tools."""
    return (
        st.session_state.get("plugin_access") == "Yes"
        or st.session_state.get("auto_action") == "Yes"
        or is_agentic_selection()
    )


def _state_is_public_facing():
    """True if the service is exposed publicly or to external users."""
    return st.session_state.get("exposure") in [
        "Public", "Authenticated Users Only", "Partner / third-party API", "Embedded in product"
    ]


# Model type options filtered by the currently selected AI type
def _model_types_for_ai_type():
    ai_type = st.session_state.get("ai_type", "Traditional ML")
    if ai_type == "Traditional ML":
        return [
            "Classifier", "Regression", "Clustering / Anomaly Detection",
            "Recommender System", "CNN / Computer Vision", "Transformer",
            "Embedding / Vector Search", "Reinforcement Learning System",
            "Edge AI / IoT Model", "Other Custom",
        ]
    # ML sub-types — each gets a short, focused list with the best-fit
    # model_type at index 0 so the default selection makes sense.
    elif ai_type == "Computer Vision":
        return [
            "CNN / Computer Vision", "Classifier", "Transformer",
            "Edge AI / IoT Model", "Other Custom",
        ]
    elif ai_type == "NLP (Non-LLM)":
        return [
            "Transformer", "Classifier", "Embedding / Vector Search",
            "Other Custom",
        ]
    elif ai_type == "Recommendation System":
        return [
            "Recommender System", "Classifier", "Embedding / Vector Search",
            "Reinforcement Learning System", "Other Custom",
        ]
    elif ai_type == "Anomaly Detection / Fraud Detection":
        return [
            "Clustering / Anomaly Detection", "Classifier", "Regression",
            "Other Custom",
        ]
    elif ai_type in ["Large Language Model (LLM)", "Generative AI (e.g., Image/Audio Generation)"]:
        return [
            "LLM (Generic)", "LLM (Custom/Fine-tuned)", "Multimodal Model",
            "Transformer", "Other Custom",
        ]
    elif ai_type == "RAG / AI Search":
        return [
            "RAG Application", "Embedding / Vector Search",
            "LLM (Generic)", "LLM (Custom/Fine-tuned)", "Other Custom",
        ]
    elif ai_type == "Multimodal AI":
        return [
            "Multimodal Model", "LLM (Generic)", "LLM (Custom/Fine-tuned)",
            "CNN / Computer Vision", "Transformer", "Other Custom",
        ]
    elif ai_type == "Agentic AI (e.g., Autonomous Agents)":
        return [
            "Agentic Workflow / Autonomous Agent", "Multi-Agent System",
            "MCP / Tool-Integrated Assistant", "LLM (Generic)",
            "LLM (Custom/Fine-tuned)", "Other Custom",
        ]
    return MODEL_TYPE_OPTIONS


def _adversarial_type_options():
    """Return the relevant adversarial test type options for the current AI architecture."""
    opts = ["None", "Data Poisoning", "Model Evasion", "Model Inversion", "Membership Inference"]
    if _state_is_llm_like():
        opts += ["Prompt Injection", "Jailbreak", "Tool Misuse"]
    return opts


def _adversarial_tool_options():
    """Return the relevant adversarial tool options for the current AI architecture."""
    # Traditional ML-focused tools always available
    opts = ["None", "CleverHans", "IBM ART", "Microsoft Counterfit", "Custom Scripts"]
    if _state_is_llm_like():
        # LLM-specific tools added only if LLM-like
        opts = ["None", "CleverHans", "IBM ART", "Microsoft Counterfit",
                "Garak", "PyRIT", "promptfoo", "Custom Scripts"]
    return opts


def _clean_multiselect_answer(key, valid_options):
    """Remove any saved answers that are no longer in valid_options."""
    current = st.session_state.get(key, [])
    if not isinstance(current, list):
        return
    cleaned = [v for v in current if v in valid_options]
    if cleaned != current:
        st.session_state[key] = cleaned


def _outputs_options_for_arch():
    """Filter the model output options to those that make sense for the architecture.
    Hides options that don't apply (e.g. Image / Audio for non-generative).

    Always includes anything the user has already picked, so we never silently
    drop existing answers; _clean_multiselect_answer handles the trim if needed.
    """
    base = ["Text", "Labels", "Recommendations", "Decisions/scores", "Embeddings"]
    if _state_is_llm_like():
        base += ["Code", "API/tool calls"]
    if is_generative_selection():
        base += ["Image", "Audio/Video"]
    if _state_has_tools_or_actions() or is_agentic_selection() or is_mcp_selection():
        base += ["API/tool calls", "Files/documents", "Database writes"]
    if not _state_is_llm_like() and not is_generative_selection():
        # Traditional ML rarely emits Image/Audio/Code — keep list lean
        base = [o for o in base if o not in {"Image", "Audio/Video"}]
    # Dedupe while preserving order
    seen, ordered = set(), []
    for o in base:
        if o not in seen:
            seen.add(o); ordered.append(o)
    # Always include items the user has already saved
    for o in st.session_state.get("outputs", []) or []:
        if o not in seen:
            ordered.append(o); seen.add(o)
    return ordered


def _output_destinations_options_for_arch():
    """Filter output-destination options based on what the model can actually emit.
    e.g. 'Code executor' only matters if outputs include Code or API/tool calls.

    Note: option labels here MUST stay in sync with the strings rules_engine.py
    looks for (Database / External APIs / Files / Storage etc.). Audited
    April 2026 — added 'External APIs' and 'Files / Storage' so the
    'unsafe_output_persistence' rule (rules_engine.py L1875) is reachable.
    """
    out = set(st.session_state.get("outputs", []) or [])
    base = ["None of the above"]
    # UI rendering targets
    if any(o in out for o in ("Text", "Labels", "Recommendations", "Decisions/scores")) or not out:
        base += ["HTML/UI", "Browser/DOM", "Email/chat message"]
    # Code/tool call exec surfaces
    if any(o in out for o in ("Code", "API/tool calls")) or _state_has_tools_or_actions():
        base += ["Code executor", "Shell / OS", "Downstream API call", "External APIs"]
    # Data writes
    if "Database writes" in out or _state_has_tools_or_actions():
        base += ["Database", "Files / Storage"]
    if not out:
        # Before the user picks outputs, show everything so they can choose
        base = [
            "HTML/UI", "Browser/DOM", "Code executor",
            "Database", "Files / Storage", "Shell / OS",
            "Downstream API call", "External APIs",
            "Email/chat message", "None of the above",
        ]
    # Dedupe
    seen, ordered = set(), []
    for o in base:
        if o not in seen:
            seen.add(o); ordered.append(o)
    for o in st.session_state.get("output_destinations", []) or []:
        if o not in seen:
            ordered.append(o); seen.add(o)
    return ordered


def is_generative_selection():
    """True if the architecture produces generative media (image/audio/text gen)."""
    return st.session_state.get("ai_type") in (
        "Generative AI (e.g., Image/Audio Generation)",
        "Multimodal AI",
        "Large Language Model (LLM)",
    )


def normalize_conditional_defaults():
    """Keep conditional defaults aligned with the currently selected architecture."""
    agentic = is_agentic_selection()
    mcp = is_mcp_selection()
    rag = is_rag_selection()
    multimodal = is_multimodal_selection()
    llm_like = is_llm_like_selection()
    fine_tuned = is_fine_tuned_selection()

    agentic_keys = [
        "agentic_autonomous", "agentic_tool_access", "agentic_logging",
        "agentic_hitl", "agentic_sensitive_data", "agentic_malicious_input_detection",
        "agentic_memory", "agentic_memory_controls", "agentic_identity_scoped",
        "agentic_code_execution", "agentic_code_sandbox", "agentic_supply_chain_controls",
        "agentic_kill_switch", "agentic_multi_agent", "agentic_inter_agent_auth",
        "agentic_plan_inspection",
        # cross-step agentic controls
        "agent_action_rate_limit", "agent_per_run_budget", "agent_execution_isolation",
        "agent_scope_declared", "agent_tool_output_sanitization", "agent_destructive_action_gate",
        "agent_data_write_access", "agent_exfil_controls",
    ]
    for key in agentic_keys:
        if agentic:
            if st.session_state.get(key) not in YN_OPTIONS:
                st.session_state[key] = "No"
        else:
            st.session_state[key] = "Not Applicable"

    mcp_yn_keys = [
        "mcp_third_party_servers", "mcp_remote_servers", "mcp_tool_schema_integrity",
        "mcp_tool_output_sanitization", "mcp_authz", "mcp_human_approval",
        "mcp_server_isolation",
    ]
    # MCP step is visible when the user selected MCP *or* Agentic AI
    # (agentic deployments commonly use MCP tool-servers).
    mcp_step_visible = mcp or is_agentic_selection()
    if mcp:
        if st.session_state.get("mcp_usage") not in YN_OPTIONS:
            st.session_state["mcp_usage"] = "Yes"
        for key in mcp_yn_keys:
            if st.session_state.get(key) not in YN_OPTIONS:
                st.session_state[key] = "No"
    elif mcp_step_visible:
        # MCP step shown because of Agentic AI selection — user hasn't opted
        # into MCP yet, so default mcp_usage to "No" (not "Not Applicable")
        # so the radio widget doesn't crash.  Sub-keys stay N/A until "Yes".
        if st.session_state.get("mcp_usage") not in YN_OPTIONS:
            st.session_state["mcp_usage"] = "No"
        for key in mcp_yn_keys:
            if st.session_state.get(key) not in YN_OPTIONS:
                st.session_state[key] = "Not Applicable"
    else:
        st.session_state["mcp_usage"] = "Not Applicable"
        for key in mcp_yn_keys:
            st.session_state[key] = "Not Applicable"

    rag_control_keys = [
        "retrieval_access_control", "retrieval_content_filtering",
        "vector_db_isolation", "embedding_model_provenance", "embedding_inversion_controls",
    ]
    for key in rag_control_keys:
        if rag:
            if st.session_state.get(key) not in CONTROL_OPTIONS:
                st.session_state[key] = "No"
        else:
            st.session_state[key] = "Not Applicable"

    for key in ["fine_tune_data_review", "fine_tune_base_model_trust"]:
        if fine_tuned:
            if st.session_state.get(key) not in YN_OPTIONS:
                st.session_state[key] = "No"
        else:
            st.session_state[key] = "Not Applicable"

    if llm_like:
        for key in ["system_prompt_secrets", "system_prompt_protection", "hallucination_controls"]:
            if st.session_state.get(key) not in YN_OPTIONS:
                st.session_state[key] = "No"
    else:
        for key in ["system_prompt_secrets", "system_prompt_protection", "hallucination_controls"]:
            st.session_state[key] = "Not Applicable"

    # Multimodal step only for explicitly multimodal or generative architectures.
    multimodal_step_visible = multimodal or is_generative_selection()
    if multimodal_step_visible:
        for key in ("multimodal_injection_testing", "vision_injection_testing",
                    "audio_injection_testing", "document_pdf_injection",
                    "deepfake_detection"):
            if st.session_state.get(key) not in YN_OPTIONS:
                st.session_state[key] = "No"
    else:
        for key in ("multimodal_injection_testing", "vision_injection_testing",
                    "audio_injection_testing", "document_pdf_injection",
                    "deepfake_detection"):
            st.session_state[key] = "Not Applicable"

    # C2PA, output watermarking, and watermark robustness only apply to
    # generative architectures (LLM, image/audio gen, multimodal).
    if is_generative_selection():
        if st.session_state.get("c2pa_provenance") not in YN_OPTIONS:
            st.session_state["c2pa_provenance"] = "No"
        if st.session_state.get("output_watermarking") not in YN_OPTIONS:
            st.session_state["output_watermarking"] = "No"
        if st.session_state.get("output_watermarking") == "Yes":
            if st.session_state.get("watermark_robustness") not in YN_OPTIONS:
                st.session_state["watermark_robustness"] = "No"
        else:
            st.session_state["watermark_robustness"] = "Not Applicable"
    else:
        st.session_state["c2pa_provenance"]      = "Not Applicable"
        st.session_state["output_watermarking"]  = "Not Applicable"
        st.session_state["watermark_robustness"] = "Not Applicable"

    # Training-data IP review: ask only for generative / LLM-like
    if is_generative_selection() or llm_like:
        if st.session_state.get("training_data_ip_review") not in YN_OPTIONS:
            st.session_state["training_data_ip_review"] = "No"
    else:
        st.session_state["training_data_ip_review"] = "Not Applicable"

    # Model collapse: only if user-influenced retraining or synthetic data
    user_inf = st.session_state.get("user_influence") == "Yes"
    has_synth = "Synthetic" in (st.session_state.get("training_data") or [])
    if user_inf or has_synth:
        if st.session_state.get("model_collapse_monitoring") not in YN_OPTIONS:
            st.session_state["model_collapse_monitoring"] = "No"
    else:
        st.session_state["model_collapse_monitoring"] = "Not Applicable"

    # Fine-tune sub-questions
    if fine_tuned:
        if st.session_state.get("lora_adapter_validation") not in YN_OPTIONS:
            st.session_state["lora_adapter_validation"] = "No"
    else:
        st.session_state["lora_adapter_validation"] = "Not Applicable"

    # Alignment regression: applies to fine-tuned models OR systems with RLHF feedback
    if fine_tuned or st.session_state.get("rl_feedback") == "Yes":
        if st.session_state.get("alignment_regression_testing") not in YN_OPTIONS:
            st.session_state["alignment_regression_testing"] = "No"
    else:
        st.session_state["alignment_regression_testing"] = "Not Applicable"

    # Jailbreak transferability: LLM-like systems that have the Fine-Tune step
    # (Agentic AI doesn't get the Fine-Tune step, so set N/A for them too).
    if llm_like and not agentic:
        if st.session_state.get("jailbreak_transfer_testing") not in YN_OPTIONS:
            st.session_state["jailbreak_transfer_testing"] = "No"
    else:
        st.session_state["jailbreak_transfer_testing"] = "Not Applicable"

    # KV-cache isolation: only if LLM-like and shared cloud infra
    cloud_infra = st.session_state.get("infra") in (
        "AWS", "GCP", "Azure", "SaaS / vendor-hosted", "Hybrid / multi-cloud"
    )
    if llm_like and cloud_infra:
        if st.session_state.get("kv_cache_isolation") not in YN_OPTIONS:
            st.session_state["kv_cache_isolation"] = "No"
    else:
        st.session_state["kv_cache_isolation"] = "Not Applicable"

    # Agentic 2026 sub-questions
    if agentic:
        if st.session_state.get("agent_goal_drift_monitoring") not in YN_OPTIONS:
            st.session_state["agent_goal_drift_monitoring"] = "No"
        if st.session_state.get("agent_credential_acquisition") not in YN_OPTIONS:
            st.session_state["agent_credential_acquisition"] = "No"
        if st.session_state.get("agentic_multi_agent") == "Yes":
            for k in ("agent_collusion_controls", "agent_identity_verification"):
                if st.session_state.get(k) not in YN_OPTIONS:
                    st.session_state[k] = "No"
        else:
            st.session_state["agent_collusion_controls"] = "Not Applicable"
            st.session_state["agent_identity_verification"] = "Not Applicable"
        if st.session_state.get("agentic_hitl") == "Yes":
            if st.session_state.get("agent_hitl_bypass_detection") not in YN_OPTIONS:
                st.session_state["agent_hitl_bypass_detection"] = "No"
        else:
            st.session_state["agent_hitl_bypass_detection"] = "Not Applicable"
    else:
        for k in ("agent_goal_drift_monitoring", "agent_credential_acquisition",
                  "agent_collusion_controls", "agent_identity_verification",
                  "agent_hitl_bypass_detection"):
            st.session_state[k] = "Not Applicable"

    # Reinforcement Learning specific controls
    is_rl = st.session_state.get("model_type") == "Reinforcement Learning System"
    rl_keys = ["rl_reward_hacking_tested", "rl_policy_drift_monitoring", "rl_safe_rl_constraints"]
    for k in rl_keys:
        if is_rl:
            if st.session_state.get(k) not in YN_OPTIONS:
                st.session_state[k] = "No"
        else:
            st.session_state[k] = "Not Applicable"

    # Edge AI / IoT specific controls
    is_edge = st.session_state.get("model_type") == "Edge AI / IoT Model"
    edge_keys = ["edge_ota_update_security", "edge_physical_adversarial", "edge_model_encryption"]
    for k in edge_keys:
        if is_edge:
            if st.session_state.get(k) not in YN_OPTIONS:
                st.session_state[k] = "No"
        else:
            st.session_state[k] = "Not Applicable"

    # MCP 2026 sub-questions
    if mcp:
        for k in ("mcp_federation_trust", "mcp_tool_description_validation",
                  "mcp_prompt_in_result_filtering", "mcp_transport_security",
                  "mcp_shadow_discovery", "mcp_audit_telemetry"):
            if st.session_state.get(k) not in YN_OPTIONS:
                st.session_state[k] = "No"
    else:
        for k in ("mcp_federation_trust", "mcp_tool_description_validation",
                  "mcp_prompt_in_result_filtering", "mcp_transport_security",
                  "mcp_shadow_discovery", "mcp_audit_telemetry"):
            st.session_state[k] = "Not Applicable"

    # Governance 2026 fields are universally applicable; ensure valid Yes/No
    for k in ("ai_bom", "ai_incident_response_plan", "iso_42001_alignment",
              "third_party_audit_ready", "data_validation"):
        if st.session_state.get(k) not in YN_OPTIONS:
            st.session_state[k] = "No"
    eu_options = ["Unknown", "No — out of scope", "No — minimal/limited risk",
                  "Yes — high-risk (Annex III)", "Yes — prohibited (Art. 5)",
                  "GPAI / General-purpose AI"]
    if st.session_state.get("eu_ai_act_high_risk") not in eu_options:
        st.session_state["eu_ai_act_high_risk"] = "Unknown"

    for key in ["tenant_isolation", "rate_limiting", "abuse_monitoring",
                "ci_cd_security", "backup_rollback", "incident_response"]:
        if st.session_state.get(key) not in CONTROL_OPTIONS:
            st.session_state[key] = "No"

    # Adaptive: sandboxing only relevant if tools/plugins/agentic in play
    has_tools = (
        st.session_state.get("plugin_access") == "Yes"
        or st.session_state.get("auto_action") == "Yes"
        or agentic
    )
    if not has_tools:
        if st.session_state.get("sandboxing") not in ("Yes", "No"):
            st.session_state["sandboxing"] = "No"

    # Adaptive: clean adversarial test answers when they no longer apply
    _clean_multiselect_answer("adversarial_test_types", _adversarial_type_options())
    _clean_multiselect_answer("adversarial_test_tools", _adversarial_tool_options())

    # Adaptive: unlearning only relevant when PII/PHI is present
    ds = st.session_state.get("data_sensitivity", [])
    has_pii = any(d in ds for d in ["PII", "PHI", "Children/minors data", "Biometric data"])
    if not has_pii:
        st.session_state["unlearning_capability"] = "Not Applicable"
    elif st.session_state.get("unlearning_capability") == "Not Applicable":
        st.session_state["unlearning_capability"] = "No"

    # Adaptive: cost_monitoring / ai_gateway are LLM-specific
    if not llm_like:
        for key in ["cost_monitoring", "ai_gateway"]:
            if st.session_state.get(key) == "Not Applicable":
                st.session_state[key] = "No"

    # Adaptive: model_type — if it's no longer valid for the selected ai_type, reset it
    valid_model_types = _model_types_for_ai_type()
    if st.session_state.get("model_type") not in valid_model_types:
        st.session_state["model_type"] = valid_model_types[0]


def selected_inputs():
    # Collect only keys the rules engine consumes; persona is UI-only
    ui_only_keys = {"persona"}
    inputs = {
        key: st.session_state[key]
        for key in initial_values.keys()
        if key not in ui_only_keys
    }
    for key in [
        "regulated_domain",
        "model_supply_chain_controls",
        "training_data",
        "data_sensitivity",
        "data_governance_controls",
        "rag_data_sources",
        "outputs",
        "output_destinations",
        "users",
        "adversarial_test_types",
        "adversarial_test_tools",
        "llm_firewall",
    ]:
        if isinstance(inputs.get(key), list):
            # Bug 8: auto-remove "None" if other items are also selected
            values = list(inputs[key])
            if "None" in values and len(values) > 1:
                values = [v for v in values if v != "None"]
            inputs[key] = sorted(values)

    # NOTE: Pass "Not Applicable" answers through to the engine. The engine
    # treats NA as a deliberate user signal that the control isn't relevant
    # (CONTROL_SCORE["Not Applicable"] = 0, and miss()/missing() exclude NA),
    # so stripping them here would silently re-introduce risk inflation.
    return inputs


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# HTML rendering compatibility helper
# ---------------------------------------------------------------------------
def _html(raw: str) -> None:
    """Render raw HTML reliably across Streamlit versions.

    st.html()  was added in Streamlit 1.31 and renders HTML without any
    sanitisation.  Older versions need st.markdown(unsafe_allow_html=True)
    but that API was silently deprecated/restricted in 1.36+.
    We probe once per session which method works.
    """
    if hasattr(st, "html"):
        st.html(raw)
    else:
        st.markdown(raw, unsafe_allow_html=True)


# CSS — modern, clean, professional
# ---------------------------------------------------------------------------
def inject_css():
    # Load Material Symbols icon font so Streamlit's expander arrow etc. render
    # as an icon glyph instead of leaking the fallback text (e.g. keyboard_arrow_down)
    # into the expander summary and overlapping the finding title. (Bug 1)
    st.markdown(
        """
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
        <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200&display=swap" rel="stylesheet">
        <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200&display=swap" rel="stylesheet">
        """,
        unsafe_allow_html=True,
    )
    st.markdown(
        """
        <style>
        :root {
            --bg: #f0f4f8;
            --panel: #ffffff;
            --ink: #0b1220;
            --ink-2: #1e293b;
            --muted: #64748b;
            --subtle: #94a3b8;
            --line: #dde3ec;
            --line-strong: #c4cdd9;
            --accent: #2563eb;
            --accent-2: #1d4ed8;
            --accent-weak: #eff6ff;
            --good: #16a34a;
            --good-bg: #dcfce7;
            --warn: #d97706;
            --warn-bg: #fef9c3;
            --bad: #dc2626;
            --bad-bg: #fee2e2;
            --critical: #991b1b;
            --purple: #7c3aed;
            --purple-bg: #f5f3ff;
            --teal: #0d9488;
            --teal-bg: #f0fdfa;
            --sidebar-bg: #111827;
            --sidebar-ink: #e5e7eb;
            --sidebar-muted: #9ca3af;
            --shadow-sm: 0 1px 3px rgba(15, 23, 42, 0.08);
            --shadow-md: 0 4px 16px rgba(15, 23, 42, 0.10);
        }
        .stApp {
            background: var(--bg);
            color: var(--ink);
        }
        .stApp, .stApp p, .stApp span, .stApp div, .stApp label {
            font-family: "Inter", "Segoe UI", system-ui, -apple-system, sans-serif;
        }
        .block-container {
            max-width: 1280px;
            padding-top: 0.6rem;
            padding-bottom: 2rem;
            padding-left: 2rem;
            padding-right: 2rem;
        }
        /* Tighten Streamlit's default element spacing globally */
        [data-testid="stVerticalBlock"] { gap: 0.4rem !important; }
        section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] { gap: 0.25rem !important; }
        .element-container { margin-bottom: 0 !important; }
        /* Compact widget labels */
        [data-testid="stWidgetLabel"] > p { font-size: 0.8rem !important; line-height: 1.3 !important; margin-bottom: 2px !important; }
        [data-testid="stWidgetLabel"] { margin-bottom: 2px !important; }
        /* Selectbox — only increase height. Never override BaseWeb's internal
           padding or the value-container's overflow; doing so collapses the
           value area and causes the "– · · ·" placeholder dots to appear. */
        div[data-baseweb="select"] > div {
            min-height: 42px !important;
        }
        /* Radio buttons inline tighter */
        .stRadio > div[role="radiogroup"] { gap: 6px !important; margin-top: 2px !important; }
        /* Markdown text tighter */
        .stMarkdown p { margin-bottom: 4px !important; }
        /* --- Sidebar --- */
        section[data-testid="stSidebar"] {
            background: var(--sidebar-bg);
            border-right: 1px solid rgba(255,255,255,0.05);
        }
        section[data-testid="stSidebar"] * {
            color: var(--sidebar-ink);
        }
        section[data-testid="stSidebar"] .atm-sidebar-muted {
            color: var(--sidebar-muted) !important;
        }
        section[data-testid="stSidebar"] div[data-baseweb="select"] * ,
        section[data-testid="stSidebar"] input {
            color: #0b1220 !important;
        }
        section[data-testid="stSidebar"] .stButton > button {
            background: rgba(255,255,255,0.07);
            border: 1px solid rgba(255,255,255,0.22);
            color: #e2e8f0 !important;
            border-radius: 8px;
            font-weight: 600;
            padding: 0.5rem 0.9rem;
            box-shadow: none;
            width: 100%;
        }
        /* Ensure all child elements (p, div, span) inside sidebar buttons show light text */
        section[data-testid="stSidebar"] .stButton > button *,
        section[data-testid="stSidebar"] .stButton > button p,
        section[data-testid="stSidebar"] button[kind="secondary"],
        section[data-testid="stSidebar"] button[kind="secondary"] *,
        section[data-testid="stSidebar"] button[data-testid="baseButton-secondary"],
        section[data-testid="stSidebar"] button[data-testid="baseButton-secondary"] * {
            color: #e2e8f0 !important;
        }
        section[data-testid="stSidebar"] .stButton > button:hover {
            background: rgba(255,255,255,0.13);
            border-color: rgba(255,255,255,0.4);
        }
        .atm-brand {
            display: flex; align-items: center; gap: 10px;
            padding: 4px 2px 12px 2px;
            border-bottom: 1px solid rgba(255,255,255,0.08);
            margin-bottom: 10px;
        }
        .atm-brand-mark {
            width: 32px; height: 32px; border-radius: 8px;
            background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
            color: white;
            display: flex; align-items: center; justify-content: center;
            font-weight: 800; letter-spacing: 0.02em; font-size: 0.8rem;
            flex-shrink: 0;
        }
        .atm-brand-text {
            font-weight: 700; font-size: 0.9rem; color: #ffffff;
            line-height: 1.2;
        }
        .atm-brand-sub {
            font-size: 0.65rem; color: var(--sidebar-muted);
            letter-spacing: 0.05em; text-transform: uppercase;
            margin-top: 1px;
        }
        .atm-nav-label {
            font-size: 0.6rem; font-weight: 800;
            letter-spacing: 0.13em; text-transform: uppercase;
            color: #6b7280;
            margin: 12px 2px 5px 2px;
            padding-bottom: 4px;
            border-bottom: 1px solid rgba(255,255,255,0.06);
        }
        .atm-steplist {
            display: flex; flex-direction: column; gap: 1px;
            padding: 0;
        }
        .atm-step {
            display: flex; align-items: center; gap: 9px;
            padding: 5px 8px; border-radius: 7px;
            font-size: 0.79rem; color: var(--sidebar-ink);
            border: 1px solid transparent;
            transition: background 0.15s;
        }
        .atm-step-done {
            color: #6ee7b7;
        }
        .atm-step-done .atm-step-num {
            background: #059669; border-color: #059669; color: #fff;
        }
        .atm-step-current {
            background: rgba(37,99,235,0.22);
            border-color: rgba(59,130,246,0.4);
            color: #ffffff; font-weight: 700;
        }
        .atm-step-current .atm-step-num {
            background: #2563eb; border-color: #2563eb; color: #fff;
        }
        .atm-step-pending {
            color: #6b7280;
        }
        .atm-step-num {
            width: 20px; height: 20px; border-radius: 999px;
            background: transparent; color: #6b7280;
            border: 1px solid rgba(255,255,255,0.18);
            display: inline-flex; align-items: center; justify-content: center;
            font-size: 0.67rem; font-weight: 700; flex-shrink: 0;
        }
        .atm-divider {
            height: 1px; background: rgba(255,255,255,0.07);
            margin: 8px 0;
        }
        .atm-ref-link {
            display: inline; padding: 0;
            color: #93c5fd !important; text-decoration: none;
            font-size: 0.8rem; font-weight: 600;
        }
        .atm-ref-link:hover { color: #ffffff !important; text-decoration: underline; }

        /* --- Header --- */
        /* ── Slim single-line header ── */
        .atm-header {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 10px;
            padding: 9px 16px 8px 16px;
            margin-bottom: 8px;
            box-shadow: var(--shadow-sm);
        }
        .atm-header-row {
            display: flex; align-items: center; justify-content: space-between;
            gap: 10px; flex-wrap: wrap;
        }
        .atm-header-left {
            display: flex; align-items: center; gap: 7px; flex-wrap: wrap;
        }
        .atm-project-name {
            font-size: 0.92rem; font-weight: 700; color: var(--ink-2);
            margin-right: 4px;
        }
        .atm-step-badge {
            font-size: 0.72rem; font-weight: 700; color: var(--accent-2);
            white-space: nowrap;
        }
        .atm-meta-pill {
            background: #f1f5f9; border: 1px solid var(--line);
            color: var(--ink-2); border-radius: 999px;
            padding: 2px 9px; font-size: 0.72rem; font-weight: 600;
        }
        .atm-progress-bar {
            width: 100%; height: 4px; border-radius: 999px;
            background: #e2e8f0; overflow: hidden;
            margin-top: 7px;
        }
        .atm-progress-fill {
            height: 100%; background: linear-gradient(90deg, #3b82f6, #1d4ed8);
            border-radius: 999px; transition: width 300ms ease;
        }

        /* --- Step card --- */
        .atm-step-card {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 10px;
            padding: 14px 20px;
            box-shadow: var(--shadow-sm);
            margin-bottom: 10px;
        }
        .atm-step-head {
            margin-bottom: 8px;
            padding-bottom: 7px;
            border-bottom: 2px solid var(--line);
            display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap;
        }
        .atm-step-title {
            font-size: 1rem; font-weight: 800; color: var(--accent-2);
            margin: 0; letter-spacing: -0.01em;
        }
        .atm-step-sub {
            color: var(--muted); font-size: 0.78rem; line-height: 1.4;
            margin: 0;
        }

        /* ── Question group cards — smooth entrance + colour themes ── */
        @keyframes atm-slide-in {
            from { opacity: 0; transform: translateY(6px); }
            to   { opacity: 1; transform: translateY(0); }
        }
        .atm-q-group {
            border-radius: 8px;
            padding: 10px 14px;
            margin-bottom: 6px;
            border: 1px solid var(--line);
            border-top-width: 3px;
            animation: atm-slide-in 200ms ease both;
        }
        .atm-q-group-title {
            font-size: 0.63rem; font-weight: 800;
            letter-spacing: 0.09em; text-transform: uppercase;
            margin-bottom: 7px;
            padding-bottom: 4px;
            border-bottom-width: 1px; border-bottom-style: solid;
        }
        /* Per-category backgrounds — slightly more saturated so each category
           is clearly distinguishable while remaining easy on the eyes. */
        .atm-q-blue   { background:#dbeafe; border-top-color:#2563eb; }
        .atm-q-blue   .atm-q-group-title { color:#1d4ed8; border-bottom-color:#93c5fd; }
        .atm-q-violet { background:#ede9fe; border-top-color:#7c3aed; }
        .atm-q-violet .atm-q-group-title { color:#5b21b6; border-bottom-color:#c4b5fd; }
        .atm-q-rose   { background:#ffe4e6; border-top-color:#e11d48; }
        .atm-q-rose   .atm-q-group-title { color:#be123c; border-bottom-color:#fda4af; }
        .atm-q-orange { background:#ffedd5; border-top-color:#ea580c; }
        .atm-q-orange .atm-q-group-title { color:#c2410c; border-bottom-color:#fdba74; }
        .atm-q-green  { background:#dcfce7; border-top-color:#16a34a; }
        .atm-q-green  .atm-q-group-title { color:#15803d; border-bottom-color:#86efac; }
        .atm-q-indigo { background:#e0e7ff; border-top-color:#4f46e5; }
        .atm-q-indigo .atm-q-group-title { color:#3730a3; border-bottom-color:#a5b4fc; }
        .atm-q-amber  { background:#fef3c7; border-top-color:#d97706; }
        .atm-q-amber  .atm-q-group-title { color:#b45309; border-bottom-color:#fcd34d; }
        .atm-q-teal   { background:#ccfbf1; border-top-color:#0d9488; }
        .atm-q-teal   .atm-q-group-title { color:#0f766e; border-bottom-color:#5eead4; }
        .atm-q-slate  { background:#f1f5f9; border-top-color:#64748b; }
        .atm-q-slate  .atm-q-group-title { color:#475569; border-bottom-color:#cbd5e1; }

        /* Legacy pill class — kept for any residual references, not used by new renderer */
        .atm-q-group-title {
            font-size: 0.66rem; font-weight: 800;
            letter-spacing: 0.09em; text-transform: uppercase;
            margin: 4px 0 6px 0;
            padding: 5px 12px;
            border-radius: 6px;
            display: inline-block;
            border-left: 4px solid transparent;
        }
        .atm-q-blue-title   { color:#1d4ed8; background:#dbeafe; border-left-color:#2563eb; }
        .atm-q-violet-title { color:#5b21b6; background:#ede9fe; border-left-color:#7c3aed; }
        .atm-q-rose-title   { color:#be123c; background:#ffe4e6; border-left-color:#e11d48; }
        .atm-q-orange-title { color:#c2410c; background:#ffedd5; border-left-color:#ea580c; }
        .atm-q-green-title  { color:#15803d; background:#dcfce7; border-left-color:#16a34a; }
        .atm-q-indigo-title { color:#3730a3; background:#e0e7ff; border-left-color:#4f46e5; }
        .atm-q-amber-title  { color:#b45309; background:#fef3c7; border-left-color:#d97706; }
        .atm-q-teal-title   { color:#0f766e; background:#ccfbf1; border-left-color:#0d9488; }
        .atm-q-slate-title  { color:#475569; background:#f1f5f9; border-left-color:#64748b; }

        /* Sidebar info panels */
        .atm-sidebar-glossary {
            font-size: 0.71rem; color: var(--sidebar-muted);
            line-height: 1.55; margin: 4px 0 0 0;
        }
        .atm-sidebar-glossary strong {
            color: var(--sidebar-ink); display: block; margin-top: 4px;
        }
        .atm-sidebar-scoring {
            font-size: 0.71rem; color: #9ca3af;
            line-height: 1.6; margin: 4px 0 0 0;
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 8px; padding: 10px 12px;
        }
        .atm-sidebar-scoring strong { color: #e2e8f0 !important; }
        /* ── Sidebar framework group blocks ── */
        .atm-fw-group { margin: 12px 0 6px 0; }
        .atm-fw-section-head {
            display: flex; align-items: center; gap: 9px; margin-bottom: 5px;
        }
        .atm-fw-icon {
            width: 28px; height: 28px; border-radius: 50%;
            background: rgba(96,165,250,0.13); border: 1px solid rgba(96,165,250,0.25);
            display: inline-flex; align-items: center; justify-content: center;
            font-size: 0.82rem; flex-shrink: 0; line-height: 1;
        }
        .atm-fw-group-label {
            font-size: 0.84rem; font-weight: 800; letter-spacing: 0.01em;
            color: #f1f5f9; display: block;
        }
        .atm-fw-tagline {
            font-size: 0.71rem; color: #9ca3af; line-height: 1.55;
            margin-bottom: 7px; font-weight: 400;
        }
        /* Card wrapper for OWASP sub-links */
        .atm-fw-card {
            background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px; padding: 8px 10px; margin: 3px 0 5px 0;
        }
        .atm-fw-links { display: flex; flex-direction: column; gap: 5px; }
        .atm-fw-link-item { font-size: 0.71rem; color: #9ca3af; line-height: 1.5; }
        .atm-fw-link-item a { color: #93c5fd !important; text-decoration: none; font-weight: 700; }
        .atm-fw-link-item a:hover { color: #ffffff !important; text-decoration: underline; }

        /* ── Question-group section header (full-width coloured band) ── */
        .atm-q-section {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 14px 8px 16px;
            border-radius: 8px 8px 0 0;
            border-left: 5px solid transparent;
            border-bottom: 1px solid rgba(0,0,0,0.08);
            margin-top: 14px;
            margin-bottom: 0;
        }
        .atm-q-section-label {
            font-size: 0.72rem;
            font-weight: 800;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }
        /* Per-category colour variants */
        .atm-q-blue-section   { background:#dbeafe; border-left-color:#2563eb; }
        .atm-q-blue-section   .atm-q-section-label { color:#1d4ed8; }
        .atm-q-violet-section { background:#ede9fe; border-left-color:#7c3aed; }
        .atm-q-violet-section .atm-q-section-label { color:#5b21b6; }
        .atm-q-rose-section   { background:#ffe4e6; border-left-color:#e11d48; }
        .atm-q-rose-section   .atm-q-section-label { color:#be123c; }
        .atm-q-orange-section { background:#ffedd5; border-left-color:#ea580c; }
        .atm-q-orange-section .atm-q-section-label { color:#c2410c; }
        .atm-q-green-section  { background:#dcfce7; border-left-color:#16a34a; }
        .atm-q-green-section  .atm-q-section-label { color:#15803d; }
        .atm-q-indigo-section { background:#e0e7ff; border-left-color:#4f46e5; }
        .atm-q-indigo-section .atm-q-section-label { color:#3730a3; }
        .atm-q-amber-section  { background:#fef3c7; border-left-color:#d97706; }
        .atm-q-amber-section  .atm-q-section-label { color:#b45309; }
        .atm-q-teal-section   { background:#ccfbf1; border-left-color:#0d9488; }
        .atm-q-teal-section   .atm-q-section-label { color:#0f766e; }
        .atm-q-slate-section  { background:#f1f5f9; border-left-color:#64748b; }
        .atm-q-slate-section  .atm-q-section-label { color:#475569; }
        /* Content area directly below a section header — white card, border, shadow */
        .atm-q-section + div,
        .atm-q-section ~ .element-container:not(:has(.atm-q-section)):not(:has(.atm-q-section-end)) {
            background: #ffffff;
        }
        /* Bottom separator between groups */
        .atm-q-section-end {
            height: 0;
            border: none;
            border-top: 1.5px solid var(--line);
            margin: 12px 0 4px 0;
        }

        /* Section divider inside step */
        .atm-section-divider {
            border: 0; border-top: 1px solid var(--line);
            margin: 8px 0 7px 0;
        }
        .atm-subhead {
            font-size: 0.63rem; font-weight: 800;
            letter-spacing: 0.09em; text-transform: uppercase;
            color: var(--accent-2);
            margin: 0 0 5px 0;
            padding: 2px 0 4px 0;
            border-bottom: 2px solid #bfdbfe;
        }

        /* Report hero */
        .atm-report-hero {
            background: linear-gradient(135deg, #1e40af 0%, #2563eb 60%, #3b82f6 100%);
            border-radius: 14px; padding: 28px 32px; margin-bottom: 16px; color: #fff;
        }
        .atm-report-hero .atm-card-eyebrow { color: #bfdbfe; border: 0; background: transparent; }
        .atm-report-hero h2 { color: #ffffff; margin: 6px 0 8px 0; font-size: 1.5rem; font-weight: 800; }
        .atm-report-hero p  { color: #dbeafe; font-size: 0.9rem; margin: 0; line-height: 1.55; }

        /* Uniform form element width — every field stretches to fill its column */
        .stSelectbox, .stMultiSelect, .stTextInput, .stTextArea { width: 100% !important; }
        .stRadio [data-testid="stWidgetLabel"] { min-height: 0; }
        /* Make radio options wrap cleanly in narrow columns */
        .stRadio > div[role="radiogroup"] { gap: 6px !important; flex-wrap: wrap; }
        /* Align label baseline across columns */
        .stRadio > label, .stCheckbox > label, .stSelectbox > label,
        .stMultiSelect > label, .stTextInput > label, .stTextArea > label {
            font-weight: 600; color: var(--ink-2); font-size: 0.87rem;
            min-height: 1.5rem; display: flex; align-items: center;
        }
        /* Uniform bottom spacing between form widgets so columns align */
        .element-container:has(.stSelectbox),
        .element-container:has(.stMultiSelect),
        .element-container:has(.stTextInput),
        .element-container:has(.stRadio) {
            margin-bottom: 4px !important;
        }

        /* Metric tiles — compact, modern, gradient hairline accent */
        div[data-testid="stMetric"] {
            background: linear-gradient(180deg, #ffffff 0%, #fafbfd 100%);
            border: 1px solid var(--line);
            border-radius: 10px;
            padding: 10px 12px;
            box-shadow: var(--shadow-sm);
            position: relative;
            overflow: hidden;
        }
        div[data-testid="stMetric"]::before {
            content: "";
            position: absolute; top: 0; left: 0; right: 0;
            height: 2px;
            background: linear-gradient(90deg, #3b82f6, #6366f1);
            opacity: 0.85;
        }
        div[data-testid="stMetricLabel"] {
            color: var(--muted); font-weight: 600; font-size: 0.74rem;
            letter-spacing: 0.04em; text-transform: uppercase;
        }
        div[data-testid="stMetricValue"] {
            color: var(--ink); font-weight: 800;
            font-size: 1.35rem !important; line-height: 1.15;
        }
        div[data-testid="stMetricDelta"] {
            font-size: 0.72rem !important;
        }

        /* Tabs inside report */
        div[data-testid="stTabs"] > div > div[role="tablist"] {
            gap: 2px;
            border-bottom: 1px solid var(--line);
        }
        div[data-testid="stTabs"] button[role="tab"] {
            background: transparent;
            border: 0;
            padding: 10px 14px;
            color: var(--muted);
            font-weight: 600;
        }
        div[data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
            color: var(--accent-2);
            border-bottom: 2px solid var(--accent);
        }
        div[data-testid="stTabs"] button p { font-size: 0.92rem; }

        /* Form inputs */
        .stTextInput input, .stTextArea textarea {
            border-radius: 8px;
            border: 1px solid var(--line-strong);
        }
        div[data-baseweb="select"] > div {
            border-radius: 8px;
            border-color: var(--line-strong);
        }
        .stRadio > label, .stCheckbox > label, .stSelectbox > label,
        .stMultiSelect > label, .stTextInput > label, .stTextArea > label {
            font-weight: 600; color: var(--ink-2); font-size: 0.88rem;
        }

        /* Buttons — Streamlit secondary type renders outline automatically;
           primary type renders filled. We just tune the sizing/radius. */
        .stButton > button {
            border-radius: 8px;
            padding: 0.6rem 1.15rem;
            font-weight: 600;
            box-shadow: none;
        }
        /* Make the nav "Generate" button a bit larger */
        [data-testid="stHorizontalBlock"] .stButton:last-child > button[kind="primary"] {
            font-size: 0.97rem;
            padding: 0.7rem 1.3rem;
        }

        /* --- Navigation row --- */
        .atm-nav-row {
            display: flex; justify-content: space-between; align-items: center;
            margin-top: 6px; gap: 12px; flex-wrap: wrap;
        }

        /* --- Findings --- */
        .atm-finding {
            border: 1px solid var(--line);
            border-radius: 10px;
            background: var(--panel);
            padding: 14px 16px;
            margin: 8px 0;
        }
        .atm-finding-critical { border-left: 4px solid var(--critical); }
        .atm-finding-high     { border-left: 4px solid var(--bad); }
        .atm-finding-medium   { border-left: 4px solid var(--warn); }
        .atm-finding-low      { border-left: 4px solid var(--good); }
        .atm-finding-row {
            display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
        }
        .atm-finding-id {
            font-family: "JetBrains Mono", monospace;
            font-size: 0.76rem; color: var(--muted);
            background: #f1f5f9; border: 1px solid var(--line);
            border-radius: 6px; padding: 2px 8px;
        }
        .atm-finding-title {
            font-size: 1rem; font-weight: 700; color: var(--ink);
            margin-top: 6px;
        }
        .atm-finding-reason {
            color: var(--ink-2); font-size: 0.92rem;
            margin: 6px 0; line-height: 1.5;
        }
        .atm-sev {
            font-size: 0.7rem; font-weight: 700;
            letter-spacing: 0.04em; text-transform: uppercase;
            padding: 3px 9px; border-radius: 999px;
            border: 1px solid;
            white-space: nowrap; flex-shrink: 0;
            display: inline-block;
        }
        .atm-sev-critical { color: #ffffff; background: var(--critical); border-color: var(--critical); }
        .atm-sev-high     { color: #ffffff; background: var(--bad); border-color: var(--bad); }
        .atm-sev-medium   { color: #ffffff; background: var(--warn); border-color: var(--warn); }
        .atm-sev-low      { color: #ffffff; background: var(--good); border-color: var(--good); }

        .atm-chain-tag {
            display: inline-block;
            font-size: 0.68rem; font-weight: 700;
            letter-spacing: 0.06em; text-transform: uppercase;
            color: var(--accent-2);
            background: var(--accent-weak);
            border: 1px solid #dbeafe;
            padding: 3px 8px; border-radius: 999px;
        }

        /* Report hero */
        .atm-report-hero {
            background: linear-gradient(135deg, #0b1220 0%, #1e293b 100%);
            color: #ffffff;
            border: 1px solid #0b1220;
            border-radius: 14px;
            padding: 24px 28px;
            margin-bottom: 18px;
            box-shadow: var(--shadow-md);
        }
        .atm-report-hero .atm-card-eyebrow {
            color: #93c5fd; letter-spacing: 0.1em;
            font-size: 0.72rem; font-weight: 700; text-transform: uppercase;
        }
        .atm-report-hero h2 {
            color: #ffffff;
            margin: 6px 0 6px 0; font-size: 1.5rem; font-weight: 700;
        }
        .atm-report-hero p {
            color: #cbd5e1; margin: 0; font-size: 0.95rem;
        }

        /* Cards */
        .atm-card {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 12px;
            padding: 16px 18px;
            margin-bottom: 12px;
            box-shadow: var(--shadow-sm);
        }
        .atm-card-eyebrow {
            display: inline-block;
            color: var(--accent-2);
            font-size: 0.68rem; font-weight: 700;
            letter-spacing: 0.1em; text-transform: uppercase;
            background: var(--accent-weak); border: 1px solid #bfdbfe;
            border-radius: 99px; padding: 2px 10px;
            margin-bottom: 8px;
        }
        .atm-card-title {
            font-size: 1.1rem; font-weight: 800; color: var(--ink);
            margin: 0 0 4px 0; letter-spacing: -0.01em;
        }
        .atm-card-subtitle { color: var(--muted); font-size: 0.88rem; line-height: 1.5; }

        /* Empty state */
        .atm-empty {
            background: var(--panel);
            border: 1px dashed var(--line-strong);
            border-radius: 12px;
            padding: 24px;
            text-align: center;
            color: var(--muted);
        }

        /* Expanders */
        div[data-testid="stExpander"] > details {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 10px;
            box-shadow: var(--shadow-sm);
        }
        div[data-testid="stExpander"] > details > summary {
            padding: 12px 14px; font-weight: 600; color: var(--ink-2);
        }

        /* Tables */
        div[data-testid="stDataFrame"] {
            border-radius: 10px;
            border: 1px solid var(--line);
            overflow: hidden;
        }

        /* -------------------------------------------------------------
           Expander icon nuke + CSS triangle (Bug 1 / image: we saw the
           literal text "keyboard_double_arrow_down" overlapping the title).
           We do NOT rely on Material Symbols font loading. Instead we
           completely hide whatever icon span Streamlit puts first and
           render a pure-CSS triangle via a ::before on the summary.
           ------------------------------------------------------------- */
        div[data-testid="stExpander"] details summary {
            list-style: none;
            position: relative;
            padding-left: 30px !important;
        }
        div[data-testid="stExpander"] details summary::-webkit-details-marker,
        div[data-testid="stExpander"] details summary::marker {
            display: none !important;
            content: "" !important;
        }
        /* Nuke every direct-child element of the summary that is an icon
           holder — streamlit has shipped this as <span>, <div>, <i>, <svg>
           and as a material-symbols span. Zero out layout size + colour so
           any fallback text can't leak through. */
        div[data-testid="stExpander"] details > summary > span:first-child,
        div[data-testid="stExpander"] details > summary > div:first-child > span:first-child,
        div[data-testid="stExpander"] details > summary span.material-symbols-outlined,
        div[data-testid="stExpander"] details > summary span.material-symbols-rounded,
        div[data-testid="stExpander"] details > summary span.material-icons,
        div[data-testid="stExpander"] details > summary > i:first-child,
        div[data-testid="stExpander"] details > summary > svg:first-child {
            font-size: 0 !important;
            color: transparent !important;
            width: 0 !important;
            max-width: 0 !important;
            height: 0 !important;
            line-height: 0 !important;
            overflow: hidden !important;
            display: inline-block !important;
            visibility: hidden !important;
        }
        /* Custom triangle indicator, positioned in the padded gap */
        div[data-testid="stExpander"] details summary::before {
            content: "▸";
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            font-family: "Inter", sans-serif;
            font-size: 11px;
            font-weight: 700;
            color: #64748b;
            transition: transform 120ms ease;
        }
        div[data-testid="stExpander"] details[open] summary::before {
            content: "▾";
        }

        /* Expander summary wraps properly (fix overlap in Priority findings) */
        div[data-testid="stExpander"] > details > summary {
            white-space: normal !important;
            word-break: break-word;
            line-height: 1.45;
            padding: 14px 16px !important;
        }
        div[data-testid="stExpander"] > details > summary p {
            margin: 0;
            white-space: normal !important;
            word-break: break-word;
        }

        /* Framework-labelled pills (MITRE, OWASP LLM/ML/ASI/MCP) */
        .atm-frame-pill {
            display: inline-flex; align-items: center; gap: 6px;
            background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 999px;
            padding: 3px 10px; font-size: 0.74rem; font-weight: 600;
            color: #1d4ed8; margin: 2px 0;
        }
        .atm-frame-pill .atm-frame-label {
            background: #1d4ed8; color: #ffffff;
            border-radius: 4px; padding: 1px 6px; font-size: 0.62rem;
            letter-spacing: 0.04em; font-weight: 700;
        }
        .atm-frame-pill-ml { background: #f0fdf4; border-color: #bbf7d0; color: #166534; }
        .atm-frame-pill-ml .atm-frame-label { background: #166534; }
        .atm-frame-pill-asi { background: #fdf2f8; border-color: #fbcfe8; color: #9d174d; }
        .atm-frame-pill-asi .atm-frame-label { background: #9d174d; }
        .atm-frame-pill-mcp { background: #fef3c7; border-color: #fde68a; color: #92400e; }
        .atm-frame-pill-mcp .atm-frame-label { background: #92400e; }
        .atm-frame-pill-mitre { background: #ecfeff; border-color: #a5f3fc; color: #0e7490; }
        .atm-frame-pill-mitre .atm-frame-label { background: #0e7490; }

        /* Persona selector card */
        .atm-persona-card {
            background: linear-gradient(135deg, #eff6ff 0%, #ffffff 60%);
            border: 1px solid #dbeafe; border-radius: 12px;
            padding: 14px 18px; margin-bottom: 16px;
        }
        .atm-persona-card .atm-card-eyebrow { color: var(--accent-2); }
        /* Legacy .atm-persona-active pill (used by step headers) */
        .atm-persona-active {
            font-size: 0.88rem; font-weight: 500;
            padding: 10px 14px; border-radius: 10px;
            letter-spacing: 0; text-transform: none;
            margin-top: 10px; line-height: 1.55;
            border: 1px solid transparent;
        }
        .atm-persona-active strong { font-weight: 700; }
        .atm-persona-active em { font-style: italic; }
        .atm-persona-active-dev {
            background: #eef2ff; color: #1e1b4b;
            border-color: #c7d2fe; border-left: 4px solid #6366f1;
        }
        .atm-persona-active-sec {
            background: #ecfeff; color: #0c4a6e;
            border-color: #a5f3fc; border-left: 4px solid #0891b2;
        }
        .atm-glossary {
            background: #f8fafc;
            border: 1px dashed var(--line-strong);
            border-radius: 10px;
            padding: 12px 16px;
            font-size: 0.86rem; color: var(--ink-2);
            margin: 10px 0 14px 0; line-height: 1.55;
        }
        .atm-glossary strong { color: var(--ink); }

        /* Reduce whitespace between header and first step card (Bug 5, 14) */
        .atm-header { margin-bottom: 10px !important; margin-top: 6px; }
        .atm-step-card { margin-top: 0 !important; }
        /* Bug 14: give the whole page a bit of top breathing room so the
           "AI SECURITY DESIGN REVIEW" badge isn't clipped at the very top. */
        .block-container { padding-top: 1.4rem !important; }
        header[data-testid="stHeader"] { background: transparent; }

        /* Hide Streamlit top-right toolbar chrome (keyboard shortcut hint, etc.).
           Use display:none — visibility:hidden leaves the element in the DOM,
           so the browser still shows its title tooltip ("keyb..." for
           "Keyboard shortcuts") on mouse-over. display:none removes it. */
        [data-testid="stToolbarActions"] { display: none !important; }
        header[data-testid="stHeader"] button[kind="header"] { display: none !important; }
        /* Belt-and-braces: kill any element whose tooltip would otherwise
           leak the truncated "keyb..." text. */
        [title^="Keyboard"], [aria-label^="Keyboard"] { display: none !important; }

        /* PDF download button — colorful gradient, prominent */
        [data-testid="stDownloadButton"] > button {
            background: linear-gradient(135deg, #1e40af 0%, #6d28d9 100%) !important;
            color: #ffffff !important;
            border: none !important;
            border-radius: 10px !important;
            padding: 13px 28px !important;
            font-size: 0.97rem !important;
            font-weight: 600 !important;
            letter-spacing: 0.02em !important;
            box-shadow: 0 4px 18px rgba(109, 40, 217, 0.32) !important;
            transition: filter 0.15s ease, box-shadow 0.15s ease !important;
        }
        [data-testid="stDownloadButton"] > button:hover {
            filter: brightness(1.1) !important;
            box-shadow: 0 6px 22px rgba(109, 40, 217, 0.44) !important;
        }
        [data-testid="stDownloadButton"] > button:active {
            filter: brightness(0.95) !important;
        }

        /* Streamlit leaves empty element-containers that add vertical gap */
        .element-container:has(> .stMarkdown > div[data-testid="stMarkdownContainer"]:empty) {
            display: none;
        }
        /* Bug 5: hide element-containers whose markdown only contains an
           opening / closing wrapper div (no real content). */
        .element-container:has(> .stMarkdown > div[data-testid="stMarkdownContainer"] > div.atm-step-card:empty) {
            display: none !important;
            margin: 0 !important;
            padding: 0 !important;
            height: 0 !important;
        }

        /* Bug 13: Streamlit auto-anchors headings with a chain-link icon.
           Hide it in the header / hero cards so "New Assessment" doesn't
           show a hanging anchor link next to it. */
        .atm-header h1 a,
        .atm-report-hero h2 a,
        .atm-card-title a,
        .atm-step-title a,
        [data-testid="stHeaderActionElements"],
        a.anchor-link,
        .stMarkdown a[href^="#"] svg,
        h1 a[href^="#"], h2 a[href^="#"], h3 a[href^="#"] {
            display: none !important;
        }
        .atm-header h1 { pointer-events: none; }
        .atm-header h1 * { pointer-events: auto; }

        /* Bug 11: compliance bar-chart tint — used in Priority tab */
        .atm-compliance-bar text { fill: #0b1220 !important; }

        /* Chain-card evidence block — per-answer list explaining
           why THIS attack chain fired for THIS user. */
        .atm-chain-evidence {
            background: #fff7ed;
            border: 1px solid #fed7aa;
            border-left: 4px solid #ea580c;
            border-radius: 8px;
            padding: 10px 14px;
            margin: 8px 0 10px 0;
        }
        .atm-chain-evidence-title {
            font-weight: 600;
            color: #7c2d12;
            margin-bottom: 4px;
        }
        .atm-chain-evidence ul {
            margin: 0;
            padding-left: 18px;
            color: #9a3412;
            font-size: 0.9rem;
        }

        /* Compliance regime pills — Frameworks tab */
        .atm-compliance-regimes {
            background: linear-gradient(135deg, #f0fdf4 0%, #ecfdf5 100%);
            border: 1px solid #86efac;
            border-left: 4px solid #16a34a;
            border-radius: 10px;
            padding: 12px 16px;
            margin: 8px 0 14px 0;
            color: #064e3b;
            font-size: 0.92rem;
            line-height: 1.9;
        }
        .atm-pill {
            display: inline-block;
            background: linear-gradient(135deg, #1e40af, #2563eb);
            color: #fff;
            border-radius: 999px;
            padding: 3px 12px;
            margin: 2px 3px;
            font-size: 0.78rem;
            font-weight: 700;
            letter-spacing: 0.03em;
            box-shadow: 0 1px 3px rgba(37,99,235,0.3);
        }
        .atm-compliance-banner { margin-top: 12px; }
        .atm-compliance-regimes-gap {
            margin-top: 6px; color: #7c2d12; font-size: 0.88rem;
        }
        .atm-compliance-regimes-hint {
            margin-top: 4px; color: #15803d; font-size: 0.8rem; font-style: italic;
        }

        /* Bug 9: behavior question grid — aligned two-column cards */
        .atm-qgrid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px 24px;
            margin-top: 4px;
        }
        @media (max-width: 720px) {
            .atm-qgrid { grid-template-columns: 1fr; }
        }

        /* Bug 2/3: persona card polish + security test-plan card */
        .atm-test-plan {
            background: #ecfeff;
            border: 1px solid #a5f3fc;
            border-left: 4px solid #0891b2;
            border-radius: 8px;
            padding: 10px 14px;
            margin-top: 10px;
            font-size: 0.88rem;
            color: #0c4a6e;
            line-height: 1.55;
        }
        .atm-test-plan strong { color: #0b1220; }
        .atm-test-plan ul { margin: 6px 0 0 18px; padding: 0; }
        .atm-test-plan li { margin: 2px 0; }

        /* Bug R2.6: developer-persona "in short + what to do in code" card */
        .atm-dev-short {
            background: #eef2ff;
            border: 1px solid #c7d2fe;
            border-left: 4px solid #6366f1;
            border-radius: 8px;
            padding: 10px 14px;
            margin-top: 10px;
            font-size: 0.9rem;
            color: #1e1b4b;
            line-height: 1.55;
        }
        .atm-dev-short strong { color: #0b1220; }

        /* Modern framework table — subtle row hover */
        tr.atm-fw-row {
            transition: background-color 140ms ease, box-shadow 140ms ease;
        }
        tr.atm-fw-row:hover {
            background: #f1f5fb !important;
            box-shadow: inset 0 0 0 9999px rgba(59,130,246,0.04);
        }

        /* Final tightening — squeeze a few more pixels out so users scroll less */
        .block-container { padding-top: 0.55rem !important; padding-bottom: 0.6rem !important; }
        .atm-step-card { padding: 8px 14px !important; margin-bottom: 6px !important; }
        .atm-step-head { margin-bottom: 4px !important; padding-bottom: 3px !important; }
        .atm-q-group { padding: 7px 12px 6px 12px !important; margin-bottom: 5px !important; border-top-width: 4px !important; }
        .atm-q-group-title { margin-bottom: 3px !important; padding-bottom: 2px !important; font-size: 0.62rem !important; }
        /* Tighter divider inside step body */
        .atm-section-divider { margin: 4px 0 3px 0 !important; }
        /* Tighter help-text under widgets */
        [data-baseweb="tooltip"] + p, .stTooltipIcon + p { font-size: 0.72rem !important; }
        /* Less air around radio rows when stacked horizontally */
        .stRadio > div[role="radiogroup"] > label { margin-right: 8px !important; }
        /* Wider report tab buttons to use horizontal real estate */
        div[data-testid="stTabs"] button[role="tab"] { padding: 8px 14px !important; }
        /* Make multiselect chips tighter */
        div[data-baseweb="tag"] {
            margin: 1px 2px !important;
            padding: 1px 6px !important;
            font-size: 0.72rem !important;
        }
        /* Tighter form widget vertical rhythm so a step fits in one screen */
        .stSelectbox, .stMultiSelect, .stTextInput, .stTextArea, .stRadio { margin-bottom: 4px !important; }
        /* Compact widget label */
        .stRadio > label, .stCheckbox > label, .stSelectbox > label,
        .stMultiSelect > label, .stTextInput > label, .stTextArea > label {
            font-size: 0.8rem !important;
            min-height: 1.3rem !important;
            margin-bottom: 2px !important;
            padding-bottom: 0 !important;
        }
        /* Input controls — give selected text & dropdowns enough height so
           values like 'Development' / 'Moderate' / 'Traditional ML' aren't
           visually clipped at the bottom. */
        div[data-baseweb="select"] > div { min-height: 40px !important; }
        div[data-baseweb="input"]  > div { min-height: 38px !important; }
        div[data-baseweb="select"] [data-baseweb="value"],
        div[data-baseweb="select"] [class*="ValueContainer"] {
            line-height: 1.4 !important;
            padding-top: 6px !important;
            padding-bottom: 6px !important;
        }
        /* Reduce gap between adjacent vertical blocks (Streamlit default is 1rem) */
        div[data-testid="stVerticalBlock"] > div[data-testid="stVerticalBlockBorderWrapper"],
        div[data-testid="stVerticalBlock"] > div { gap: 0.3rem !important; }
        /* Squeeze the helper-text under widgets (small grey caption) */
        small, [data-testid="stCaptionContainer"] { font-size: 0.7rem !important; line-height: 1.3 !important; }

        /* ── Navigation buttons: replace Streamlit's red 'primary' with our blue ── */
        .stButton > button {
            border-radius: 8px !important;
            font-weight: 600 !important;
            padding: 8px 16px !important;
            transition: background-color 140ms ease, transform 80ms ease;
        }
        .stButton > button[kind="primary"],
        .stButton > button[data-testid="baseButton-primary"] {
            background: linear-gradient(180deg, #2563eb 0%, #1d4ed8 100%) !important;
            color: #ffffff !important;
            border: 1px solid #1d4ed8 !important;
            box-shadow: 0 1px 2px rgba(29,78,216,0.20) !important;
        }
        .stButton > button[kind="primary"]:hover,
        .stButton > button[data-testid="baseButton-primary"]:hover {
            background: linear-gradient(180deg, #1d4ed8 0%, #1e40af 100%) !important;
            transform: translateY(-1px);
        }
        .stButton > button[kind="secondary"],
        .stButton > button[data-testid="baseButton-secondary"] {
            background: #ffffff !important;
            color: #1d4ed8 !important;
            border: 1px solid #c7d2fe !important;
        }
        .stButton > button[kind="secondary"]:hover,
        .stButton > button[data-testid="baseButton-secondary"]:hover {
            background: #eef2ff !important;
            border-color: #93c5fd !important;
        }
        /* Sidebar reset button — override global secondary style */
        section[data-testid="stSidebar"] .stButton > button,
        section[data-testid="stSidebar"] .stButton > button[data-testid="baseButton-secondary"],
        section[data-testid="stSidebar"] .stButton > button[data-testid="baseButton-secondary"] p,
        section[data-testid="stSidebar"] .stButton > button[data-testid="baseButton-secondary"] * {
            color: #f1f5f9 !important;
            background: rgba(255,255,255,0.08) !important;
            border-color: rgba(255,255,255,0.25) !important;
        }
        section[data-testid="stSidebar"] .stButton > button:hover,
        section[data-testid="stSidebar"] .stButton > button[data-testid="baseButton-secondary"]:hover {
            background: rgba(255,255,255,0.16) !important;
            border-color: rgba(255,255,255,0.45) !important;
        }
        .stButton > button:disabled {
            background: #f1f5f9 !important;
            color: #94a3b8 !important;
            border: 1px solid #e2e8f0 !important;
            box-shadow: none !important;
        }
        /* Active state (selected radio) — replace red dot with our blue. */
        .stRadio input[type="radio"]:checked + div { color: #1d4ed8 !important; }
        .stRadio [data-baseweb="radio"] [aria-checked="true"] > div:first-child,
        .stRadio [data-baseweb="radio"] div[role="radio"][aria-checked="true"] {
            border-color: #2563eb !important;
            background: #2563eb !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Wizard steps
# ---------------------------------------------------------------------------
def build_steps():
    """Return an ordered list of step dicts. The list reacts to architecture
    picks, so extra steps appear only when needed."""
    steps = [
        {"key": "project",    "label": "Project",         "icon": "1",
         "subtitle": "Tell us about the system's stage, impact, and technology."},
        {"key": "data",       "label": "Data & Behavior", "icon": "2",
         "subtitle": "What data does the model touch and how does it behave?"},
    ]
    if is_rag_selection():
        steps.append({"key": "rag",    "label": "RAG & Memory", "icon": "R",
                      "subtitle": "Retrieval sources, authorization, and embedding controls."})
    steps.extend([
        {"key": "deployment", "label": "Deployment",   "icon": "3",
         "subtitle": "Exposure, identity, isolation, cost, and resilience."},
        {"key": "security",   "label": "Security",     "icon": "4",
         "subtitle": "I/O, secrets, logging, and adversarial testing."},
        {"key": "governance", "label": "Governance",   "icon": "5",
         "subtitle": "Documentation, traceability, and explainability."},
    ])
    if is_llm_like_selection():
        steps.append({"key": "llm",        "label": "LLM / GenAI",  "icon": "L",
                      "subtitle": "Prompt strategy, guardrails, hallucination and system-prompt protection."})
    # Multimodal & Media step only for systems explicitly dealing with multimodal
    # inputs or generative media output. Plain LLM, RAG, and Agentic AI
    # architectures don't inherently need vision/audio/deepfake questions.
    if is_multimodal_selection() or is_generative_selection():
        steps.append({"key": "multimodal", "label": "Multimodal & Media", "icon": "M",
                      "subtitle": "Vision, audio, document, deepfake, and content-provenance defenses."})
    # Fine-tune step covers fine-tune-specific *and* model-customization risks
    # (LoRA, RLHF reward hacking, alignment regression, jailbreak transfer).
    # Shown for LLM-like architectures but NOT Agentic AI — agentic risks are
    # covered in the dedicated Agentic step; jailbreak-transfer is less central
    # to agentic threat models than tool-chaining and goal-hijacking.
    if is_fine_tuned_selection() or (is_llm_like_selection() and not is_agentic_selection()):
        steps.append({"key": "finetune",   "label": "Fine-Tune & Alignment",    "icon": "F",
                      "subtitle": "Fine-tune data review, base-model provenance, alignment, jailbreak transfer."})
    if is_agentic_selection():
        steps.append({"key": "agentic",    "label": "Agentic",      "icon": "A",
                      "subtitle": "Autonomy, memory, code execution, multi-agent, and oversight."})
    if is_mcp_selection() or is_agentic_selection():
        steps.append({"key": "mcp",        "label": "MCP",          "icon": "C",
                      "subtitle": "Tool-server trust, schemas, authorization, and isolation."})
    if is_trad_ml_selection():
        steps.append({"key": "classical_ml", "label": "Classical ML",  "icon": "X",
                      "subtitle": "Adversarial robustness, interpretability, membership inference, and drift."})
    return steps


def clamp_step():
    steps = build_steps()
    current = int(st.session_state.get("step_index") or 0)
    st.session_state.step_index = max(0, min(current, len(steps) - 1))


def goto_step(delta):
    steps = build_steps()
    current = int(st.session_state.get("step_index") or 0)
    st.session_state.step_index = max(0, min(current + int(delta), len(steps) - 1))


def jump_to_step(index):
    steps = build_steps()
    st.session_state.step_index = max(0, min(int(index), len(steps) - 1))


# ---------------------------------------------------------------------------
# Sidebar (lean: brand, step indicator, references)
# ---------------------------------------------------------------------------
def render_sidebar(steps, current_idx):
    with st.sidebar:
        _html(
            """
            <div class="atm-brand">
                <div class="atm-brand-mark">AI</div>
                <div>
                    <div class="atm-brand-text">Threat Model</div>
                    <div class="atm-brand-sub">AI / ML threat modelling</div>
                </div>
            </div>
            """
        )

        _html("<div class='atm-nav-label'>Progress</div>")
        step_html_parts = ["<div class='atm-steplist'>"]
        for i, step in enumerate(steps):
            if i < current_idx:
                cls = "atm-step atm-step-done"
                indicator = "&#10003;"
            elif i == current_idx:
                cls = "atm-step atm-step-current"
                indicator = str(i + 1)
            else:
                cls = "atm-step atm-step-pending"
                indicator = str(i + 1)
            step_html_parts.append(
                f"<div class='{cls}'>"
                f"<div class='atm-step-num'>{indicator}</div>"
                f"<div>{step['label']}</div>"
                f"</div>"
            )
        step_html_parts.append("</div>")
        _html("".join(step_html_parts))

        _html("<div class='atm-divider'></div>")

        if st.session_state.report_requested:
            if st.button("← Back to questions", key="btn_back_to_questions",
                         type="primary", use_container_width=True):
                st.session_state.report_requested = False
                st.rerun()
        else:
            if st.button("↺ Reset all answers", key="btn_reset",
                         use_container_width=True):
                for k, v in initial_values.items():
                    st.session_state[k] = v
                st.session_state.step_index = 0
                st.session_state.report_requested = False
                st.session_state["_autosave_loaded"] = True  # don't re-load stale file
                _autosave_clear()
                st.rerun()

        _html("<div class='atm-divider'></div>")
        _html("<div class='atm-nav-label'>Frameworks</div>")
        _html(
            """
            <div class="atm-sidebar-glossary">

              <div class="atm-fw-group">
                <div class="atm-fw-section-head">
                  <div class="atm-fw-icon">✈</div>
                  <span class="atm-fw-group-label">OWASP</span>
                </div>
                <div class="atm-fw-tagline">Open Worldwide Application Security Project — community-maintained ranked lists of the most critical security risks, updated yearly. Used globally by security teams to prioritise what to fix first.</div>
                <div class="atm-fw-card">
                  <div class="atm-fw-links">
                    <div class="atm-fw-link-item">🎯 <a href="https://genai.owasp.org/llm-top-10/" target="_blank">LLM Top 10</a> — Prompt injection, data leakage, supply-chain, unbounded consumption &amp; large-language-model apps.</div>
                    <div class="atm-fw-link-item">🔬 <a href="https://owasp.org/www-project-machine-learning-security-top-10/" target="_blank">ML Top 10</a> — Classical ML risks: data poisoning, model inversion, membership inference, adversarial evasion.</div>
                    <div class="atm-fw-link-item">🤖 <a href="https://genai.owasp.org/initiatives/agentic-security-initiative/" target="_blank">Agentic (AS) Top 10</a> — Autonomous agent threats: goal hijacking, tool misuse, memory poisoning, cascading failures.</div>
                    <div class="atm-fw-link-item">🔌 <a href="https://genai.owasp.org/initiatives/mcp-security/" target="_blank">MCP Top 10</a> — Context Protocol risks: tool poisoning, scope creep, shadow servers, context injection.</div>
                  </div>
                </div>
              </div>

              <div class="atm-fw-group">
                <div class="atm-fw-section-head">
                  <div class="atm-fw-icon">🛡</div>
                  <span class="atm-fw-group-label">MITRE ATLAS</span>
                </div>
                <div class="atm-fw-tagline">Adversarial Threat Landscape for Artificial-Intelligence Systems — a knowledge base of real-world AI/ML attack techniques used by nation-state actors and red teams. Each technique has an <strong style="color:#e2e8f0;">AML.T</strong> code.</div>
                <div class="atm-fw-links">
                  <div class="atm-fw-link-item"><a href="https://atlas.mitre.org/" target="_blank">atlas.mitre.org ↗</a> — Browse tactics, techniques &amp; case studies.</div>
                  <div class="atm-fw-link-item"><a href="https://atlas.mitre.org/matrices/ATLAS" target="_blank">ATLAS Matrix ↗</a> — Full technique catalogue mapped to ML attack lifecycle.</div>
                </div>
              </div>

              <div class="atm-fw-group">
                <div class="atm-fw-section-head">
                  <div class="atm-fw-icon">⚙</div>
                  <span class="atm-fw-group-label">NIST AI RMF</span>
                </div>
                <div class="atm-fw-tagline">US NIST AI Risk Management Framework — a voluntary, flexible framework to identify, assess and manage AI-related risks across four functions.</div>
                <div class="atm-fw-links">
                  <div class="atm-fw-link-item"><a href="https://www.nist.gov/itl/ai-risk-management-framework" target="_blank">NIST AI RMF ↗</a> — <strong style="color:#bfdbfe;">Govern · Map · Measure · Manage</strong></div>
                  <div class="atm-fw-link-item"><a href="https://airc.nist.gov/Docs/1" target="_blank">AI RMF Playbook ↗</a> — Suggested actions for each function.</div>
                </div>
              </div>

              <div class="atm-fw-group">
                <div class="atm-fw-section-head">
                  <div class="atm-fw-icon">⚖</div>
                  <span class="atm-fw-group-label">EU AI Act</span>
                </div>
                <div class="atm-fw-tagline">EU regulation imposing obligations on high-risk AI systems: risk management, human oversight, transparency, accuracy, and post-market monitoring. Fines up to €35 M.</div>
              </div>

            </div>
            """
        )

        _html("<div class='atm-divider'></div>")
        _html("<div class='atm-nav-label'>How scoring works</div>")
        _html(
            """
            <div class="atm-sidebar-scoring">
              <strong style="color:var(--sidebar-ink);display:block;margin-bottom:4px;">Risk formula</strong>
              Risk = (Likelihood × Impact) + Control Gap<br><br>
              <strong style="color:var(--sidebar-ink);">Control gap scores</strong><br>
              Yes = 0 &nbsp;·&nbsp; Partial = 1<br>
              Unknown = 2 &nbsp;·&nbsp; No = 3<br><br>
              <strong style="color:var(--sidebar-ink);">Hidden / N-A questions</strong><br>
              Questions hidden because they don't apply to your architecture are set to <em>Not Applicable</em> (score = 2, same as Unknown). No false findings are generated.
            </div>
            """
        )
        _html(
            "<p class='atm-sidebar-muted' style='font-size:0.72rem;margin-top:10px;'>"
            "Output is a design-time indicator, not a formal audit."
            "</p>"
        )


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
def render_header(steps, current_idx):
    total = len(steps)
    _raw_name = (st.session_state.project_name or "").strip()
    project = _raw_name if _raw_name else None   # None = don't show name until entered
    stage = st.session_state.project_stage
    impact = st.session_state.business_impact
    arch = st.session_state.ai_type
    pct = 0 if total <= 1 else int(round((current_idx / (total - 1)) * 100)) if not st.session_state.report_requested else 100
    step_label = "Report ready" if st.session_state.report_requested else steps[current_idx]["label"]
    step_num = f"Step {current_idx + 1}/{total}" if not st.session_state.report_requested else "✓ Complete"
    name_html = f'<span class="atm-project-name">{project}</span>' if project else ""
    _html(f"""
        <div class="atm-header">
            <div class="atm-header-row">
                <div class="atm-header-left">
                    {name_html}
                    <span class="atm-meta-pill">{arch}</span>
                    <span class="atm-meta-pill">{stage}</span>
                    <span class="atm-meta-pill">{impact} impact</span>
                </div>
                <span class="atm-step-badge">{step_num} · {step_label}</span>
            </div>
            <div class="atm-progress-bar"><div class="atm-progress-fill" style="width:{pct}%"></div></div>
        </div>
    """)


# ---------------------------------------------------------------------------
# Step header card
# ---------------------------------------------------------------------------
def step_head(step, current_idx, total):
    pct = int((current_idx / max(total - 1, 1)) * 100)
    _html(f"""
        <div class="atm-step-head">
            <div class="atm-step-title">{step['label']}</div>
            <div class="atm-step-sub">— {step['subtitle']}</div>
        </div>
    """)


def subhead(label):
    _html(f"<div class='atm-subhead'>{label}</div>")


def section_divider():
    _html("<hr class='atm-section-divider' />")


_Q_COLOR_COUNTER = {"n": 0}
# Step-to-color mapping so each step has a consistent palette
_STEP_COLORS = {
    "project":    "blue",
    "data":       "violet",
    "rag":        "indigo",
    "deployment": "orange",
    "security":   "rose",
    "governance": "green",
    "llm":        "indigo",
    "multimodal": "indigo",
    "finetune":   "violet",
    "agentic":    "amber",
    "mcp":        "teal",
    "review":     "slate",
}
_CURRENT_STEP_COLOR = {"c": "slate"}   # set per-render by render_wizard

# Cycled palette so each question category gets its own header colour.
_Q_GROUP_PALETTE = ["blue", "violet", "rose", "orange", "green", "indigo", "amber", "teal"]
_Q_GROUP_COUNTER = {"i": 0}


def reset_q_group_palette():
    """Reset the per-step colour cycle. Called by render_wizard before each step."""
    _Q_GROUP_COUNTER["i"] = 0


def _agentic_step_banner(section_name: str):
    """No-op — orientation banners removed."""
    pass


def q_group_start(title, color=None):
    """Open a themed question-group.  Renders a full-width coloured section
    header div; the content widgets follow directly in the Streamlit flow.
    Visual card separation is achieved purely through CSS."""
    if color is None:
        i = _Q_GROUP_COUNTER["i"]
        color = _Q_GROUP_PALETTE[i % len(_Q_GROUP_PALETTE)]
        _Q_GROUP_COUNTER["i"] = i + 1
    _html(
        f"<div class='atm-q-section atm-q-{color}-section'>"
        f"<span class='atm-q-section-label'>{title}</span>"
        f"</div>"
    )


def q_group_end():
    """Render a thin bottom-border separator between question groups."""
    _html("<div class='atm-q-section-end'></div>")


@contextmanager
def q_row():
    """Render two question categories side-by-side. Use as:
        with q_row() as (left, right):
            with left:  q_group_start(...); ...; q_group_end()
            with right: q_group_start(...); ...; q_group_end()
    """
    cols = st.columns(2, gap="small")
    yield cols


# ---------------------------------------------------------------------------
# Persona helpers — developer-friendly language + glossary hints
# ---------------------------------------------------------------------------
def is_developer_mode():
    return st.session_state.get("persona", "Security Engineer") in (
        "Developer / ML Engineer",
        "Developer",
        "ML Engineer",
    )


def h(security_help, dev_help=None):
    """Return the help string appropriate for the active persona.
    Falls back to security_help if dev_help is not provided."""
    if is_developer_mode() and dev_help:
        return dev_help
    return security_help


def q(security_label, dev_label=None):
    """Return the WIDGET LABEL appropriate for the active persona.

    Security persona gets the formal, standards-oriented label (e.g.
    'Adversarial-input detection for agent'). Developer persona gets a
    conversational, plain-English version (e.g. 'Can you catch someone
    trying to jailbreak the agent?'). Bug 2.
    """
    if is_developer_mode() and dev_label:
        return dev_label
    return security_label


def glossary_hint(items):
    """Glossary hints are now surfaced in the sidebar under 'Frameworks'.
    This function is intentionally a no-op to keep the main content clean."""
    return


# ---------------------------------------------------------------------------
# Framework-labelled pill rendering
# ---------------------------------------------------------------------------
_FRAMEWORK_FOR_CODE = {
    "LLM": ("OWASP LLM", "atm-frame-pill"),
    "ML":  ("OWASP ML",  "atm-frame-pill atm-frame-pill-ml"),
    "ASI": ("OWASP Agentic", "atm-frame-pill atm-frame-pill-asi"),
    "MCP": ("OWASP MCP", "atm-frame-pill atm-frame-pill-mcp"),
    "TA":  ("MITRE ATLAS", "atm-frame-pill atm-frame-pill-mitre"),
}


def _framework_pill_html(token):
    """Render a token like 'LLM03: Supply Chain' or 'TA0010: Exfiltration'
    as a framework-labelled pill so users see which framework it belongs to."""
    token = (token or "").strip()
    if not token or token == "N/A":
        return ""
    if ":" in token:
        code, desc = token.split(":", 1)
        code, desc = code.strip(), desc.strip()
    else:
        code, desc = token, ""
    # Detect framework prefix
    prefix = None
    for key in ("LLM", "ML", "ASI", "MCP", "TA"):
        if code.startswith(key):
            prefix = key
            break
    label, css_cls = _FRAMEWORK_FOR_CODE.get(prefix, ("Framework", "atm-frame-pill"))
    suffix = f" — {desc}" if desc else ""
    return (
        f"<span class='{css_cls}'>"
        f"<span class='atm-frame-label'>{label}</span>"
        f"{code}{suffix}</span>"
    )


def render_owasp_pills(owasp_str):
    parts = [p.strip() for p in str(owasp_str or "").split("|")
             if p.strip() and p.strip() != "N/A"]
    return " ".join(_framework_pill_html(p) for p in parts)


# Human-readable names for MITRE ATLAS technique IDs
_MITRE_ATLAS_NAMES: dict[str, str] = {
    "AML.T0000": "Reconnaissance",
    "AML.T0010": "ML Model Access",
    "AML.T0018": "Backdoor ML Model",
    "AML.T0019": "Publish Poisoned Datasets",
    "AML.T0020": "Training Data Poisoning",
    "AML.T0022": "Exploit Public-Facing ML App",
    "AML.T0024": "Exfiltration via API",
    "AML.T0025": "Model Inversion",
    "AML.T0031": "Erode ML Model Integrity",
    "AML.T0034": "Cost Harvesting",
    "AML.T0040": "ML Model Inference",
    "AML.T0043": "Craft Adversarial Data",
    "AML.T0044": "Develop Capabilities",
    "AML.T0047": "Develop Advex",
    "AML.T0048": "Exfiltration via Cyber Intrusion",
    "AML.T0049": "Exfiltration via ML Inference",
    "AML.T0050": "Membership Inference",
    "AML.T0051": "Prompt Injection",
    "AML.T0052": "Unauthorized Agent Action",
    "AML.T0053": "Shadow Alignment",
    "AML.T0054": "Indirect Prompt Injection",
    "AML.T0055": "LLM Jailbreak",
    "AML.T0056": "System Prompt Extraction",
    "AML.T0058": "LLM Plugin Compromise",
    "AML.T0059": "Insecure Output Handling",
    "AML.T0060": "Excessive Agency",
    "AML.T0062": "LLM DoS",
    "AML.T0063": "Supply Chain Corruption",
    "AML.T0064": "Retrieval Manipulation",
}

def _mitre_label(mitre_str: str) -> str:
    """Return 'AML.T0051 — Prompt Injection' style label for a MITRE code."""
    import re
    m = re.match(r"(AML\.[A-Z]\d+)", str(mitre_str or "").strip())
    if not m:
        return str(mitre_str or "")
    code = m.group(1)
    name = _MITRE_ATLAS_NAMES.get(code, "")
    return f"{code} — {name}" if name else code


def render_mitre_pill(mitre_str: str) -> str:
    """Render MITRE badge with human-readable technique name."""
    raw = str(mitre_str or "").strip()
    if not raw or raw == "N/A":
        return ""
    # Handle pipe-separated values (graph chains)
    parts = [p.strip() for p in raw.split("|") if p.strip() and p.strip() != "N/A"]
    html_parts = []
    for part in parts[:2]:   # cap at 2 pills to avoid overflow
        label = _mitre_label(part)
        html_parts.append(
            f"<span style='font-size:0.67rem;font-weight:600;color:#1e40af;background:#dbeafe;"
            f"padding:2px 7px;border-radius:4px;margin-left:4px;white-space:nowrap;'>"
            f"ATLAS: {label}</span>"
        )
    return "".join(html_parts)


# ---------------------------------------------------------------------------
# Step renderers
# ---------------------------------------------------------------------------
def render_step_project():

    q_group_start(q("Project identity", "What are we threat-modelling?"))
    pi1, pi2, pi3 = st.columns(3)
    with pi1:
        st.text_input(
            q("Project name", "What's the project called?"), key="project_name",
            placeholder="e.g., Customer support copilot",
            help=h("A short name for this system; shown in the final report header.",
                   "Just a name so you can tell this threat model apart from the next one."),
        )
    with pi2:
        st.selectbox(
            q("Project stage", "How far along?"),
            PROJECT_STAGE_OPTIONS,
            key="project_stage",
            help=h("High-impact findings are escalated one severity level in Pilot / Production.",
                   "Prod gets stricter scoring than a hackathon prototype."),
        )
    with pi3:
        st.selectbox(
            q("Business impact", "If this breaks, how bad?"),
            BUSINESS_IMPACT_OPTIONS,
            key="business_impact",
            help=h("Drives severity escalation together with project stage.",
                   "We combine this with project stage to size the risk."),
        )
    # NOTE: Project description was removed — it was never consumed by the rules
    # engine. The metadata default ("description": "") still satisfies the report
    # template.
    q_group_end()

    # Architecture and Domain & supply-chain run side-by-side to save scroll.
    with q_row() as (_arch_col, _domain_col):
        with _arch_col:
            q_group_start(q("Architecture", "What does the stack look like?"))
            # Row 1 — AI type  ·  Model / app pattern
            _a1, _a2 = st.columns(2)
            with _a1:
                st.selectbox(
                    q("AI type", "What kind of AI is this?"),
                    AI_TYPE_OPTIONS,
                    key="ai_type",
                    help=h("Drives which architecture-specific steps appear (LLM, RAG, Agentic, MCP, etc.).",
                           "Picking GenAI/LLM/Agentic adds extra question pages later."),
                )
            with _a2:
                filtered_model_types = _model_types_for_ai_type()
                current_model_type = st.session_state.get("model_type", filtered_model_types[0])
                if current_model_type not in filtered_model_types:
                    st.session_state["model_type"] = filtered_model_types[0]
                st.selectbox(
                    q("Model / app pattern", "Pattern — classifier, RAG, agent, MCP app?"),
                    filtered_model_types,
                    key="model_type",
                    help=h("The architectural pattern (classifier, RAG app, agent, MCP tool-integrated, etc.).",
                           "The shape of the app under the hood."),
                )
            # Row 2 — Model source  ·  Updated regularly?
            _a3, _a4 = st.columns(2)
            with _a3:
                st.selectbox(
                    q("Model source", "Where did the model come from?"),
                    MODEL_SOURCE_OPTIONS,
                    key="model_source",
                    help=h("Choosing Fine-tuned adds a Fine-Tune step with provenance and dataset-review questions.",
                           "Pick 'Fine-tuned' if you retrained a base model on your data."),
                )
            with _a4:
                st.radio(
                    q("Model updated regularly?", "Do you push new model versions often?"),
                    YN_OPTIONS, horizontal=True, key="model_updates",
                    help=h("Regular retraining creates supply-chain and data-poisoning exposure if not reviewed.",
                           "If yes, we flag supply-chain and drift risks."),
                )
            q_group_end()

        with _domain_col:
            q_group_start(q("Domain &amp; supply-chain context", "Regulated domain + supply-chain controls"))
            st.multiselect(
                q("Regulated / high-impact domains", "Regulated industry?"),
                ["None", "Healthcare", "Financial services / payments", "Education",
                 "Employment / HR", "Legal", "Government / public sector",
                 "Critical infrastructure", "Children / minors", "Biometrics"],
                key="regulated_domain",
                help=h("Used to infer HIPAA / PCI / GDPR / EU AI Act obligations.",
                       "We use this to flag compliance gaps (HIPAA, PCI, GDPR, EU AI Act)."),
            )
            st.multiselect(
                q("Supply-chain controls in place", "Stopping malicious models / libs sneaking in?"),
                ["None", "Version pinning", "Checksum/signature verification", "SBOM / ML-BOM",
                 "License review", "Vulnerability scanning", "Model registry approvals",
                 "Reproducible training/builds"],
                key="model_supply_chain_controls",
                help=h("Controls that protect against OWASP LLM03 / ML06 supply-chain risks.",
                       "Pin versions, scan for CVEs, verify signatures — anything you've actually wired up."),
            )
            q_group_end()

    # Orientation cards removed — users found them distracting.
    # Coverage reference is available as a separate shareable document.


def render_step_data():
    _agentic_step_banner("Agent data access scope")
    q_group_start(q("Data sensitivity &amp; governance", "Your data: what is it, and how clean is it?"))
    c1, c2 = st.columns(2)
    with c1:
        st.multiselect(
            q("Training data types", "What kind of data did you train / fine-tune on?"),
            ["Public", "Internal", "PII", "PHI", "Synthetic", "Customer data",
             "Source code", "Logs / telemetry", "Licensed third-party data", "Unknown"],
            key="training_data",
            help=h("Sources of data used for training / fine-tuning. Drives privacy and supply-chain rules.",
                   "What kind of data did you train on? Public scrape, customer tickets, synthetic, etc."),
        )
        st.multiselect(
            q("Sensitive data processed at runtime",
              "What sensitive info can the model see or produce?"),
            ["Public", "Internal", "Confidential", "PII", "PHI", "Financial/payment data",
             "Credentials/secrets", "Children/minors data", "Biometric data",
             "Source code/IP", "Safety-critical data"],
            key="data_sensitivity",
            help=h("Sensitivity classes in inputs/outputs. Triggers encryption, DLP, and compliance rules.",
                   "What kind of sensitive info might the model see or produce at runtime?"),
        )
    with c2:
        st.multiselect(
            q("Data governance controls in place",
              "How do you manage training data?"),
            ["None", "Data minimization", "Provenance tracking", "Data classification/labeling",
             "DLP/redaction", "Retention/deletion policy", "Dataset access reviews",
             "Consent/legal basis review"],
            key="data_governance_controls",
            help=h("Controls that reduce data-related risk across GDPR/CCPA/HIPAA.",
                   "How do you keep your training data tidy? Labeling, retention limits, who can access it, etc."),
        )
        # Drives rules for data poisoning, RLHF manipulation, fine-tune
        # poisoning, online-learning feedback poisoning. Previously phantom-
        # read by the engine — now wired to a real input.
        st.radio(q("Automated training-data validation",
                   "Do you validate training data with schema / outlier / integrity checks?"),
                 YN_OPTIONS, horizontal=True, key="data_validation",
                 help=h("Schema checks, statistical outlier detection, dataset integrity hashes before training (drives 5+ rules: data poisoning, RLHF, fine-tune, online-learning).",
                        "Do you actually run automated checks on training/fine-tune data before it hits training?"))
        _data_sens_now = st.session_state.get("data_sensitivity", [])
        _has_pii_phi = any(d in _data_sens_now for d in ["PII", "PHI", "Children/minors data", "Biometric data"])
        if _has_pii_phi:
            st.radio(q("Unlearning / erasure capability for PII/PHI?",
                       "Can you delete one person's data from the model on request?"),
                     YN_OPTIONS, horizontal=True, key="unlearning_capability",
                     help=h("Right-to-be-forgotten compliance for GDPR/CCPA.",
                            "Can you actually remove a specific person's data from the model if they ask?"))
        else:
            st.session_state["unlearning_capability"] = "Not Applicable"
        # Generative-only: training-data IP/copyright review
        if is_generative_selection() or is_llm_like_selection():
            st.radio(q("Training-data IP / copyright review",
                       "Have you assessed risk of memorized copyrighted content in outputs?"),
                     YN_OPTIONS, horizontal=True, key="training_data_ip_review",
                     help=h("Risk of memorized copyrighted text/code surfacing in outputs (NYT/Getty 2025-26 litigation; EU AI Act Art. 28).",
                            "Could the model regurgitate copyrighted training data? Have you actually checked?"))
        else:
            st.session_state["training_data_ip_review"] = "Not Applicable"
    q_group_end()

    q_group_start(q("Outputs &amp; users", "Where the output goes, and who uses it"))
    c3, c4, c5 = st.columns(3)
    with c3:
        _out_opts = _outputs_options_for_arch()
        _clean_multiselect_answer("outputs", _out_opts)
        st.multiselect(
            q("Model outputs", "What does the model return?"),
            _out_opts,
            key="outputs",
            help=h("What the model produces. Drives downstream integrity and abuse rules.",
                   "What does the model spit out? Text, images, code, tool calls?"),
        )
    with c4:
        _dest_opts = _output_destinations_options_for_arch()
        _clean_multiselect_answer("output_destinations", _dest_opts)
        st.multiselect(
            q("Output consumed / rendered by", "Where does output land?"),
            _dest_opts,
            key="output_destinations",
            help=h("Used to assess improper output handling (HTML/JS injection, code-exec, SSRF).",
                   "Where does the output land? If it hits a shell, DB, or DOM, we flag XSS / SQLi / RCE risk."),
        )
    with c5:
        st.multiselect(
            q("Primary users", "Who actually uses this?"),
            ["Internal", "Employees", "Developers", "Customers", "Partners",
             "Anonymous", "Administrators", "Other systems/agents"],
            key="users",
            help=h("External/anonymous users raise exposure and escalate rate-limit/abuse rules.",
                   "Who actually uses this? Your own team, paying customers, or anonymous internet people?"),
        )
    q_group_end()

    q_group_start(q("Runtime behavior", "What the model can reach and do"))
    bc_left, bc_right = st.columns(2)
    with bc_left:
        st.radio(q("Uses external sources during inference?",
                   "Does the model call the web / outside APIs while answering?"),
                 YN_OPTIONS, horizontal=True, key="external_sources",
                 help=h("External lookups (web, third-party APIs) can inject untrusted content.",
                        "Does the model call the web or outside APIs while answering?"))
        st.radio(q("Direct user query to model?",
                   "Can a user send text straight to the model?"),
                 YN_OPTIONS, horizontal=True, key="direct_query",
                 help=h("Direct user prompts enable prompt injection if not validated.",
                        "Does user input go straight to the model, or is it heavily pre-processed?"))
        st.radio(q("Processes real-time inputs?",
                   "Is it online serving, or an offline batch job?"),
                 YN_OPTIONS, horizontal=True, key="real_time",
                 help=h("Real-time ingestion raises abuse / poisoning monitoring requirements.",
                        "Is it online serving, or offline batch?"))
        _has_real_time = st.session_state.get("real_time") == "Yes"
        _has_ext_users = _state_has_external_users()
        if _has_real_time or _has_ext_users:
            st.radio(q("Users influence training/retraining data?",
                       "Does user feedback feed back into retraining?"),
                     YN_OPTIONS, horizontal=True, key="user_influence",
                     help=h("User-contributed data can poison online-learning systems.",
                            "Does user feedback / content feed back into retraining?"))
        else:
            st.session_state["user_influence"] = "No"
    with bc_right:
        st.radio(q("Takes auto actions without review?",
                   "Can the model act without a human approving each step?"),
                 YN_OPTIONS, horizontal=True, key="auto_action",
                 help=h("Autonomous actions without HITL map to LLM06: Excessive Agency.",
                        "Can the model do things on its own — send email, run a tool — without a human clicking approve?"))
        st.radio(q("Model can access tools/plugins?",
                   "Can the model call functions / tools / plugins / APIs?"),
                 YN_OPTIONS, horizontal=True, key="plugin_access",
                 help=h("Tool access widens the attack surface (LLM06, MCP, ASI02).",
                        "Can the model call functions / tools / plugins / APIs?"))
        st.radio(q("Human override available?",
                   "If the model does something weird, can a human undo it?"),
                 YN_OPTIONS, horizontal=True, key="can_override",
                 help=h("Override paths reduce impact of incorrect model decisions.",
                        "If the model decides something weird, can a human reverse it?"))
        st.radio(q("Model can access external systems?",
                   "Can it reach databases / SaaS apps / other services?"),
                 YN_OPTIONS, horizontal=True, key="external_systems",
                 help=h("External systems imply outbound credentials and data egress paths.",
                        "Can it reach out to databases, SaaS apps, or other services in your stack?"))
    q_group_end()

    if is_agentic_selection():
        q_group_start(q("🤖 Agent data access scope",
                        "What can the agent read, modify, or exfiltrate?"), color="amber")
        da1, da2 = st.columns(2)
        with da1:
            st.radio(
                q("Agent write / delete access to external data stores",
                  "Can the agent modify or delete records in external databases, storage, or SaaS?"),
                YN_OPTIONS, horizontal=True, key="agent_data_write_access",
                help=h(
                    "Write/delete access turns a compromised or manipulated agent into a data-destruction or ransomware vector.",
                    "Can the agent write to or delete data in external databases, object stores, or SaaS systems?",
                ),
            )
        with da2:
            st.radio(
                q("Data exfiltration controls for agent",
                  "Are there controls to prevent the agent from leaking data to external endpoints?"),
                YN_OPTIONS, horizontal=True, key="agent_exfil_controls",
                help=h(
                    "Exfil controls (egress filtering, DLP, allow-list of outbound destinations) prevent an agent from leaking sensitive context.",
                    "Does anything stop the agent from sending data to an arbitrary external URL or API?",
                ),
            )
        q_group_end()


def render_step_rag():
    if is_developer_mode():
        # Bug 7: drop RAG/embedding basics — focus on the attack terms.
        glossary_hint([
            ("Embedding inversion", "Attack that reconstructs the original sensitive text from a vector embedding."),
            ("Indirect prompt injection", "Malicious instructions hidden inside retrieved documents; the model obeys them when they're pulled into context."),
            ("Cross-tenant retrieval", "Leak pattern where vector search returns chunks from another tenant / user — the main risk behind OWASP LLM08."),
        ])
    st.radio(q("Uses RAG, vector search, embeddings, retrieval, or long-term memory?",
               "Does the app look up docs and stuff them into the prompt before answering?"),
             YN_OPTIONS, horizontal=True, key="rag_usage",
             help=h("If yes, OWASP LLM08 (Vector & Embedding Weaknesses) applies.",
                    "Does the app look up documents and stuff them into the prompt before answering?"))

    if st.session_state.rag_usage == "Yes" or is_rag_selection():
        q_group_start(q("Sources", "What are you searching / retrieving?"))
        st.multiselect(
            q("Retrieval or memory data sources",
              "What are you indexing? (Wiki, public web, user uploads…)"),
            ["Internal docs", "Customer/user documents", "Public web",
             "Code repositories", "Tickets/chat/email", "Databases",
             "Third-party APIs", "Uploaded files", "Unknown"],
            key="rag_data_sources",
            help=h("Untrusted sources (web, uploads) introduce indirect prompt-injection paths.",
                   "What are you searching? Your wiki, public web, user uploads? That's where poisoned content could sneak in."),
        )
        q_group_end()

        q_group_start(q("Retrieval controls", "How retrieval is fenced off"))
        r1, r2, r3 = st.columns(3)
        with r1:
            st.radio(q("Retrieval access control",
                       "Does retrieval respect the user's doc permissions?"),
                     CONTROL_OPTIONS, key="retrieval_access_control",
                     help=h("Per-user permissions enforced on retrieved chunks (prevents cross-tenant leakage).",
                            "When the app searches docs, does it only see docs the current user is allowed to read?"))
        with r2:
            st.radio(q("Retrieved content filtering",
                       "Do you scan retrieved chunks for injection payloads before prompting?"),
                     CONTROL_OPTIONS, key="retrieval_content_filtering",
                     help=h("Inspects retrieved chunks for instruction-like / malicious content before prompt insertion.",
                            "Do you scan chunks for hidden 'ignore previous instructions' style junk before putting them in the prompt?"))
        with r3:
            st.radio(q("Vector DB isolation",
                       "Is each tenant in its own namespace / index?"),
                     CONTROL_OPTIONS, key="vector_db_isolation",
                     help=h("Tenancy separation for vector stores: namespaces, separate indexes, or per-tenant encryption keys.",
                            "Is each customer's vector data in its own namespace, or is it all one giant shared pool?"))
        q_group_end()

        q_group_start(q("Embedding model", "The embedding model itself"))
        r4, r5 = st.columns(2)
        with r4:
            st.radio(q("Embedding-model provenance reviewed",
                       "Do you actually trust where your embedding model came from?"),
                     CONTROL_OPTIONS,
                     key="embedding_model_provenance",
                     help=h("Checks source, license, and integrity of the embedding model.",
                            "Do you trust the thing that turns text into vectors? Where did it come from?"))
        with r5:
            st.radio(q("Embedding-inversion / leakage controls",
                       "Can someone reverse your vectors back into the original text?"),
                     CONTROL_OPTIONS,
                     key="embedding_inversion_controls",
                     help=h("Mitigations against reconstructing sensitive text from vectors.",
                            "Can an attacker work backwards from the vectors to recover the original sensitive text?"))
        q_group_end()


def render_step_deployment():
    _agentic_step_banner("Agent execution controls")
    q_group_start(q("Exposure &amp; access", "Where is it deployed and who can reach it?"))
    d1, d2, d3 = st.columns(3)
    with d1:
        st.selectbox(q("Infrastructure", "Where does it run?"), INFRA_OPTIONS,
                     key="infra",
                     help=h("Deployment environment; drives cloud-vs-on-prem-specific controls.",
                            "Where does it run? AWS, GCP, your office server, a laptop?"))
    with d2:
        st.selectbox(q("Exposure", "Who can reach the endpoint?"), EXPOSURE_OPTIONS,
                     key="exposure",
                     help=h("Public exposure triggers stricter rate-limit, WAF, and DoS-prevention rules.",
                            "Who can actually reach the endpoint?"))
    with d3:
        st.selectbox(q("Access control", "How do callers authenticate?"), ACCESS_CONTROL_OPTIONS,
                     key="access_control",
                     help=h("Auth model: None < Token < Role-based < Attribute/policy-based.",
                            "How do callers prove who they are? API token, SSO login, nothing?"))

    r1, r2, r3 = st.columns(3)
    with r1:
        st.radio(q("Rate limits / quotas", "Can a user hammer the API?"),
                 CONTROL_OPTIONS, horizontal=True, key="rate_limiting",
                 help=h("Prevents LLM10 unbounded consumption and basic DoS.",
                        "Can a user hammer the API as many times as they want?"))
    with r2:
        if _state_has_external_users() or _state_is_public_facing():
            st.radio(q("Tenant isolation", "Are tenants walled off?"),
                     CONTROL_OPTIONS, horizontal=True, key="tenant_isolation",
                     help=h("Prevents cross-tenant data leakage in shared models/indexes.",
                            "If customers share infra, are their data and sessions actually walled off?"))
        else:
            st.session_state["tenant_isolation"] = "Not Applicable"
    with r3:
        st.radio(q("Abuse monitoring", "Do you watch for misuse?"),
                 CONTROL_OPTIONS, horizontal=True, key="abuse_monitoring",
                 help=h("Detects prompt-injection, jailbreaks, scraping, brute force patterns.",
                        "Do you watch for misuse — weird prompts, suspicious patterns?"))
    q_group_end()

    q_group_start(q("Infrastructure hardening", "How locked-down is the infra around the model?"))
    o1, o2, o3 = st.columns(3)
    with o1:
        st.radio(q("WAF / API gateway", "Is there a firewall in front?"),
                 YN_OPTIONS, horizontal=True, key="waf",
                 help=h("Blocks malformed payloads and common web attacks at the edge.",
                        "Is there a firewall that drops obviously-malicious requests?"))
        st.radio(q("Network segmentation", "Model hosts on isolated networks?"),
                 YN_OPTIONS, horizontal=True, key="network_segmentation",
                 help=h("Limits blast radius if the model layer is compromised.",
                        "Are model hosts / vector DBs on their own isolated network segments?"))
    with o2:
        st.radio(q("CI/CD &amp; registry protected", "Can anyone push a model to prod?"),
                 CONTROL_OPTIONS, horizontal=True, key="ci_cd_security",
                 help=h("Protects against model-supply-chain attacks via pipelines and registries.",
                        "Is your CI/CD locked down, or can anyone push a model / notebook into prod?"))
        st.radio(q("Rollback / backup", "Can you revert a bad model fast?"),
                 CONTROL_OPTIONS, horizontal=True, key="backup_rollback",
                 help=h("Ability to revert a bad model version or poisoned data.",
                        "If a bad version ships, can you roll back to the previous model fast?"))
    with o3:
        st.radio(q("AI incident-response plan", "Is there a written 'who does what'?"),
                 CONTROL_OPTIONS, horizontal=True, key="incident_response",
                 help=h("IR playbook specifically covering AI incidents (jailbreak, poisoning, leakage).",
                        "If something goes wrong, is there a written plan?"))
        st.radio(q("Environment patched &amp; scanned", "Hosts patched and vuln-scanned regularly?"),
                 YN_OPTIONS, horizontal=True, key="env_patching_scanning",
                 help=h("Routine patching and vuln scanning of the hosting environment.",
                        "Are you keeping the OS, libs, and containers up to date?"))
    q_group_end()

    if is_agentic_selection():
        q_group_start(q("🤖 Agent execution controls",
                         "Blast-radius limits, per-run budgets, and infra isolation for autonomous agents"), color="amber")
        ag1, ag2, ag3 = st.columns(3)
        with ag1:
            st.radio(
                q("Per-action rate cap",
                  "Is there a max number of tool calls / actions the agent can make per minute or per run?"),
                YN_OPTIONS, horizontal=True, key="agent_action_rate_limit",
                help=h("Prevents runaway agents from spamming APIs or accumulating costs in a single run (ASI10).",
                       "If an agent loops or gets hijacked, can it call 10,000 APIs before you notice?"),
            )
        with ag2:
            st.radio(
                q("Per-run step / cost budget",
                  "Does each agent run have a hard ceiling on steps, tokens, or cost?"),
                YN_OPTIONS, horizontal=True, key="agent_per_run_budget",
                help=h("Hard cap per run (e.g., max 50 LLM calls, max $0.50) bounds the blast-radius of goal hijacking.",
                       "If someone hijacks the agent's goal, how much damage can it do before it hits a wall?"),
            )
        with ag3:
            st.radio(
                q("Agent runs in isolated environment",
                  "Does the agent execute in a dedicated, isolated environment (not shared prod)?"),
                YN_OPTIONS, horizontal=True, key="agent_execution_isolation",
                help=h("Isolates agent file system, network, and IAM from the broader production environment.",
                       "If the agent is compromised, can it pivot to your other prod services?"),
            )
        q_group_end()

    if _state_is_llm_like():
        q_group_start(q("Cost &amp; AI gateway", "Token cost controls + policy proxy"))
        g1, g2 = st.columns(2)
        with g1:
            st.radio(q("Token/compute cost monitoring &amp; budgets", "Can someone burn your GPU budget?"),
                     YN_OPTIONS, horizontal=True, key="cost_monitoring",
                     help=h("Mitigation for LLM10: Unbounded Consumption — per-user and per-feature caps.",
                            "Can a user accidentally burn through your entire OpenAI/GPU budget?"))
        with g2:
            st.radio(q("AI gateway / policy proxy in front of model", "Single chokepoint for LLM calls?"),
                     YN_OPTIONS, horizontal=True, key="ai_gateway",
                     help=h("Centralized policy, logging, quotas, and safety checks for model calls.",
                            "Is there a single chokepoint where LLM calls get logged, rate-limited, policy-checked?"))
        q_group_end()

        # Multi-tenant inference: KV-cache & batch-level side channels
        if st.session_state.get("infra") in (
            "AWS", "GCP", "Azure", "SaaS / vendor-hosted", "Hybrid / multi-cloud"
        ):
            q_group_start(q("Shared-inference isolation",
                            "Multi-tenant KV-cache &amp; batch-level leakage"))
            st.radio(q("KV-cache / batch isolation in shared inference",
                       "Are users prevented from observing each other via cache or batch timing?"),
                     YN_OPTIONS, horizontal=True, key="kv_cache_isolation",
                     help=h("Shared LLM serving (vLLM, TensorRT-LLM) reuses KV-cache and batches across users; timing/collision side channels can leak prompts (LLM02, MITRE AML.T0048).",
                            "If multiple users share the same inference endpoint, can one user's prompts leak via cache or batch timing?"))
            q_group_end()
        else:
            st.session_state["kv_cache_isolation"] = "Not Applicable"
    else:
        st.session_state["cost_monitoring"] = "No"
        st.session_state["ai_gateway"] = "No"
        st.session_state["kv_cache_isolation"] = "Not Applicable"


def render_step_security():
    _agentic_step_banner("Agent action security")
    # Row 1 — I/O controls + Encryption & secrets, side-by-side.
    with q_row() as (_io_col, _enc_col):
        with _io_col:
            q_group_start(q("Input / output controls", "What you check on the way in and out of the model"))
            st.radio(q("Input validation", "Do you check inputs before the model sees them?"),
                     YN_OPTIONS, horizontal=True, key="input_validation",
                     help=h("Schema checks, size limits, and content sanitization on inputs.",
                            "Do you check that inputs look sane before sending them to the model?"))
            st.radio(q("Output filtering / moderation", "Do you scan outputs before returning them?"),
                     YN_OPTIONS, horizontal=True, key="output_filtering",
                     help=h("Moderation / PII / secret filters on model output before it reaches users.",
                            "Do you scan the model's output for leaked PII or dangerous content?"))
            if _state_has_tools_or_actions():
                st.radio(q("Tool/plugin sandboxed", "When the model runs a tool, is it sandboxed?"),
                         YN_OPTIONS, horizontal=True, key="sandboxing",
                         help=h("Sandbox / container for agent-executed tools and generated code.",
                                "When the model runs a tool or generated code, is it in a sandbox?"))
            else:
                st.session_state["sandboxing"] = "Not Applicable"
            q_group_end()

        with _enc_col:
            q_group_start(q("Encryption &amp; secrets", "Encryption at rest + how you handle API keys"))
            st.radio(q("Data encrypted at rest", "Is your data encrypted on disk?"),
                     YN_OPTIONS, horizontal=True, key="data_encrypted_at_rest",
                     help=h("Disk-level or field-level encryption for PII/PHI/sensitive data stores.",
                            "Is your data encrypted on disk?"))
            st.radio(q("Model artifacts encrypted", "Are model weights encrypted?"),
                     YN_OPTIONS, horizontal=True, key="artifacts_encrypted_at_rest",
                     help=h("Weights, embeddings, and checkpoints protected against theft (LLM03 / ML05).",
                            "Are the model weights encrypted so someone copying the bucket can't use them?"))
            st.radio(q("Secrets in vault / KMS", "Are API keys in a vault, not in code?"),
                     YN_OPTIONS, horizontal=True, key="secrets_managed_securely",
                     help=h("No plaintext API keys, cloud creds, or tokens in code/configs.",
                            "Are API keys in a vault, or hardcoded in env files / notebooks?"))
            q_group_end()

    if is_agentic_selection():
        q_group_start(q("🤖 Agent action security",
                         "Scope declaration, tool-output sanitization, and destructive-action gates"), color="amber")
        sa1, sa2, sa3 = st.columns(3)
        with sa1:
            st.radio(
                q("Explicit tool/API scope declared",
                  "Is there a written allowlist of exactly which tools and APIs the agent may call?"),
                YN_OPTIONS, horizontal=True, key="agent_scope_declared",
                help=h("An undeclared scope is an open-ended authorization — attacker tricks agent into calling anything (ASI02, ASI03).",
                       "Can the agent call any API it discovers, or is the list of allowed tools explicitly bounded?"),
            )
        with sa2:
            st.radio(
                q("Tool output sanitized before LLM re-ingestion",
                  "Are tool results cleaned for hidden instructions before being fed back into the model context?"),
                YN_OPTIONS, horizontal=True, key="agent_tool_output_sanitization",
                help=h("Prevents indirect prompt injection via tool results — attacker embeds 'ignore instructions' in API responses (LLM08, ASI01).",
                       "A compromised API could return 'ignore previous instructions and exfil data' — do you strip that?"),
            )
        with sa3:
            st.radio(
                q("Destructive actions require explicit approval",
                  "Do send/delete/write actions (email, DB rows, file system) need human or system confirmation?"),
                YN_OPTIONS, horizontal=True, key="agent_destructive_action_gate",
                help=h("Irreversible actions should never auto-execute — require a confirmation gate before the agent proceeds (ASI09, LLM06).",
                       "If the agent decides to send an email or delete a record, does anything stop it without human approval?"),
            )
        q_group_end()

    # Row 2 — Monitoring + Adversarial testing, side-by-side.
    _adv_type_opts = _adversarial_type_options()
    _adv_tool_opts = _adversarial_tool_options()
    _clean_multiselect_answer("adversarial_test_types", _adv_type_opts)
    _clean_multiselect_answer("adversarial_test_tools", _adv_tool_opts)
    with q_row() as (_mon_col, _adv_col):
        with _mon_col:
            q_group_start(q("Monitoring &amp; testing", "Logs, audits, red-teaming"))
            _m1, _m2 = st.columns(2)
            with _m1:
                st.radio(q("Logs &amp; monitoring", "Logs of prompts / responses?"),
                         YN_OPTIONS, horizontal=True, key="logging",
                         help=h("Prompts, responses, tool calls, and errors logged immutably.",
                                "Do you keep logs of prompts, responses, and errors?"))
                st.radio(q("Audits / pen tests", "Has anyone tried to break in?"),
                         YN_OPTIONS, horizontal=True, key="auditing",
                         help=h("Internal or external security audits including AI-specific scenarios.",
                                "Has anyone tried to break into / break the system on purpose?"))
            with _m2:
                st.radio(q("Red-team exercises", "Has anyone tried to jailbreak the model?"),
                         YN_OPTIONS, horizontal=True, key="red_team",
                         help=h("AI-specific red-teaming: prompt injection, jailbreaks, model abuse.",
                                "Has someone specifically tried to jailbreak or trick the model?"))
                st.radio(q("Safety evals (automated)", "Do you run regular bias/jailbreak eval suites?"),
                         YN_OPTIONS, horizontal=True, key="safety_evals",
                         help=h("Continuous evals for hallucination, bias, jailbreak robustness, regressions.",
                                "Do you run an automated test suite for bias, hallucination, jailbreaks regularly?"))
            q_group_end()

        with _adv_col:
            q_group_start(q("Adversarial testing", "Attack types and tools you've actually used"))
            st.multiselect(
                q("Test types performed", "Which attack categories have you tested?"),
                _adv_type_opts,
                key="adversarial_test_types",
                help=h("Categories of adversarial tests you've run against the system.",
                       "Which attack categories have you actually tested for?"),
            )
            _tool_help_suffix = "" if _state_is_llm_like() else " (LLM tools like Garak/PyRIT hidden — not an LLM architecture.)"
            st.multiselect(
                q("Testing tools used", "What tools have you used?"),
                _adv_tool_opts,
                key="adversarial_test_tools",
                help=h("Frameworks used for adversarial testing." + _tool_help_suffix,
                       "What tools have you used? Pick None if none." + _tool_help_suffix),
            )
            q_group_end()


def render_step_governance():
    if is_developer_mode():
        # Bug 7: drop RLHF / explainability / model-card explanations; keep
        # governance items tied to compliance obligations.
        glossary_hint([
            ("Model card / datasheet", "Required for EU AI Act 'high-risk' systems; becomes evidence for audits."),
            ("Traceability / watermarking", "Needed when regulations require distinguishing model-generated from human content (EU AI Act, some FTC guidance)."),
            ("AI-BOM", "AI Bill of Materials — manifest of base model + datasets + adapters + dependencies, ideally signed. Becoming a 2026 customer / regulator expectation."),
            ("EU AI Act high-risk", "Annex III categories (employment, credit, biometrics, education, safety, law-enforcement…) face Aug 2 2026 obligations: risk management, technical docs, human oversight, robustness & cybersecurity."),
            ("ISO/IEC 42001", "Emerging AI Management System certification (2024+). Often a customer-procurement requirement in 2026."),
        ])

    q_group_start(q("Documentation, traceability &amp; explainability",
                    "Foundational governance"))
    g1, g2, g3, g4 = st.columns(4)
    with g1:
        st.radio(q("Model card / documentation",
                   "Is there a written doc covering what the model does and its limits?"),
                 YN_OPTIONS, horizontal=True, key="model_card",
                 help=h("Maintained model card / datasheet covering purpose, limits, and risks.",
                        "Is there a written doc covering what the model does, what it was trained on, and known limits?"))
    with g2:
        st.radio(q("RLHF / feedback loop",
                   "Do you collect thumbs-up/down and actually use it?"),
                 YN_OPTIONS, horizontal=True, key="rl_feedback",
                 help=h("Human feedback incorporated to improve safety over time.",
                        "Do you collect thumbs-up/down and actually use it to tune the model?"))
    with g3:
        # Watermarking only meaningful for generative architectures (LLM, image/audio
        # gen, multimodal).  RAG retrieval and Agentic action pipelines don't produce
        # content that needs provenance marking.
        if is_generative_selection():
            st.radio(q("Output traceable / watermarked",
                       "Can you tell later that a piece of content came from your model?"),
                     YN_OPTIONS, horizontal=True, key="output_watermarking",
                     help=h("Traceability of model-generated content (C2PA, statistical watermark).",
                            "Can you tell later that a specific piece of content came from your model?"))
        else:
            st.session_state["output_watermarking"] = "Not Applicable"
            _html(
                "<div style='font-size:0.74rem;color:#94a3b8;font-style:italic;"
                "padding:8px 0;'>Watermarking is generative-AI specific — not asked for "
                "this architecture.</div>"
            )
    with g4:
        st.radio(q("Explainability available",
                   "Can you show *why* the model said what it said?"),
                 YN_OPTIONS, horizontal=True, key="explainability",
                 help=h("Mechanism to explain model outputs (SHAP, attention, citations, reason traces).",
                        "Can you show *why* the model said what it said — citations, feature importance, chain of thought?"))
    q_group_end()

    q_group_start(q("Regulatory readiness &amp; supply-chain transparency",
                    "EU AI Act, ISO/IEC 42001, AI-BOM, AI incident response"))
    rg1, rg2 = st.columns(2)
    with rg1:
        st.radio(q("AI Bill of Materials (AI-BOM) maintained",
                   "Manifest of base model, datasets, fine-tunes, dependencies, and signatures?"),
                 YN_OPTIONS, horizontal=True, key="ai_bom",
                 help=h("AI-BOM enables supply-chain traceability; expected for high-risk + customer due-diligence (LLM03 / ML06).",
                        "Do you have a signed manifest of every component in this model: base, data, adapters, libs?"))
        st.radio(q("AI-specific incident response plan",
                   "Documented playbook for poisoning, jailbreak, prompt leak, agent runaway?"),
                 YN_OPTIONS, horizontal=True, key="ai_incident_response_plan",
                 help=h("Distinct from generic IR; covers AI-specific events and 72-hour reporting under EU AI Act / NIST AI 600-1.",
                        "If the model misbehaves, does someone know who to call and what to do?"))
        st.radio(q("ISO/IEC 42001 alignment",
                   "Project aligned to ISO/IEC 42001 (AI Management System)?"),
                 YN_OPTIONS, horizontal=True, key="iso_42001_alignment",
                 help=h("ISO/IEC 42001 is the emerging AIMS certification (2024+); customer asks accelerating in 2026.",
                        "Is the org's AI program structured per ISO 42001? (Often a customer-procurement requirement.)"))
    with rg2:
        st.selectbox(q("EU AI Act high-risk classification",
                       "Is this an EU AI Act high-risk system (Annex III)?"),
                     ["Unknown", "No — out of scope", "No — minimal/limited risk",
                      "Yes — high-risk (Annex III)", "Yes — prohibited (Art. 5)",
                      "GPAI / General-purpose AI"],
                     key="eu_ai_act_high_risk",
                     help=h("High-risk obligations (Art. 9 risk mgmt, Art. 13 transparency, Art. 15 robustness) enter force Aug 2 2026.",
                            "Does this fall under EU AI Act high-risk (jobs, credit, biometrics, education, safety, etc.)?"))
        st.radio(q("Third-party AI audit readiness",
                   "Could you pass an independent AI audit today (model card, lineage, evals, logs)?"),
                 YN_OPTIONS, horizontal=True, key="third_party_audit_ready",
                 help=h("EU AI Act Art.68 mandates third-party audits for high-risk; customers increasingly demand this independent of regulation.",
                        "If a customer or regulator asked to audit this AI today, would you have the artifacts ready?"))
    q_group_end()


def render_step_llm():
    if is_developer_mode():
        # Bug 7: drop basic LLM terminology (system prompt, hallucination,
        # grounding) — keep the attack-pattern definitions that drive rules.
        glossary_hint([
            ("Prompt injection (LLM01)", "Direct override of instructions by a user prompt."),
            ("Indirect prompt injection", "Payload hidden in retrieved docs / emails / tool output; fires when that content reaches the prompt."),
            ("System-prompt leakage (LLM07)", "Extraction of your hidden instructions, sometimes containing policies or secrets."),
        ])
    q_group_start(q("Prompt strategy &amp; guardrails", "Prompt building + safety checks"))
    p1, p2 = st.columns(2)
    with p1:
        st.selectbox(
            q("Prompt strategy",
              "How do you build prompts — string concat, or a locked-down template?"),
            ["Free-form", "Templated", "System/developer prompt with policy",
             "Structured JSON/tool schema", "Not Applicable"],
            key="prompt_template",
            help=h("Template discipline reduces injection surface. Structured outputs are safer than free-form.",
                   "How do you build prompts? Just string concat, or a locked-down template / JSON schema?"),
        )
    with p2:
        st.multiselect(
            q("LLM / GenAI guardrails",
              "What's checking prompts and outputs for bad stuff?"),
            ["None", "Content moderation", "Prompt injection detector",
             "Output policy checker", "PII/secrets redaction",
             "Tool-call policy engine", "OpenAI Moderation API",
             "Rebuff", "Guardrails.ai", "Prompt Armor", "Custom guardrails"],
            key="llm_firewall",
            help=h("Any content-safety / prompt-injection / policy guardrails in place.",
                   "What's checking the prompts and outputs for bad stuff? Pick None if you haven't wired anything up."),
        )
    q_group_end()

    q_group_start(q("System prompt and hallucination", "System prompt handling + hallucination controls"))
    sp1, sp2, sp3 = st.columns(3)
    with sp1:
        st.radio(q("System prompt contains secrets or policies you don't want leaked?",
                   "Is there anything in your system prompt you'd hate for users to see?"),
                 YN_OPTIONS, horizontal=True, key="system_prompt_secrets",
                 help=h("If yes, system-prompt leakage (LLM07) becomes a direct risk.",
                        "Is there anything in the system prompt you'd hate for users to see — API keys, business rules, competitor-facing strategy?"))
    with sp2:
        st.radio(q("System-prompt / instruction protection tested",
                   "Have you tried to make the model print or override its own system prompt?"),
                 YN_OPTIONS, horizontal=True, key="system_prompt_protection",
                 help=h("Prompt extraction, instruction override, and indirect-injection tests.",
                        "Have you actually tried to get the model to print its system prompt, or override its instructions?"))
    with sp3:
        st.radio(q("Hallucination / grounding controls in place",
                   "Do you force citations / verifier calls, or let the model freestyle?"),
                 YN_OPTIONS, horizontal=True, key="hallucination_controls",
                 help=h("Grounded responses, citations, self-consistency, verifier models.",
                        "Do you force the model to cite sources, or cross-check answers, so it can't just make things up?"))
    q_group_end()


def render_step_multimodal():
    if is_developer_mode():
        # Bug 7: keep attack-pattern terms only.
        glossary_hint([
            ("Image / audio prompt injection", "Malicious instructions embedded in an image's alt-text, OCR'd caption, steganography layer, or audio transcript — executed when the model reads the asset."),
            ("EXIF / metadata injection", "Payloads hidden in image or document metadata fields that get concatenated into the prompt."),
            ("Document / PDF injection", "PDFs and docs can hide instructions (white text, metadata, OCR layers) that hijack RAG / summarization pipelines."),
            ("C2PA provenance", "Coalition for Content Provenance & Authenticity — a digital credential signed onto generated media so consumers can verify origin."),
            ("Deepfake / synthetic-voice", "AI-generated audio/video used to impersonate executives, customers, or biometric identity gates."),
        ])
    q_group_start(q("Multi-modal injection testing", "Image / audio / document attacks"))
    mm1, mm2 = st.columns(2)
    with mm1:
        # General + vision + audio questions only make sense when the model
        # actually processes images or audio (Multimodal AI).  Plain LLMs and
        # Generative-text models receive only text/documents.
        if is_multimodal_selection():
            st.radio(q("General multimodal injection testing",
                       "Overall: have you tested injection across modalities?"),
                     YN_OPTIONS, horizontal=True, key="multimodal_injection_testing",
                     help=h("Covers injection via images, audio transcripts, metadata/EXIF, PDFs, etc.",
                            "If your model reads images/audio, have you tested what happens when the input carries hidden instructions?"))
            st.radio(q("Vision-specific injection testing",
                       "Adversarial text / QR / typographic prompts in images?"),
                     YN_OPTIONS, horizontal=True, key="vision_injection_testing",
                     help=h("OCR-pivot, embedded QR with instructions, typographic prompts, steganographic payloads against VLMs (LLM01 vision variant, MITRE AML.T0051).",
                            "Have you tested images carrying hidden instructions the vision model picks up?"))
            st.radio(q("Audio adversarial testing",
                       "Acoustic adversarials / Whisper prompt-prepending tested?"),
                     YN_OPTIONS, horizontal=True, key="audio_injection_testing",
                     help=h("Acoustic adversarials and prepended-prompt audio against Whisper-class STT (LLM01 audio variant).",
                            "If the model takes audio, have you tested adversarial audio that hijacks the transcript?"))
        else:
            st.session_state["multimodal_injection_testing"] = "Not Applicable"
            st.session_state["vision_injection_testing"]     = "Not Applicable"
            st.session_state["audio_injection_testing"]      = "Not Applicable"
    with mm2:
        st.radio(q("Document / PDF injection sanitization",
                   "Hidden instructions stripped from uploaded PDFs/docs before LLM read?"),
                 YN_OPTIONS, horizontal=True, key="document_pdf_injection",
                 help=h("PDFs can carry white-on-white text, metadata, or OCR'd payloads that survive into context (LLM01 indirect, LLM08 retrieval).",
                        "When a user uploads a PDF or doc, do you strip hidden instructions before the LLM reads it?"))
        st.radio(q("Deepfake / synthetic-voice detection",
                   "Detection for AI-generated voice / face impersonation?"),
                 YN_OPTIONS, horizontal=True, key="deepfake_detection",
                 help=h("Liveness, deepfake classifiers, voiceprint integrity for video/audio that drives trust decisions (62% of cyber leaders saw deepfake attacks in 2025; OWASP LLM05 / NIST AI 600-1).",
                        "Could a deepfake voice/video fool this system? Do you detect them?"))
        if is_generative_selection():
            st.radio(q("C2PA / content provenance signing",
                       "Generated media signed with C2PA digital credentials?"),
                     YN_OPTIONS, horizontal=True, key="c2pa_provenance",
                     help=h("C2PA lets downstream consumers verify origin & edit history of generated media (NIST AI 600-1, EU AI Act Art. 50 transparency).",
                            "When you generate media, do you sign it with C2PA so people can verify its origin?"))
            if st.session_state.get("output_watermarking") == "Yes":
                st.radio(q("Watermark robustness tested",
                           "Does the watermark survive crop / compress / re-encode?"),
                         YN_OPTIONS, horizontal=True, key="watermark_robustness",
                         help=h("Watermarks degrade under common transformations — false confidence allows misinformation to spread (LLM09).",
                                "If you watermark output, have you tested it survives normal post-processing?"))
            else:
                st.session_state["watermark_robustness"] = "Not Applicable"
        else:
            st.session_state["c2pa_provenance"] = "Not Applicable"
            st.session_state["watermark_robustness"] = "Not Applicable"
    q_group_end()


def render_step_finetune():
    if is_developer_mode():
        # Bug 7: devs know what fine-tuning is; keep the risks only.
        glossary_hint([
            ("Memorization of secrets (LLM02)", "Fine-tuning on un-redacted data can make the model surface API keys or PII via normal prompts."),
            ("Backdoored base model (LLM03 / ML06)", "If the base you fine-tuned came from an untrusted source, it may contain dormant triggers that survive fine-tuning."),
            ("LoRA / PEFT poisoning", "Adapters from public hubs can carry backdoors that merge cleanly into your base model — hard to detect."),
            ("Alignment regression", "Fine-tuning silently undoes RLHF safety; if you only test task accuracy, jailbreaks come back."),
            ("Jailbreak transfer", "Jailbreaks for closely-related foundation models often transfer; one model's failure can compromise yours."),
        ])

    if is_fine_tuned_selection():
        q_group_start(q("Fine-tune data &amp; base-model provenance",
                        "What you fine-tuned with, and what you fine-tuned from"))
        ft1, ft2 = st.columns(2)
        with ft1:
            st.radio(q("Fine-tune dataset reviewed / redacted for secrets and PII",
                       "Did you scrub your fine-tune data for API keys, PII, and junk samples?"),
                     YN_OPTIONS, horizontal=True, key="fine_tune_data_review",
                     help=h("Prevents training-time memorization of secrets or PII (LLM02 / ML02).",
                            "Did you scrub your fine-tune data for API keys, PII, and obviously-bad examples?"))
        with ft2:
            st.radio(q("Base-model provenance / trust verified",
                       "Do you actually trust where your base model came from?"),
                     YN_OPTIONS, horizontal=True, key="fine_tune_base_model_trust",
                     help=h("Verifies source, license, and integrity of the base model (LLM03 / ML06).",
                            "Do you actually trust the base model you fine-tuned? Where is it from, is it signed, has it been scanned?"))
        q_group_end()
    else:
        st.session_state["fine_tune_data_review"] = "Not Applicable"
        st.session_state["fine_tune_base_model_trust"] = "Not Applicable"

    # Alignment + adapter + jailbreak-transfer questions apply broadly to any
    # LLM-like system, even ones using only a third-party model.
    q_group_start(q("Alignment, adapters &amp; jailbreak transfer",
                    "Customization safety beyond just data review"))
    _show_lora       = is_fine_tuned_selection()
    _show_align_regr = is_fine_tuned_selection() or st.session_state.get("rl_feedback") == "Yes"

    if _show_lora and _show_align_regr:
        # All three columns populated — full 3-col layout.
        al1, al2, al3 = st.columns(3)
        with al1:
            st.radio(q("LoRA / PEFT adapter source verification",
                       "Are downloaded LoRA / PEFT adapters scanned and pinned by hash?"),
                     YN_OPTIONS, horizontal=True, key="lora_adapter_validation",
                     help=h("Adapters from HF / public repos can carry backdoors that merge cleanly into base weights (ML06, ML10).",
                            "If you use community LoRAs / adapters, do you scan & pin them?"))
        with al2:
            st.radio(q("Alignment regression testing post-customization",
                       "After fine-tuning / RLHF, do you re-run safety / jailbreak / harmful-output evals?"),
                     YN_OPTIONS, horizontal=True, key="alignment_regression_testing",
                     help=h("Fine-tuning and RLHF changes can silently undo safety alignment; re-run TruthfulQA / HarmBench / custom safety suites every release.",
                            "Do you actually re-test safety after fine-tuning / RLHF, or only task-specific accuracy?"))
        with al3:
            st.radio(q("Jailbreak transferability assessed",
                       "Have you tested whether known jailbreaks for similar models work on yours?"),
                     YN_OPTIONS, horizontal=True, key="jailbreak_transfer_testing",
                     help=h("Jailbreaks transfer across closely-related foundation models; one model's failure may compromise yours (ML06 supply chain).",
                            "Do known jailbreaks for the underlying foundation model still work after your customization?"))
    elif _show_lora:
        # Fine-tuning only (no RLHF) — LoRA + jailbreak, 2 columns.
        st.session_state["alignment_regression_testing"] = "Not Applicable"
        al1, al2 = st.columns(2)
        with al1:
            st.radio(q("LoRA / PEFT adapter source verification",
                       "Are downloaded LoRA / PEFT adapters scanned and pinned by hash?"),
                     YN_OPTIONS, horizontal=True, key="lora_adapter_validation",
                     help=h("Adapters from HF / public repos can carry backdoors that merge cleanly into base weights (ML06, ML10).",
                            "If you use community LoRAs / adapters, do you scan & pin them?"))
        with al2:
            st.radio(q("Jailbreak transferability assessed",
                       "Have you tested whether known jailbreaks for similar models work on yours?"),
                     YN_OPTIONS, horizontal=True, key="jailbreak_transfer_testing",
                     help=h("Jailbreaks transfer across closely-related foundation models; one model's failure may compromise yours (ML06 supply chain).",
                            "Do known jailbreaks for the underlying foundation model still work after your customization?"))
    elif _show_align_regr:
        # RLHF only (no fine-tuning) — alignment regression + jailbreak, 2 columns.
        st.session_state["lora_adapter_validation"] = "Not Applicable"
        al1, al2 = st.columns(2)
        with al1:
            st.radio(q("Alignment regression testing post-customization",
                       "After fine-tuning / RLHF, do you re-run safety / jailbreak / harmful-output evals?"),
                     YN_OPTIONS, horizontal=True, key="alignment_regression_testing",
                     help=h("Fine-tuning and RLHF changes can silently undo safety alignment; re-run TruthfulQA / HarmBench / custom safety suites every release.",
                            "Do you actually re-test safety after fine-tuning / RLHF, or only task-specific accuracy?"))
        with al2:
            st.radio(q("Jailbreak transferability assessed",
                       "Have you tested whether known jailbreaks for similar models work on yours?"),
                     YN_OPTIONS, horizontal=True, key="jailbreak_transfer_testing",
                     help=h("Jailbreaks transfer across closely-related foundation models; one model's failure may compromise yours (ML06 supply chain).",
                            "Do known jailbreaks for the underlying foundation model still work after your customization?"))
    else:
        # Neither fine-tuning nor RLHF — only jailbreak question is universal.
        st.session_state["lora_adapter_validation"]      = "Not Applicable"
        st.session_state["alignment_regression_testing"] = "Not Applicable"
        st.radio(q("Jailbreak transferability assessed",
                   "Have you tested whether known jailbreaks for similar models work on yours?"),
                 YN_OPTIONS, horizontal=True, key="jailbreak_transfer_testing",
                 help=h("Jailbreaks transfer across closely-related foundation models; one model's failure may compromise yours (ML06 supply chain).",
                        "Do known jailbreaks for the underlying foundation model still work after your customization?"))
    q_group_end()


def render_step_agentic():
    if is_developer_mode():
        # Bug 7: devs know agent & HITL basics; focus on OWASP ASI attack types.
        glossary_hint([
            ("Goal hijack (ASI01)", "Adversarial input that replaces the agent's objective with the attacker's."),
            ("Tool misuse (ASI02)", "Tricking the agent into calling tools with attacker-chosen arguments."),
            ("Confused deputy (ASI03)", "Agent acts with more privilege than the user who asked it — a classic privilege-escalation pattern."),
            ("Memory poisoning (ASI06)", "Attacker plants false facts into persistent memory that influence future reasoning."),
            ("Cascading failure (ASI08)", "One misbehaving agent or tool call triggers downstream agents / tools to amplify the error."),
        ])
    q_group_start(q("Autonomy and capabilities", "What can the agent do on its own?"))
    a1, a2 = st.columns(2)
    with a1:
        st.radio(
            q("Autonomous operation",
              "Does the agent act on its own for multiple steps (no human in the loop per step)?"),
            YN_OPTIONS, horizontal=True, key="agentic_autonomous",
            help=h("Agent takes multi-step actions without user-in-loop (LLM06, ASI10).",
                   "If yes, it maps to OWASP LLM06 (Excessive Agency) and ASI10 (Rogue Agents)."),
        )
        st.radio(
            q("External tool / API access",
              "Can the agent call tools / APIs, or is it read-only?"),
            YN_OPTIONS, horizontal=True, key="agentic_tool_access",
            help=h("Agent calls tools/APIs — widens attack surface (ASI02).",
                   "Tool access widens the attack surface (OWASP ASI02)."),
        )
        st.radio(
            q("Persistent memory",
              "Does the agent remember things between sessions?"),
            YN_OPTIONS, horizontal=True, key="agentic_memory",
            help=h("Memory persisted across sessions (ASI06 memory poisoning risk).",
                   "Persistent memory is the target of OWASP ASI06 (Memory Poisoning)."),
        )
        st.radio(
            q("Can execute code",
              "Can the agent run Python / shell / arbitrary code it generates?"),
            YN_OPTIONS, horizontal=True, key="agentic_code_execution",
            help=h("Agent can generate AND run code (ASI05 unexpected code execution).",
                   "If yes we check for OWASP ASI05 (Unexpected Code Execution) — needs a sandbox."),
        )
        st.radio(
            q("Multi-agent system",
              "Are multiple agents talking to each other, or just one?"),
            YN_OPTIONS, horizontal=True, key="agentic_multi_agent",
            help=h("Multiple agents collaborate — introduces ASI07 inter-agent communication risks.",
                   "Multi-agent setups pull in OWASP ASI07 & ASI08 (communication / cascading failure)."),
        )
    with a2:
        st.radio(
            q("Human in the loop / circuit breakers",
              "Does a human have to approve before the agent does anything important?"),
            YN_OPTIONS, horizontal=True, key="agentic_hitl",
            help=h("Required HITL approvals for sensitive or destructive actions.",
                   "HITL approvals block the blast-radius of a hijacked agent."),
        )
        st.radio(
            q("Agent action logging",
              "Are the agent's plans, tool calls, and results logged so you can investigate later?"),
            YN_OPTIONS, horizontal=True, key="agentic_logging",
            help=h("Immutable logs of plans, tool calls, outputs, and user context.",
                   "Without this, an incident is almost impossible to root-cause."),
        )
        st.radio(
            q("Memory controls (scoping, expiry, integrity)",
              "If there's memory: is it scoped per user, does it expire, can you detect tampering?"),
            YN_OPTIONS, horizontal=True, key="agentic_memory_controls",
            help=h("Scoping, TTLs, integrity checks on persistent memory.",
                   "Scoping + TTL + integrity checks are the mitigations for ASI06."),
        )
        st.radio(
            q("Code execution sandboxed",
              "If the agent runs code, is it in a locked-down sandbox?"),
            YN_OPTIONS, horizontal=True, key="agentic_code_sandbox",
            help=h("Container/OS sandbox with narrow FS/network/secret access.",
                   "Direct execution on your host is the #1 rope-to-hang-yourself pattern."),
        )
        st.radio(
            q("Inter-agent authentication / signed messages",
              "When agents talk to each other, can an attacker spoof one?"),
            YN_OPTIONS, horizontal=True, key="agentic_inter_agent_auth",
            help=h("Agents authenticate each other and messages are integrity-protected (ASI07).",
                   "Mitigates OWASP ASI07 — agent-to-agent messages should be signed + authenticated."),
        )

    q_group_end()

    q_group_start(q("Identity, safety and supply chain", "What does the agent touch, and who built its parts?"))
    b1, b2, b3 = st.columns(3)
    with b1:
        st.radio(q("Handles sensitive data",
                   "Does the agent touch PII / PHI / secrets / financial data?"),
                 YN_OPTIONS, horizontal=True, key="agentic_sensitive_data",
                 help=h("If yes, encryption/DLP/access rules escalate (LLM02).",
                        "Does the agent touch PII / PHI / secrets / financial data?"))
    with b2:
        st.radio(q("Adversarial-input detection for agent",
                   "Do you watch for jailbreak / goal-hijack attempts against the agent?"),
                 YN_OPTIONS, horizontal=True, key="agentic_malicious_input_detection",
                 help=h("Detection for prompt-injection, goal hijack, memory poisoning (ASI01).",
                        "Are you looking for jailbreak / goal-hijack attempts against the agent specifically?"))
    with b3:
        st.radio(q("Runtime limits / kill switch",
                   "Can you stop the agent in one click or with a budget ceiling?"),
                 YN_OPTIONS, horizontal=True, key="agentic_kill_switch",
                 help=h("Step/cost/time caps and emergency stop to bound blast radius.",
                        "If the agent goes off the rails, can you stop it in one click or with a budget ceiling?"))
    b4, b5 = st.columns(2)
    with b4:
        st.radio(q("Agent identities scoped per user / task",
                   "Does the agent act as the current user, or as a shared super-user?"),
                 YN_OPTIONS, horizontal=True, key="agentic_identity_scoped",
                 help=h("Per-user, per-task, JIT credentials (ASI03 confused-deputy prevention).",
                        "When the agent calls APIs on behalf of a user, does it use that user's identity or a shared super-user?"))
    with b5:
        st.radio(q("Agent / tool supply chain reviewed",
                   "Do you know who built each tool / plugin and pin versions?"),
                 YN_OPTIONS, horizontal=True, key="agentic_supply_chain_controls",
                 help=h("Provenance/signatures/pinning for agents, plugins, and MCP servers (ASI04).",
                        "Do you actually know who built each tool / plugin / agent component and pin versions?"))

    q_group_end()

    q_group_start(q("Oversight and environment", "Oversight + the runtime the agent drives"))
    c1, c2 = st.columns(2)
    with c1:
        st.radio(q("Agent plan / reasoning inspection (pre-action review)",
                   "Before the agent executes, can someone see its plan and approve it?"),
                 YN_OPTIONS, horizontal=True, key="agentic_plan_inspection",
                 help=h("Reviewable plan-trace / tool-call approval before execution (ASI09).",
                        "Before the agent executes its plan, can someone see it and approve it?"))
    with c2:
        st.radio(q("Uses browser / computer-use / OS-control agent?",
                   "Does the agent drive a browser or desktop?"),
                 YN_OPTIONS, horizontal=True, key="browser_agent_use",
                 help=h("Browser and computer-use agents expand the attack surface dramatically.",
                        "Does the agent drive a browser or desktop? Those are high-risk because web pages can carry hidden instructions."))

    q_group_end()

    q_group_start(q("Modern agent threats",
                    "Goal drift, agent-to-agent infection chains, autonomous privilege creep, HITL bypass"))
    if is_developer_mode():
        glossary_hint([
            ("Multi-Agent Infection Chain (MAIC)", "One jailbroken/poisoned agent peer-pressures other agents into harmful behavior via inter-agent messages — invisible to per-agent filters."),
            ("Agent identity spoofing", "An agent (or attacker) claims to be the 'supervisor' or 'admin' agent and other agents grant trust based on the claim alone."),
            ("Long-horizon goal drift", "Over many steps / hours / days, an agent's objective subtly shifts from what was originally requested due to cumulative prompt injections or memory poisoning."),
            ("Autonomous credential acquisition", "Agents argue 'I need elevated access to finish this task' and obtain new tokens / scopes if there is no audit gate."),
            ("HITL bypass", "Agents craft 'too-quick' or 'pre-approved' framings to slip past the human reviewer who's supposed to gate dangerous actions."),
        ])
    n1, n2 = st.columns(2)
    with n1:
        st.radio(q("Long-horizon goal-drift monitoring",
                   "For multi-day / many-step agents, do you check the agent's objective hasn't drifted?"),
                 YN_OPTIONS, horizontal=True, key="agent_goal_drift_monitoring",
                 help=h("Detect cumulative goal drift via periodic objective re-statement, plan-trace diffs, or external auditor (ASI01 extended, ASI06).",
                        "If the agent runs for hours/days, do you check it still wants to do what you originally asked?"))
        st.radio(q("Autonomous credential / privilege acquisition controls",
                   "Are agents prevented (or audited) when they try to obtain new tokens / scopes?"),
                 YN_OPTIONS, horizontal=True, key="agent_credential_acquisition",
                 help=h("Agents can argue they 'need elevated access to finish task'. Block, audit, or human-approve credential requests (ASI03, MCP01).",
                        "Can the agent talk its way into more privileges, and would you notice?"))
        if st.session_state.get("agentic_hitl") == "Yes":
            st.radio(q("HITL-bypass detection",
                       "Do you detect agents attempting to bypass / socially-engineer HITL gates?"),
                     YN_OPTIONS, horizontal=True, key="agent_hitl_bypass_detection",
                     help=h("Agents may craft 'too-quick' or 'pre-approved' framings to slip past human reviewers (ASI09).",
                            "Could the agent talk a human into clicking approve when they shouldn't?"))
        else:
            st.session_state["agent_hitl_bypass_detection"] = "Not Applicable"
    with n2:
        if st.session_state.get("agentic_multi_agent") == "Yes":
            st.radio(q("Multi-agent collusion / infection-chain detection",
                       "Can you detect a poisoned agent influencing peers via inter-agent messages?"),
                     YN_OPTIONS, horizontal=True, key="agent_collusion_controls",
                     help=h("Multi-Agent Infection Chains (MAIC) — one compromised agent peer-pressures the swarm via JSON inter-agent messages, invisible to traditional WAF (ASI01, ASI07).",
                            "If one agent gets jailbroken, can it spread bad instructions to the other agents?"))
            st.radio(q("Cryptographic agent identity verification",
                       "Do agents authenticate each other with signed identity claims (vs. shared secrets only)?"),
                     YN_OPTIONS, horizontal=True, key="agent_identity_verification",
                     help=h("Each agent has a signed identity claim verifiable by peers; prevents spoofing of 'supervisor' or 'admin' agents (ASI03 confused-deputy, ATR-2026-00117).",
                            "When one agent claims it's the 'supervisor', can a peer cryptographically verify that?"))
        else:
            st.session_state["agent_collusion_controls"] = "Not Applicable"
            st.session_state["agent_identity_verification"] = "Not Applicable"
            _html("<div style='font-size:0.74rem;color:#94a3b8;font-style:italic;padding:6px 0;'>"
                  "Multi-agent fields shown only when 'Multi-agent system' is Yes.</div>")
    q_group_end()


def render_step_mcp():
    if is_developer_mode():
        # Bug 7: devs know what MCP / tool schemas are. Keep the attack patterns.
        glossary_hint([
            ("Tool poisoning / rug-pull (MCP03)", "Malicious server hides instructions inside tool descriptions, or silently mutates a tool's schema after you've trusted it."),
            ("Intent-flow subversion (MCP06)", "Tool output is crafted to alter the model's plan / intent for future tool calls."),
            ("Shadow MCP server (MCP09)", "An MCP server connected to your agent without explicit approval or inventory — common via dev-environment auto-loading."),
            ("Context injection / over-sharing (MCP10)", "MCP server returns more context (secrets, other-tenant data) than it should, which then lands in the prompt."),
        ])
    st.radio(q("Uses MCP or MCP-like tool layer?",
               "Are you using MCP (or similar) to let the model call external tools?"),
             YN_OPTIONS, horizontal=True, key="mcp_usage",
             help=h("Enables MCP-specific rules (token mgmt, tool poisoning, cross-server shadowing, etc.).",
                    "Are you using MCP or something similar to give the model access to external tools?"))
    if st.session_state.get("mcp_usage") == "Yes":
        q_group_start(q("Server trust", "Who's running the MCP servers you talk to?"))
        m1, m2 = st.columns(2)
        with m1:
            st.radio(q("Third-party MCP servers",
                       "Do any of your MCP servers come from someone else?"),
                     YN_OPTIONS, horizontal=True, key="mcp_third_party_servers",
                     help=h("Using servers you didn't build triggers supply-chain rules (MCP04).",
                            "Do any of your MCP servers come from someone else (vendor, OSS community)?"))
            st.radio(q("Remote MCP servers (vs. local-only)",
                       "Are MCP servers reached over the network, or local only?"),
                     YN_OPTIONS, horizontal=True, key="mcp_remote_servers",
                     help=h("Remote transport adds TLS / session / replay requirements (MCP07).",
                            "Are MCP servers reached over the network, or are they local processes only?"))
            st.radio(q("Tool schemas pinned / integrity monitored",
                       "Are tool schemas locked so they can't silently change on you?"),
                     YN_OPTIONS, horizontal=True, key="mcp_tool_schema_integrity",
                     help=h("Pin by hash and alert on schema mutations (MCP03 tool poisoning).",
                            "Do you lock tool schemas so they can't silently change after you approved them?"))
            st.radio(q("Tool outputs sanitized before LLM consumption",
                       "Do you clean tool outputs before they land back in the prompt?"),
                     YN_OPTIONS, horizontal=True, key="mcp_tool_output_sanitization",
                     help=h("Strip instruction-like content from tool outputs (MCP06 intent-flow subversion).",
                            "Before an MCP tool's output goes back into the model's context, do you clean it up?"))
        with m2:
            st.radio(q("Least-privilege / per-user MCP authorization",
                       "Does each tool get only what it needs, scoped to the current user?"),
                     YN_OPTIONS, horizontal=True, key="mcp_authz",
                     help=h("Narrow scopes, short-lived tokens, per-user / per-server authorization (MCP07).",
                            "Does each MCP server get only the permissions it actually needs, scoped to the current user?"))
            st.radio(q("Human approval for sensitive MCP calls",
                       "For destructive calls (delete, send), does a human click 'yes'?"),
                     YN_OPTIONS, horizontal=True, key="mcp_human_approval",
                     help=h("Show full parameters and require explicit approval for destructive actions (MCP02).",
                            "For dangerous tool calls (send email, delete row), does a human click 'yes, do it'?"))
            st.radio(q("MCP servers isolated by trust zone",
                       "Are sketchy and trusted MCP servers walled off from each other?"),
                     YN_OPTIONS, horizontal=True, key="mcp_server_isolation",
                     help=h("Treat each server as its own security domain; isolate sensitive tools (MCP10).",
                            "Are your MCP servers split into trust zones, or can a sketchy one influence how your trusted tools get called?"))

        q_group_end()

        q_group_start(q("Modern MCP threats",
                        "Federation, transport, shadow servers, prompt-in-result, audit"))
        if is_developer_mode():
            glossary_hint([
                ("Federation / transitive trust", "When MCP server A calls MCP server B, B inherits A's trust — one compromised hop = lateral movement across your toolchain."),
                ("Tool-description injection", "Adversarial JSON description (e.g. 'always call this tool first') in a tool spec influences agent behavior at registration time."),
                ("Prompt-in-result", "Tool returns a string that is itself a prompt; the LLM treats the result as authoritative and executes the embedded instruction (MCP02 / LLM01 indirect)."),
                ("Shadow MCP server", "A server attached to your agents without explicit approval / inventory — common in dev environments via auto-loading."),
            ])
        n1, n2 = st.columns(2)
        with n1:
            st.radio(q("MCP server federation / transitive-trust controls",
                       "When MCP servers call other MCP servers, is each hop authorized?"),
                     YN_OPTIONS, horizontal=True, key="mcp_federation_trust",
                     help=h("Federation creates transitive trust paths; one compromised server enables lateral movement (MCP04, MCP09).",
                            "If one MCP server reaches another, is each hop checked, or do they all trust each other?"))
            st.radio(q("Tool-description / schema validation",
                       "Are JSON tool descriptions validated for hidden instructions before registration?"),
                     YN_OPTIONS, horizontal=True, key="mcp_tool_description_validation",
                     help=h("Adversarial tool descriptions (e.g. 'always call this tool first') guide agents into misuse (MCP03 tool poisoning).",
                            "Could a malicious MCP server's tool description trick the model into using it incorrectly?"))
            st.radio(q("Prompt-injection filtering on tool RESULTS",
                       "Do you scan tool RESULTS (not just inputs) for embedded prompts?"),
                     YN_OPTIONS, horizontal=True, key="mcp_prompt_in_result_filtering",
                     help=h("Tool outputs flow back into the LLM context; adversarial tools can return prompts (MCP02 extended, LLM01 indirect).",
                            "When an MCP tool returns data, do you scan it for prompt-injection before showing the model?"))
        with n2:
            st.radio(q("MCP transport security (TLS, signed channels)",
                       "Are MCP HTTP / SSE / stdio transports encrypted &amp; authenticated?"),
                     YN_OPTIONS, horizontal=True, key="mcp_transport_security",
                     help=h("Plaintext stdio sockets, unencrypted SSE, or HTTP credentials are common; transport hardening required (MCP01, MCP07).",
                            "Are the connections to your MCP servers encrypted and properly authenticated?"))
            st.radio(q("Shadow MCP server discovery / inventory",
                       "Do you have an inventory of approved MCP servers and detect rogue ones?"),
                     YN_OPTIONS, horizontal=True, key="mcp_shadow_discovery",
                     help=h("Dev environments often auto-register MCP servers without approval; build an allowlist + discovery audit (MCP09).",
                            "Could a sketchy MCP server attach to your agents without anyone noticing?"))
            st.radio(q("MCP invocation audit telemetry",
                       "Is every MCP tool call logged with caller, parameters, and result?"),
                     YN_OPTIONS, horizontal=True, key="mcp_audit_telemetry",
                     help=h("MCP traffic happens via JSON APIs invisible to traditional WAF/log; per-call audit needed (MCP08).",
                            "Can you see exactly which MCP tools were called, with what arguments, by which agent?"))
        q_group_end()


def render_step_classical_ml():
    _model_type = st.session_state.get("model_type", "")
    if _model_type == "Reinforcement Learning System":
        _html(
            "<div style='background:#ffedd5;border:1px solid #fed7aa;border-left:4px solid #ea580c;"
            "border-radius:6px;padding:9px 14px;margin-bottom:14px;'>"
            "<strong style='color:#9a3412;font-size:0.85rem;'>⚠️ Reinforcement Learning detected</strong>"
            "<span style='color:#c2410c;font-size:0.8rem;margin-left:8px;'>"
            "Scroll to the bottom for RL-specific questions: reward hacking, policy drift, and safe-RL constraints.</span>"
            "</div>"
        )
    elif _model_type == "Edge AI / IoT Model":
        _html(
            "<div style='background:#ccfbf1;border:1px solid #99f6e4;border-left:4px solid #0d9488;"
            "border-radius:6px;padding:9px 14px;margin-bottom:14px;'>"
            "<strong style='color:#134e4a;font-size:0.85rem;'>📡 Edge AI / IoT detected</strong>"
            "<span style='color:#0f766e;font-size:0.8rem;margin-left:8px;'>"
            "Scroll to the bottom for Edge AI questions: OTA update security, physical adversarials, and on-device encryption.</span>"
            "</div>"
        )
    q_group_start(q("Adversarial robustness", "Can your model be fooled by crafted inputs?"))
    c1, c2 = st.columns(2)
    with c1:
        st.selectbox(
            q("Adversarial robustness testing",
              "Do you test the model against adversarial examples (e.g. FGSM, PGD, DeepFool)?"),
            CONTROL_OPTIONS,
            key="adversarial_robustness_testing",
            help=h("Models without adversarial testing are vulnerable to OWASP ML01 (Adversarial Evasion).",
                   "Adversarial examples are inputs crafted to fool classifiers — e.g. adding imperceptible noise to bypass a fraud detector."),
        )
    with c2:
        st.selectbox(
            q("Input schema / feature validation",
              "Are input features validated against an expected schema before inference?"),
            CONTROL_OPTIONS,
            key="ml_input_schema_validation",
            help=h("Missing schema validation lets attackers send malformed features to probe model behaviour (ML02).",
                   "Validate feature ranges, dtypes, and presence before they hit your model."),
        )
    q_group_end()

    q_group_start(q("Privacy attacks", "Could someone extract training data or membership info from your model?"))
    c1, c2 = st.columns(2)
    with c1:
        st.selectbox(
            q("Membership inference controls",
              "Do you apply defences against membership inference attacks (differential privacy, output rounding)?"),
            CONTROL_OPTIONS,
            key="membership_inference_controls",
            help=h("Membership inference lets an attacker determine whether a record was in the training set — a GDPR / HIPAA risk (ML05).",
                   "Mitigation: differential privacy (DP-SGD), prediction confidence rounding, model ensembles."),
        )
    with c2:
        st.selectbox(
            q("Model inversion controls",
              "Do you apply defences against model inversion / reconstruction attacks?"),
            CONTROL_OPTIONS,
            key="model_inversion_controls",
            help=h("Model inversion can reconstruct sensitive training samples from model outputs (ML06).",
                   "Defences include output perturbation, access controls on the prediction API, and rate limiting."),
        )
    q_group_end()

    q_group_start(q("Explainability & drift", "Can you explain and monitor your model?"))
    c1, c2 = st.columns(2)
    with c1:
        st.selectbox(
            q("Feature attribution available",
              "Can your model explain which features drove a prediction (SHAP, LIME, integrated gradients)?"),
            YN_OPTIONS,
            key="feature_attribution_available",
            help=h("Lack of explainability prevents detection of bias, data poisoning effects, and shortcut learning (ML10).",
                   "SHAP values or LIME explanations help catch cases where the model learned the wrong features."),
        )
    with c2:
        st.selectbox(
            q("Drift monitoring",
              "Is the model monitored in production for data drift, concept drift, or distribution shift?"),
            YN_OPTIONS,
            key="ml_drift_monitoring",
            help=h("Models degrade silently under distribution shift — a key operational ML risk not covered by standard security scanners.",
                   "Tools: Evidently AI, WhyLogs, Alibi Detect."),
        )
    q_group_end()

    # ── Reinforcement Learning specific questions ──────────────────────────────
    if st.session_state.get("model_type") == "Reinforcement Learning System":
        q_group_start(q("Reinforcement Learning safety",
                        "Reward hacking, policy drift, and safe-RL controls"), color="orange")
        rl1, rl2, rl3 = st.columns(3)
        with rl1:
            st.radio(
                q("Reward function audited / red-teamed",
                  "Has the reward function been reviewed for exploitable shortcuts or Goodhart's Law failure modes?"),
                YN_OPTIONS, horizontal=True, key="rl_reward_hacking_tested",
                help=h(
                    "Reward hacking lets an agent maximise a proxy metric without achieving the real goal — often with dangerous side effects (OWASP ML04, ML08).",
                    "Could the agent exploit the reward function in an unintended way (e.g. score-farming, early termination exploits)?",
                ),
            )
        with rl2:
            st.radio(
                q("Policy / distribution-shift monitoring",
                  "Is the deployed policy monitored for behaviour degradation when the environment changes?"),
                YN_OPTIONS, horizontal=True, key="rl_policy_drift_monitoring",
                help=h(
                    "RL policies degrade silently under environment/distribution shift — standard drift monitors miss this because inputs look normal while behaviour diverges.",
                    "If the real-world environment shifts (new users, seasonality, adversarial inputs), will you detect the policy failing?",
                ),
            )
        with rl3:
            st.radio(
                q("Safe-RL / action constraints in place",
                  "Are safety constraints (shielding, constrained MDP, hard stop rules) enforced in the RL loop?"),
                YN_OPTIONS, horizontal=True, key="rl_safe_rl_constraints",
                help=h(
                    "Without hard action constraints, a compromised or drifted policy can take catastrophic irreversible actions (constrained MDP, safety shielding, formal verification).",
                    "Is there a hard stop that prevents the policy from taking dangerous actions even if rewards say to?",
                ),
            )
        q_group_end()

    # ── Edge AI / IoT specific questions ──────────────────────────────────────
    if st.session_state.get("model_type") == "Edge AI / IoT Model":
        q_group_start(q("Edge AI / IoT security",
                        "OTA integrity, physical adversarials, and on-device model protection"), color="teal")
        ea1, ea2, ea3 = st.columns(3)
        with ea1:
            st.radio(
                q("OTA update integrity verified",
                  "Are over-the-air model / firmware updates signed and integrity-checked before deployment?"),
                YN_OPTIONS, horizontal=True, key="edge_ota_update_security",
                help=h(
                    "Unsigned OTA updates are a supply-chain entry point: an attacker who intercepts the channel can push a backdoored model to millions of devices.",
                    "If you push model updates to devices, is the update signed? Can a device tell a tampered update from a real one?",
                ),
            )
        with ea2:
            st.radio(
                q("Physical adversarial / patch testing performed",
                  "Have you tested real-world physical adversarial patches, lighting changes, or sensor-spoofing?"),
                YN_OPTIONS, horizontal=True, key="edge_physical_adversarial",
                help=h(
                    "Physical adversarial attacks (stop-sign patches, IR-transparent clothes, LiDAR spoofing) bypass purely digital adversarial defences — edge/IoT models in the physical world must be tested in-environment.",
                    "Can someone stick a printed patch on an object and fool your edge camera / sensor model?",
                ),
            )
        with ea3:
            st.radio(
                q("Model weights encrypted on-device",
                  "Are model weights stored encrypted on the device to prevent extraction via physical access?"),
                YN_OPTIONS, horizontal=True, key="edge_model_encryption",
                help=h(
                    "Physical access to an edge device (stolen device, supply chain swap) can lead to model theft (ML05 / ML06) or white-box adversarial attack generation. Encrypt weights with device-bound keys.",
                    "If someone pulls the flash chip out of your device, can they steal and reverse-engineer your model?",
                ),
            )
        q_group_end()


def render_step_review(steps):
    _html(
        "<div class='atm-card'>"
        "<div class='atm-card-eyebrow'>Ready to analyze</div>"
        "<div class='atm-card-title'>Review &amp; confirm your setup</div>"
        "<div class='atm-card-subtitle'>"
        "Check the key settings below — edit anything that looks wrong, then click "
        "<strong>Generate threat report</strong>."
        "</div>"
        "</div>"
    )

    q_group_start("Your project")
    _html("<div style='font-size:0.78rem;color:#64748b;margin:2px 0 10px 0;'>"
          "Confirm your setup — these drive the findings. Edit anything wrong before generating.</div>")

    # Project name — editable
    _proj_name = (st.session_state.get("project_name") or "").strip()
    rn_col, _ = st.columns([2, 1])
    with rn_col:
        st.text_input(
            "Project name (shown in report header)",
            key="project_name",
            placeholder="e.g. Customer support chatbot",
        )
        if not _proj_name:
            _html(
                "<div style='font-size:0.75rem;color:#d97706;background:#fef9c3;"
                "border:1px solid #fde68a;border-radius:6px;padding:5px 10px;margin:-4px 0 8px 0;'>"
                "⚠️ Enter a project name — otherwise the report will show \"Untitled AI Project\".</div>"
            )

    # Read directly from session_state — never use selectbox here so stale
    # widget defaults can't overwrite what the user entered in earlier steps.
    _s = st.session_state
    def _val(key): return str(_s.get(key) or "—")
    def _rv_cell(label, value, accent="#2563eb"):
        return (
            f"<div style='background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;"
            f"padding:10px 14px;'>"
            f"<div style='font-size:0.63rem;font-weight:700;text-transform:uppercase;"
            f"letter-spacing:0.07em;color:#94a3b8;margin-bottom:4px;'>{label}</div>"
            f"<div style='font-size:0.88rem;font-weight:600;color:#1e293b;"
            f"white-space:nowrap;overflow:hidden;text-overflow:ellipsis;'>{value}</div>"
            f"</div>"
        )
    _html(
        "<div style='display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:6px 0 10px 0;'>"
        + _rv_cell("AI Type",        _val("ai_type"))
        + _rv_cell("Project Stage",  _val("project_stage"))
        + _rv_cell("Business Impact",_val("business_impact"))
        + _rv_cell("Model Source",   _val("model_source"))
        + _rv_cell("Exposure",       _val("exposure"))
        + _rv_cell("Access Control", _val("access_control"))
        + "</div>"
    )

    _html("<div style='font-size:0.75rem;color:#94a3b8;margin:4px 0 2px 0;'>"
          "To change any value, click ← Back and update the relevant step.</div>")
    q_group_end()



# ---------------------------------------------------------------------------
# Wizard orchestrator
# ---------------------------------------------------------------------------
STEP_RENDERERS = {
    "project":    render_step_project,
    "data":       render_step_data,
    "rag":        render_step_rag,
    "deployment": render_step_deployment,
    "security":   render_step_security,
    "governance": render_step_governance,
    "llm":        render_step_llm,
    "multimodal": render_step_multimodal,
    "finetune":   render_step_finetune,
    "agentic":    render_step_agentic,
    "mcp":        render_step_mcp,
    "classical_ml": render_step_classical_ml,
    "review":     lambda: None,  # handled inline
}


def render_wizard(steps, current_idx):
    step = steps[current_idx]
    total = len(steps)

    # Bug R2.2: scroll to the top of the page whenever the step changes so the
    # next step always starts from its top, not wherever the user last scrolled.
    # `st.markdown(<script>…)` is stripped by Streamlit, so we use the
    # streamlit.components.v1.html component — scripts there run in an iframe
    # and can still reach window.parent.document to scroll the host page.
    last_idx = st.session_state.get("_last_step_index")
    if last_idx != current_idx:
        st.session_state["_last_step_index"] = current_idx
        # include a nonce so the iframe re-mounts on every step change and
        # the script fires again even if the component was already cached.
        nonce = f"{current_idx}-{id(step)}"
        try:
            import streamlit.components.v1 as _components
            _components.html(
                f"""
                <div data-nonce="{nonce}" style="height:0;overflow:hidden;"></div>
                <script>
                (function() {{
                    function scrollTop() {{
                        try {{
                            var win = window.parent || window;
                            var doc = win.document || document;
                            if (typeof win.scrollTo === 'function') {{
                                win.scrollTo(0, 0);
                            }}
                            var sels = [
                                'section.main',
                                'section[data-testid="stMain"]',
                                'div[data-testid="stAppViewContainer"]',
                                'div[data-testid="stAppViewBlockContainer"]',
                                'main',
                                'html', 'body'
                            ];
                            sels.forEach(function(sel) {{
                                var el = doc.querySelector(sel);
                                if (el) {{
                                    if (typeof el.scrollTo === 'function') {{
                                        el.scrollTo(0, 0);
                                    }}
                                    el.scrollTop = 0;
                                }}
                            }});
                        }} catch (e) {{}}
                    }}
                    // Fire now and on a short timeout in case Streamlit has
                    // not yet finished painting when the iframe loads.
                    scrollTop();
                    setTimeout(scrollTop, 30);
                    setTimeout(scrollTop, 150);
                }})();
                </script>
                """,
                height=0,
            )
        except Exception:
            # Component API not available — fall back to st.markdown, which
            # at least gets rendered (script tag usually stripped but harmless).
            st.markdown(
                "<div style='display:none' data-scroll-top-nonce='" + nonce + "'></div>",
                unsafe_allow_html=True,
            )

    step_head(step, current_idx, total)

    # Set the current step colour so q_group_start() uses the right palette
    _CURRENT_STEP_COLOR["c"] = _STEP_COLORS.get(step["key"], "slate")
    # Reset the colour cycle so each category on this page gets its own hue
    reset_q_group_palette()

    renderer = STEP_RENDERERS.get(step["key"])
    if renderer:
        renderer()

    # Navigation row
    nav_left, nav_right = st.columns([1, 1])
    with nav_left:
        if current_idx == 0:
            st.button("← Back", key="nav_back", disabled=True, use_container_width=True)
        else:
            if st.button("← Back", key="nav_back", use_container_width=True):
                goto_step(-1)
                st.rerun()
    with nav_right:
        if current_idx == total - 1:
            # Last step — generate report directly, no review page
            if st.button("⚡ Generate threat report", key="nav_generate",
                         type="primary", use_container_width=True):
                st.session_state.report_requested = True
                st.rerun()
        else:
            if st.button("Next →", key="nav_next", type="primary", use_container_width=True):
                goto_step(1)
                st.rerun()


# ---------------------------------------------------------------------------
# Charts (every chart gets a unique plotly key)
# ---------------------------------------------------------------------------
def severity_pie(threats):
    counts = Counter(t["severity"] for t in threats)
    labels = [lbl for lbl in ["Critical", "High", "Medium", "Low"] if counts[lbl]]
    values = [counts[lbl] for lbl in labels]
    if not labels:
        return None
    fig = go.Figure(
        data=[go.Pie(
            labels=labels, values=values, hole=0.6,
            marker_colors=[SEVERITY_COLORS[lbl] for lbl in labels],
            textfont=dict(size=13),
        )]
    )
    fig.update_layout(
        title=dict(text="Severity Distribution", font=dict(size=14, color="#0b1220")),
        margin=dict(l=10, r=10, t=45, b=10),
        height=300, showlegend=True,
        legend=dict(orientation="h", y=-0.12),
        paper_bgcolor="rgba(0,0,0,0)",
    )
    return fig


def nist_radar(threats, title="NIST CIA + Abuse"):
    all_nist = []
    for t in threats:
        all_nist.extend(t["nist"])
    counts = Counter(all_nist)
    categories = ["Confidentiality", "Integrity", "Availability", "Abuse"]
    values = [counts.get(c, 0) for c in categories]
    if sum(values) == 0:
        return None
    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(
        r=values + [values[0]],
        theta=categories + [categories[0]],
        fill="toself",
        line=dict(color="#2563eb", width=2),
        fillcolor="rgba(37, 99, 235, 0.18)",
    ))
    fig.update_layout(
        title=dict(text=title, font=dict(size=14, color="#0b1220")),
        polar=dict(
            bgcolor="rgba(0,0,0,0)",
            radialaxis=dict(visible=True, range=[0, max(values) + 1],
                            gridcolor="#e2e8f0", linecolor="#e2e8f0"),
            angularaxis=dict(gridcolor="#e2e8f0", linecolor="#e2e8f0"),
        ),
        showlegend=False,
        margin=dict(l=25, r=25, t=50, b=25),
        height=320,
        paper_bgcolor="rgba(0,0,0,0)",
    )
    return fig


def _extract_mitre_id(mitre_str):
    """Extract base MITRE ATLAS technique IDs from a full string (normalised, no sub-technique suffix).
    'AML.T0051.000 – LLM Prompt Injection' → ['AML.T0051']
    'AML.T0049 | AML.T0054'               → ['AML.T0049', 'AML.T0054']
    """
    import re
    ids = []
    for part in str(mitre_str or "").split("|"):
        part = part.strip()
        # Match base technique ID only (AML.TNNNN) — strip sub-technique .NNN suffix
        m = re.match(r"(AML\.[A-Z]\d+)", part)
        if m:
            ids.append(m.group(1))
    return ids


def mitre_bar(threats):
    """Horizontal bar chart grouped by MITRE ATLAS technique with human-readable names."""
    counts: Counter = Counter()
    for t in threats:
        for mid in _extract_mitre_id(t.get("mitre", "")):
            if mid and mid != "N/A":
                counts[mid] += 1
    if not counts:
        return None
    ordered = sorted(counts.items(), key=lambda kv: kv[1])[-12:]   # bottom→top order for horizontal
    # Build readable labels: "AML.T0051 — Prompt Injection"
    labels = [
        f"{k} — {_MITRE_ATLAS_NAMES[k]}" if k in _MITRE_ATLAS_NAMES else k
        for k, _ in ordered
    ]
    values = [v for _, v in ordered]
    fig = go.Figure([go.Bar(
        x=values,
        y=labels,
        orientation="h",
        marker_color="#2563eb",
        marker_line_color="#1d4ed8",
        marker_line_width=0.6,
        text=[str(v) for v in values],
        textposition="outside",
        textfont=dict(size=11, color="#0b1220"),
    )])
    fig.update_layout(
        title=dict(text="MITRE ATLAS Technique Coverage", font=dict(size=14, color="#0b1220")),
        xaxis_title="Number of Findings",
        yaxis_title=None,
        margin=dict(l=20, r=40, t=48, b=30),
        height=max(280, len(ordered) * 36 + 80),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(gridcolor="#f1f5f9", dtick=1),
        yaxis=dict(tickfont=dict(size=11), automargin=True),
    )
    return fig


def severity_bar(threats):
    counts = Counter(t["severity"] for t in threats)
    order = ["Critical", "High", "Medium", "Low"]
    values = [counts.get(c, 0) for c in order]
    if sum(values) == 0:
        return None
    fig = go.Figure([go.Bar(
        x=order, y=values,
        marker_color=[SEVERITY_COLORS[c] for c in order],
        text=values, textposition="outside",
    )])
    fig.update_layout(
        title=dict(text="Findings by Severity", font=dict(size=14, color="#0b1220")),
        margin=dict(l=20, r=20, t=45, b=30),
        height=300,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        yaxis=dict(gridcolor="#f1f5f9"),
    )
    return fig


_KNOWN_REGIMES = [
    "GDPR", "HIPAA", "PCI DSS", "SOC 2", "ISO 27001",
    "NIST AI RMF", "EU AI Act", "CCPA",
]

def _extract_regime(compliance_str):
    """Extract short regime name from a full compliance article string.
    e.g. 'GDPR Art.5(1)(f) – ...' → 'GDPR'
         'NIST AI RMF – GOVERN 1.2' → 'NIST AI RMF'
    """
    for r in _KNOWN_REGIMES:
        if compliance_str.startswith(r):
            return r
    # Fallback: everything before first space/section marker
    return compliance_str.split(" ")[0].split("§")[0].rstrip(":").strip()


def compliance_bar(threats, inferred=None):
    """Pie chart of findings grouped by top-level compliance regime."""
    counts = Counter()
    for t in threats:
        seen_regimes = set()
        for c in (t.get("compliance") or []):
            if not c or c == "N/A":
                continue
            regime = _extract_regime(c)
            if regime not in seen_regimes:
                counts[regime] += 1
                seen_regimes.add(regime)
    for reg in (inferred or []):
        counts.setdefault(reg, 0)
    # Remove zero-count entries from the pie (they create ghost slices)
    counts = {k: v for k, v in counts.items() if v > 0}
    if not counts:
        return None
    labels = list(counts.keys())
    values = list(counts.values())
    palette = [
        "#0e7490", "#0369a1", "#1d4ed8", "#4f46e5",
        "#7c3aed", "#9333ea", "#c026d3", "#db2777",
        "#e11d48", "#ea580c",
    ]
    fig = go.Figure([go.Pie(
        labels=labels,
        values=values,
        hole=0.38,
        marker=dict(
            colors=[palette[i % len(palette)] for i in range(len(labels))],
            line=dict(color="#ffffff", width=2),
        ),
        textinfo="label+value",
        textfont=dict(size=12),
        insidetextorientation="radial",
        hovertemplate="<b>%{label}</b><br>Findings: %{value}<br>Share: %{percent}<extra></extra>",
    )])
    fig.update_layout(
        title=dict(text="Findings by Compliance Regime",
                   font=dict(size=14, color="#0b1220")),
        margin=dict(l=10, r=10, t=48, b=10),
        height=310,
        paper_bgcolor="rgba(0,0,0,0)",
        showlegend=True,
        legend=dict(font=dict(size=11), orientation="v", x=1.02, y=0.5),
    )
    return fig


# ---------------------------------------------------------------------------
# Findings and report
# ---------------------------------------------------------------------------
def severity_class(sev):
    return {
        "Critical": "atm-sev-critical", "High": "atm-sev-high",
        "Medium": "atm-sev-medium", "Low": "atm-sev-low",
    }.get(sev, "atm-sev-low")


def border_class(sev):
    return {
        "Critical": "atm-finding-critical", "High": "atm-finding-high",
        "Medium": "atm-finding-medium", "Low": "atm-finding-low",
    }.get(sev, "atm-finding-low")


def risk_score(severity_counts):
    return (
        severity_counts.get("Critical", 0) * 10
        + severity_counts.get("High", 0) * 6
        + severity_counts.get("Medium", 0) * 3
        + severity_counts.get("Low", 0)
    )


# ---------------------------------------------------------------------------
# Bug 3: "How to test this threat" — shown to Security persona only.
# Keyed on OWASP IDs so a single rule works for many threat names.
# ---------------------------------------------------------------------------
_TEST_GUIDANCE_BY_OWASP = {
    # OWASP LLM Top 10 (2025)
    "LLM01": {
        "tools": "Garak, PyRIT, promptfoo, Rebuff, Microsoft PyRIT",
        "steps": [
            "Run automated prompt-injection test suites (Garak --probes prompt_injection; PyRIT AttackStrategy=PromptInjection).",
            "Attempt direct overrides (\"ignore previous instructions…\") and indirect injection via retrieved docs / tool output.",
            "Verify injected instructions do NOT change the system prompt, tools invoked, or data returned.",
        ],
    },
    "LLM02": {
        "tools": "promptfoo red-team, custom regex scrapers, Presidio, truffleHog, PyRIT",
        "steps": [
            "Ask the model to repeat system prompt, training data, prior-session content, or secrets.",
            "Probe for memorized PII/PHI/credentials using canary strings inserted during fine-tuning.",
            "Scan outputs with a DLP / Presidio pipeline and confirm leaks are blocked before delivery.",
        ],
    },
    "LLM03": {
        "tools": "Trivy, Grype, Syft, ModelScan, Protect AI Huntr, pip-audit, Sigstore/cosign",
        "steps": [
            "Run SBOM/ML-BOM scans on models, weights, adapters, and Python deps.",
            "Verify signatures / checksums of pulled models (cosign verify or hub trust policies).",
            "Fuzz loaders with malformed model files (pickle, safetensors, GGUF) to check sandboxing.",
        ],
    },
    "LLM04": {
        "tools": "IBM ART, CleverHans, custom canary-record tests",
        "steps": [
            "Insert known poisoned samples into a retraining pipeline and verify detection/rejection.",
            "Compare model behavior on clean-vs-tainted eval sets for targeted drift.",
            "Review data-ingestion provenance and reproducibility of training runs.",
        ],
    },
    "LLM05": {
        "tools": "Burp Suite, ZAP, XSS Hunter, SSRFmap, sqlmap, custom fuzzers",
        "steps": [
            "Ask the model to emit payloads (XSS, SQL, shell, SSRF) and trace where the output lands.",
            "Test HTML/Markdown/JSON escaping in the downstream renderer / API / executor.",
            "Confirm no raw model output goes to code-exec, DB writes, or DOM without sanitisation.",
        ],
    },
    "LLM06": {
        "tools": "PyRIT ActionChains, agentic red-team harnesses, MCP inspector",
        "steps": [
            "Craft prompts that trick the model into invoking destructive tools without user intent.",
            "Verify human-approval / guard-rails fire on write/send/delete actions.",
            "Exercise rate / scope limits and confirm the agent cannot escalate privileges across tools.",
        ],
    },
    "LLM07": {
        "tools": "Garak system_prompt_leak, promptfoo, manual jailbreak corpora",
        "steps": [
            "Use extraction prompts (\"print your instructions verbatim\", multilingual, base64) to probe the system prompt.",
            "Attempt indirect leaks via tool-call parameters, error messages, and trace output.",
            "Confirm any secret/policy in the system prompt is moved to config / vault instead.",
        ],
    },
    "LLM08": {
        "tools": "Milvus security benchmarks, custom embedding-inversion harnesses, Vec2Text",
        "steps": [
            "Attempt cross-tenant retrieval with a low-privileged user to verify isolation.",
            "Run embedding-inversion attacks (Vec2Text) on a sample of your vectors.",
            "Inject malicious chunks and verify retrieval-time filtering strips instructions.",
        ],
    },
    "LLM09": {
        "tools": "TruthfulQA, RAGAS, DeepEval, custom grounding evals",
        "steps": [
            "Run a hallucination eval suite covering your domain (RAGAS faithfulness, groundedness).",
            "Force over-long / adversarial context and confirm the model cites or abstains.",
            "Manually review a sample of outputs for confident-but-wrong claims.",
        ],
    },
    "LLM10": {
        "tools": "k6, Locust, Artillery, gatling, Prometheus cost dashboards",
        "steps": [
            "Load-test with long prompts, recursive tool calls, and streaming token floods.",
            "Verify per-user / per-feature token quotas, timeouts, and max_tokens ceilings fire.",
            "Simulate wallet-drain attacks and confirm cost alerts trigger.",
        ],
    },
    # OWASP ML Top 10
    "ML01": {
        "tools": "IBM ART (FGSM, PGD, DeepFool), CleverHans, TextAttack",
        "steps": [
            "Generate adversarial examples against the deployed classifier and measure misclassification.",
            "Test defences (adversarial training, input transformation, detector).",
        ],
    },
    "ML02": {
        "tools": "Custom poisoning harness, TrojAI, Adversa AI Red Team toolkit",
        "steps": [
            "Inject poisoned samples labelled consistent with attacker intent and retrain.",
            "Measure post-train behavior on the trigger pattern and verify anomaly detection.",
        ],
    },
    "ML03": {
        "tools": "IBM ART MIFace, custom inversion scripts",
        "steps": [
            "Query the model repeatedly to reconstruct training examples for specific classes.",
            "Verify output-smoothing, differential privacy, or access limits mitigate reconstruction.",
        ],
    },
    "ML04": {
        "tools": "IBM ART MembershipInferenceBlackBox",
        "steps": [
            "Train a shadow model and use confidence scores to distinguish member vs. non-member records.",
            "Confirm DP-noise, output temperature, or rate limits defeat the attack.",
        ],
    },
    "ML05": {
        "tools": "CloneAttack, ActiveThief, custom query harvesters",
        "steps": [
            "Query the model with a large synthetic distribution, train a surrogate, compare fidelity.",
            "Verify rate-limits, watermarking, or output perturbation reduce extraction success.",
        ],
    },
    "ML06": {
        "tools": "ModelScan, ProtectAI Huntr, Sigstore, pip-audit, Trivy",
        "steps": [
            "Scan model files (pickle, safetensors) for embedded payloads.",
            "Verify signing of model artifacts and dependency CVEs before deployment.",
        ],
    },
    # OWASP Agentic (ASI) Top 10
    "ASI01": {
        "tools": "PyRIT agent harnesses, manual goal-hijack corpora, LLM Guard",
        "steps": [
            "Run goal-hijack prompts that try to replace the agent's objective mid-plan.",
            "Verify the planner rejects out-of-scope sub-goals and logs the attempt.",
        ],
    },
    "ASI02": {
        "tools": "MCP Inspector, custom tool-fuzzers, Burp for outbound calls",
        "steps": [
            "Feed the agent tool-argument inputs that mix commands, SSRF, and path traversal.",
            "Verify tool schemas, allow-lists, and per-tool rate/cost limits.",
        ],
    },
    "ASI03": {
        "tools": "IAM policy simulators, OPA / Rego tests, scoped-token checks",
        "steps": [
            "Confirm the agent acts with the caller's identity, not a shared super-user.",
            "Attempt confused-deputy escalations across tool calls and check audit logs.",
        ],
    },
    "ASI05": {
        "tools": "gVisor, Firecracker, seccomp-bpf tests, container escape harnesses",
        "steps": [
            "Ask the agent to run shell / Python and verify execution is inside the sandbox.",
            "Try network, filesystem, and syscall escape payloads and confirm they fail.",
        ],
    },
    "ASI06": {
        "tools": "Custom memory-poisoning harnesses, signed-memory proofs",
        "steps": [
            "Plant false facts in long-term memory and observe later reasoning.",
            "Verify memory integrity checks, TTL, and per-user scoping.",
        ],
    },
    "ASI07": {
        "tools": "mTLS test harness, JWS message-signing verifier, Wireshark",
        "steps": [
            "Spoof messages between agents and confirm authentication rejects them.",
            "Verify all inter-agent traffic is integrity-protected and replay-resistant.",
        ],
    },
    "ASI10": {
        "tools": "Kill-switch drills, runtime budget / step-limit tests",
        "steps": [
            "Force the agent into a loop and confirm step/cost/time ceilings halt it.",
            "Verify operators can kill a running agent and all actions are reversible/audited.",
        ],
    },
    # OWASP MCP Top 10
    "MCP01": {
        "tools": "truffleHog, gitleaks, Vault audit logs, scoped-token rotation tests",
        "steps": [
            "Search code / logs / memory dumps for long-lived MCP tokens.",
            "Verify short-lived tokens, per-user scoping, and revocation on logout.",
        ],
    },
    "MCP02": {
        "tools": "OPA/Rego policy tests, MCP Inspector",
        "steps": [
            "Call tools outside the user's declared scope and confirm authorisation denies them.",
            "Verify humans approve destructive actions with full argument visibility.",
        ],
    },
    "MCP03": {
        "tools": "Schema-hash monitor, MCP Inspector, diff tooling",
        "steps": [
            "Change a tool's description on the server and verify the client alerts / blocks.",
            "Check for hidden instructions inside tool descriptions or parameter docstrings.",
        ],
    },
    "MCP05": {
        "tools": "Burp Suite, ZAP, command-injection fuzzers, seccomp tests",
        "steps": [
            "Send shell-metachar / traversal payloads to every MCP tool parameter.",
            "Verify sandboxing and argument validation reject dangerous inputs.",
        ],
    },
    "MCP07": {
        "tools": "Postman, mitmproxy, OAuth / OIDC test harness",
        "steps": [
            "Call MCP endpoints with missing, expired, and wrong-audience tokens.",
            "Verify mTLS / TLS, session binding, and replay protection on remote transports.",
        ],
    },
}


def _test_plan_html(threat):
    """Return HTML for a 'how to test this threat' block — Security persona ONLY.
    Returns empty string immediately when in Developer mode."""
    if is_developer_mode():
        return ""
    owasp = str(threat.get("owasp", "") or "")
    picked = None
    for part in owasp.split("|"):
        code = part.strip().split(":", 1)[0].strip()
        if code in _TEST_GUIDANCE_BY_OWASP:
            picked = _TEST_GUIDANCE_BY_OWASP[code]
            break
    if not picked:
        return ""
    steps_html = "".join(f"<li>{s}</li>" for s in picked["steps"])
    return (
        f"<div class='atm-test-plan'>"
        f"<strong>How to test (security persona):</strong>"
        f"<div style='margin-top:2px;'><strong>Tools:</strong> {picked['tools']}</div>"
        f"<ul>{steps_html}</ul>"
        f"</div>"
    )


# Bug R2.6: developer-persona "In short" / "What to do in code" block per OWASP
# family. Keeps the technical description intact but adds a plain-English and
# code-focused summary on top, so the developer sees clearly *what changes in
# their codebase*, not just the standards language.
_DEV_SHORT_BY_OWASP = {
    "LLM01": {
        "plain": "A user can trick your LLM by hiding instructions in their prompt or in content you pass to the model. The model then does what the attacker wrote instead of what you wanted.",
        "code": "Don't concatenate untrusted text straight into the prompt. Keep a fixed system prompt, pass user text as a clearly separated user message, and strip/flag instruction-like phrases before they reach the model.",
    },
    "LLM02": {
        "plain": "The model can accidentally repeat sensitive things it saw — training data, system prompt, or another user's content — back to the caller.",
        "code": "Don't put secrets or PII in the system prompt. Filter model output through a PII/secret scanner before returning it. In RAG, filter retrieved docs by the caller's identity before sending them to the model.",
    },
    "LLM03": {
        "plain": "Your model or one of its dependencies could come from a place you don't fully trust. An attacker who gets into that supply chain can change what your model does.",
        "code": "Pin model and package versions. Verify checksums/signatures on pull. Run dependency and model scanners in CI. Don't auto-update production models without a review gate.",
    },
    "LLM04": {
        "plain": "If an attacker can poison what the model learns from (training data, fine-tune set, feedback), they can make the model behave badly on demand.",
        "code": "Treat training/feedback data like any user input: validate it, log where it came from, and keep clean and dirty datasets versioned so you can roll back.",
    },
    "LLM05": {
        "plain": "The model's output can contain HTML, SQL, shell, or URLs. If your code pastes that straight into a browser, database, or shell, you've just given the model permission to attack your own systems.",
        "code": "Treat model output as untrusted input on the way out: HTML-escape before rendering, parameterize SQL, use allowlists for URLs, and never send model output straight to a shell or eval.",
    },
    "LLM06": {
        "plain": "Your agent can call tools (send email, run code, change data). If it follows a malicious instruction, it performs the action for real.",
        "code": "Scope each tool narrowly, require user approval for destructive actions, apply per-tool rate limits, and log every tool call so you can audit what happened.",
    },
    "LLM07": {
        "plain": "Your system prompt often has rules or secrets. Attackers can usually get the model to print it back.",
        "code": "Never put credentials or proprietary policy in the system prompt. Pull those from config at runtime. Assume the system prompt will eventually leak.",
    },
    "LLM08": {
        "plain": "Your vector DB can leak across tenants, or an attacker can plant poisoned chunks that your RAG pipeline later retrieves.",
        "code": "Tag every embedding with owner/tenant, filter on retrieval, and scan newly added chunks for injection patterns before indexing.",
    },
    "LLM09": {
        "plain": "The model will sometimes make things up confidently. In a serious product, that's a real liability.",
        "code": "Add a hallucination eval to CI, cite sources in RAG answers, let the model say 'I don't know', and surface a confidence signal to the UI.",
    },
    "LLM10": {
        "plain": "Attackers can send expensive prompts in a loop and drain your budget or slow the system for everyone else.",
        "code": "Enforce per-user/per-key rate limits, cap max_tokens and tool-call depth, set a hard cost budget with an alert, and reject obviously abusive input patterns early.",
    },
    "ML01": {
        "plain": "A small, crafted change to the input can make your classifier give the wrong answer on purpose.",
        "code": "Add adversarial examples to your eval set, consider input transforms/detection, and monitor for unusual prediction patterns in production.",
    },
    "ML02": {
        "plain": "Bad training data lets an attacker teach your model a backdoor that only they know how to trigger.",
        "code": "Version and review training data, add anomaly detection on new batches, and keep a clean eval set you re-run after every retrain.",
    },
    "ML03": {
        "plain": "If the model responds to queries about specific inputs, an attacker can recover training data or even reconstruct records.",
        "code": "Use differential privacy or limit confidence-score exposure. Rate-limit probing queries and alert on patterns that look like membership-inference attacks.",
    },
    "ML04": {
        "plain": "An attacker can query your model enough times to copy it.",
        "code": "Rate-limit predictions, watermark outputs, and add anomaly detection for suspicious query patterns.",
    },
    "ML05": {
        "plain": "The model's output format can be abused — raw bytes, serialized pickles, unvalidated JSON — to attack downstream systems.",
        "code": "Return strict, typed responses (Pydantic/JSON Schema). Never deserialize untrusted pickles. Validate shape and type before any downstream use.",
    },
    "ML06": {
        "plain": "A tampered model file or dependency is enough to ship an attacker's code alongside yours.",
        "code": "Require signed models, run SCA and model scanners (ModelScan, Trivy) in CI, and block unknown sources at the loader.",
    },
    "ASI01": {
        "plain": "An attacker nudges the agent off its real goal (\"forget the user's task, do this instead\").",
        "code": "Restate the original goal on every planning step, cross-check planned actions against it, and require approval when the plan drifts.",
    },
    "ASI02": {
        "plain": "The agent calls tools more freely than it should — wrong tool, wrong scope, wrong data.",
        "code": "Give every tool a tight allowlist of arguments, require human approval for destructive operations, and log every call immutably.",
    },
    "ASI03": {
        "plain": "Long-running agents carry memory; that memory can be poisoned so the agent later misbehaves on its own.",
        "code": "Treat memory entries as untrusted, namespace them per session/user, and validate on read — not only on write.",
    },
    "MCP01": {
        "plain": "An MCP server it talks to can be impersonated, or its schema changed on the fly.",
        "code": "Pin server identities and tool schemas, verify signatures on connect, and refuse silent schema changes.",
    },
    "MCP03": {
        "plain": "A malicious MCP tool description can itself carry prompt injection (\"tool poisoning\").",
        "code": "Sanitize tool descriptions as untrusted input before showing them to the planner, and allowlist the tools your agent is allowed to load.",
    },
    "MCP05": {
        "plain": "A tool that runs locally can be coaxed into running shell / file / network operations you did not intend.",
        "code": "Sandbox tool execution (container/OS/seccomp), drop privileges, and narrow filesystem + network egress.",
    },
    "MCP07": {
        "plain": "Without proper auth, any caller can use an MCP tool as if they were you.",
        "code": "Require scoped tokens on every call, bind them to the user and tenant, and rotate secrets with a vault — never hardcode.",
    },
}


def _dev_short_html(threat):
    """Return HTML for the developer-persona 'in short + code action' block."""
    owasp = str(threat.get("owasp", "") or "")
    picked = None
    for part in owasp.split("|"):
        code = part.strip().split(":", 1)[0].strip()
        if code in _DEV_SHORT_BY_OWASP:
            picked = _DEV_SHORT_BY_OWASP[code]
            break
    if not picked:
        return ""
    return (
        "<div class='atm-dev-short'>"
        "<strong>In short (developer):</strong> "
        f"{picked['plain']}"
        "<div style='margin-top:6px;'><strong>What to change in code:</strong> "
        f"{picked['code']}</div>"
        "</div>"
    )


def _confidence_badge(conf):
    colors = {"High": ("#166534", "#dcfce7"), "Medium": ("#92400e", "#fef9c3"), "Low": ("#1e40af", "#dbeafe")}
    fg, bg = colors.get(conf, ("#374151", "#f3f4f6"))
    return (f"<span style='font-size:0.7rem;font-weight:700;color:{fg};background:{bg};"
            f"padding:2px 7px;border-radius:99px;margin-left:6px;'>{conf} confidence</span>")


def format_finding(f, persona):
    """Return a persona-filtered view of a finding dict.

    Developer  → plain-language subset (title, severity, goal, reason, mitigation, quick_win).
    Security   → full finding dict unchanged.
    """
    if persona == "Developer":
        return {
            "title":      f.get("title") or f.get("threat", ""),
            "severity":   f.get("severity", ""),
            "goal":       f.get("attacker_goal", ""),
            "reason":     (f.get("reason") or "")[:150],
            "mitigation": f.get("mitigation", ""),
            "quick_win":  f.get("quick_win", ""),
            # pass-through fields render_threat_card always needs
            "id":         f.get("id", ""),
            "threat":     f.get("title") or f.get("threat", ""),
            "owasp":      "",          # hidden in developer mode
            "mitre":      "",          # hidden in developer mode
            "attack_path": [],         # hidden in developer mode
            "confidence": f.get("confidence", ""),
            "attacker_goal": f.get("attacker_goal", ""),
            "description": f.get("abuse_case") or f.get("impact_story") or f.get("description", ""),
            "abuse_case":  f.get("abuse_case") or f.get("impact_story", ""),
            "impact_story": f.get("impact_story", ""),
            "nist":        [],
            "compliance":  [],
            "how_to_test": "",
            "root_cause":  f.get("root_cause", ""),
            "risk_value":  f.get("risk_value", 0),
            "related_findings": f.get("related_findings", []),
            "supporting_findings": f.get("supporting_findings", []),
            "threat_category": f.get("threat_category", ""),
            "is_top_priority": f.get("is_top_priority", False),
            "is_graph_chain":  f.get("is_graph_chain", False),
            "finding_type":      f.get("finding_type", "THREAT"),
            "affected_capability": f.get("affected_capability", "any"),
            "variants":          f.get("variants", []),
        }
    return f


def render_threat_card(threat, index, chain=False):
    sev      = threat["severity"]
    conf     = threat.get("confidence", "")
    border   = border_class(sev)
    sev_cls  = severity_class(sev)
    priority_badge = (
        "<span style='font-size:0.7rem;font-weight:700;color:#fff;background:#7c3aed;"
        "padding:2px 7px;border-radius:99px;margin-left:6px;'>Top priority</span>"
        if threat.get("is_top_priority") else ""
    )
    chain_tag   = "<span class='atm-chain-tag'>Chained</span>" if chain else ""
    owasp_pills = render_owasp_pills(threat.get("owasp", ""))
    # MITRE pill only shown in Security Engineer persona
    mitre_pill  = render_mitre_pill(threat.get("mitre", "")) if not is_developer_mode() else ""
    cat_label   = threat.get("threat_category", "")
    cat_pill    = (f"<span style='font-size:0.68rem;color:#64748b;background:#f1f5f9;"
                   f"padding:2px 7px;border-radius:4px;margin-left:6px;'>{cat_label}</span>"
                   if cat_label else "")
    # Attacker goal badge — shown for both personas
    _goal       = threat.get("attacker_goal", "")
    _goal_colors = {
        "Data Exfiltration":    ("#1e40af", "#dbeafe"),
        "Privilege Escalation": ("#6b21a8", "#f3e8ff"),
        "System Manipulation":  ("#9a3412", "#ffedd5"),
        "Cost Exhaustion":      ("#991b1b", "#fee2e2"),
        "Model Theft":          ("#065f46", "#d1fae5"),
    }
    _gc, _gbg = _goal_colors.get(_goal, ("#374151", "#f3f4f6"))
    goal_pill   = (
        f"<span style='font-size:0.68rem;font-weight:600;color:{_gc};background:{_gbg};"
        f"padding:2px 8px;border-radius:99px;margin-left:6px;'>Goal: {_goal}</span>"
        if _goal else ""
    )
    header = (
        f"<div class='atm-finding-row'>"
        f"<span class='atm-sev {sev_cls}'>{sev}</span>"
        f"{_confidence_badge(conf)}"
        f"{priority_badge}"
        f"{owasp_pills}"
        f"{mitre_pill}"
        f"{goal_pill}"
        f"{chain_tag}"
        f"{cat_pill}"
        f"</div>"
        f"<div class='atm-finding-title'>{index}. {threat['threat']}</div>"
    )

    with st.expander(f"{index}. [{sev}] {threat['threat']}",
                     expanded=(sev in ("Critical", "High") or chain or bool(threat.get("is_top_priority")))):
        _html(f"<div class='atm-finding {border}'>{header}</div>")
        st.markdown(f"**Reason:** {threat['reason']}")

        if chain:
            rc = threat.get("reason_components") or []
            if rc:
                evidence_items = "".join(f"<li>{item}</li>" for item in rc)
                _html(
                    "<div class='atm-chain-evidence'>"
                    "<div class='atm-chain-evidence-title'>Why this chain fires</div>"
                    f"<ul>{evidence_items}</ul></div>"
                )

        if is_developer_mode():
            # ── DEVELOPER PERSONA — plain language only ────────────────────────
            # Why this matters (plain-language abuse case)
            _why = threat.get("abuse_case") or threat.get("impact_story") or threat.get("description", "")
            _html(
                f"<div style='background:#f8fafc;border-left:3px solid #6366f1;"
                f"padding:9px 13px;border-radius:4px;margin:6px 0;font-size:0.9rem;'>"
                f"<strong>Why this matters:</strong> {_why}</div>"
            )
            # Mitigation
            st.markdown(f"**What to do:** {threat['mitigation']}")
            # Quick win (inline, prominent)
            _qw = threat.get("quick_win", "")
            if _qw:
                _html(
                    f"<div style='background:#f0fdf4;border-left:3px solid #16a34a;"
                    f"padding:8px 12px;border-radius:4px;margin:6px 0;font-size:0.88rem;'>"
                    f"<strong>Quick win:</strong> {_qw}</div>"
                )
            # Attack path — 1-line summary only (no step-by-step)
            _ap = threat.get("attack_path") or []
            if _ap:
                # Build node-level summary: first node → middle → last
                _nodes = _ap if len(_ap) <= 4 else [_ap[0], "...", _ap[-1]]
                _summary = " → ".join(
                    s.split("—")[-1].strip() if "—" in s else s
                    for s in _nodes
                )
                _html(
                    f"<div style='font-size:0.82rem;color:#64748b;margin:4px 0;'>"
                    f"<strong>Attack summary:</strong> {_summary}</div>"
                )
            # Related issues cluster
            _related = threat.get("supporting_findings") or []
            if _related:
                _titles = [r.replace("_", " ").title() for r in _related]
                _html(
                    "<div style='margin:6px 0 2px 0;font-size:0.8rem;color:#64748b;'>"
                    f"<strong>Related issues (same root cause):</strong> "
                    + " · ".join(_titles) + "</div>"
                )
            # Dev code-action block (OWASP lookup)
            dev_html = _dev_short_html(threat)
            if dev_html:
                _html(dev_html)

        else:
            # ── SECURITY ENGINEER PERSONA — full technical detail ──────────────
            st.markdown(f"**Description:** {threat['description']}")
            st.markdown(f"**Mitigation:** {threat['mitigation']}")

            # Abuse case + Quick win (side by side)
            abuse_case = threat.get("abuse_case") or threat.get("impact_story", "")
            quick_win  = threat.get("quick_win", "")
            if abuse_case or quick_win:
                ac_col, qw_col = st.columns([1.1, 1])
                with ac_col:
                    if abuse_case:
                        _html(
                            f"<div style='background:#fef9ec;border-left:3px solid #d97706;"
                            f"padding:8px 12px;border-radius:4px;margin:6px 0;font-size:0.88rem;'>"
                            f"<strong>Abuse case:</strong> {abuse_case}</div>"
                        )
                with qw_col:
                    if quick_win:
                        _html(
                            f"<div style='background:#f0fdf4;border-left:3px solid #16a34a;"
                            f"padding:8px 12px;border-radius:4px;margin:6px 0;font-size:0.88rem;'>"
                            f"<strong>Quick win:</strong> {quick_win}</div>"
                        )

            # Full attack path (step-by-step)
            if threat.get("attack_path"):
                st.markdown("**Attack path:**")
                for i, step in enumerate(threat["attack_path"], start=1):
                    st.markdown(f"{i}. {step}")

            # NIST impact categories (compliance details live in the Compliance tab)
            nist_values = [n for n in (threat.get("nist") or []) if n]
            if nist_values:
                st.markdown(f"**NIST impact:** `{', '.join(nist_values)}`")

            # Related findings (deduplication cluster)
            related = threat.get("supporting_findings") or []
            if related:
                _titles = [r.replace("_", " ").title() for r in related]
                bullet_html = "".join(f"<li style='font-size:0.82rem;'>{t}</li>" for t in _titles)
                _html(
                    "<div style='margin:8px 0 4px 0;'>"
                    "<strong style='font-size:0.85rem;color:#374151;'>Related issues "
                    "(same root cause — one fix resolves all):</strong>"
                    f"<ul style='margin:4px 0 0 0;padding-left:18px;color:#64748b;'>{bullet_html}</ul></div>"
                )

            # How to test — Security Engineer persona: button opens lightbox dialog
            if not is_developer_mode():
                how_to_test = threat.get("how_to_test", "")
                plan_html   = _test_plan_html(threat)
                # Bug fix: rules engine never sets adversarial_test_tools on the
                # threat dict — surface the user's session-state list of tools so
                # the testing guide actually shows what they have available.
                _adv_tools  = (
                    threat.get("adversarial_test_tools")
                    or st.session_state.get("adversarial_test_tools")
                    or []
                )

                if how_to_test or plan_html or _adv_tools:
                    # Use threat id (stable, unique per finding) + chain flag to
                    # guarantee uniqueness across both the main list and the
                    # attack-path list which share the same index counter.
                    _ctx     = "chain" if chain else "main"
                    _tid     = threat.get("id") or threat.get("threat", "")
                    _dlg_key = f"_show_test_{_ctx}_{index}_{_tid}"
                    if st.button(
                        "🔍 How to test",
                        key=f"btn_test_{_ctx}_{index}_{_tid}",
                        help="Open step-by-step testing guide with tools",
                    ):
                        st.session_state[_dlg_key] = True

                    if st.session_state.get(_dlg_key):
                        _threat_name = threat.get("threat", "this threat")
                        _threat_reason = (threat.get("reason") or "").strip()
                        # Build threat-specific example block
                        if how_to_test:
                            _ex_steps = "".join(
                                f"<li style='margin:4px 0;'>{ln.strip()}</li>"
                                for ln in how_to_test.strip().splitlines()
                                if ln.strip()
                            )
                            _ex_expected = (
                                "<li>Data validation or access control blocks the action</li>"
                                "<li>System returns a filtered or safe response</li>"
                                "<li>A security alert or audit log entry is generated</li>"
                            )
                            _ex_failure = (
                                "<li>Input accepted and processed without restriction</li>"
                                "<li>No validation, filtering, or control applied</li>"
                                "<li>No alert, log, or monitoring signal generated</li>"
                            )
                        else:
                            _ex_steps = "<li>Simulate the threat condition using synthetic/benign data</li><li>Pass through the actual system workflow</li><li>Observe whether controls are applied</li>"
                            _ex_expected = "<li>System detects and blocks or sanitizes the input</li><li>A log or alert is generated</li>"
                            _ex_failure = "<li>System processes the input without restriction</li><li>No alert or log is generated</li>"

                        _tools_section = ""
                        if _adv_tools:
                            _tool_pills = "".join(
                                f"<span style='display:inline-block;background:#eff6ff;"
                                f"color:#1d4ed8;border:1px solid #bfdbfe;"
                                f"font-size:0.75rem;padding:2px 10px;border-radius:99px;"
                                f"margin:2px 3px;font-weight:600;'>{t}</span>"
                                for t in _adv_tools
                            )
                            _tools_section = (
                                f"<div style='margin-top:4px;font-size:0.8rem;color:#374151;'>"
                                f"Relevant tools for this threat: {_tool_pills}</div>"
                            )

                        def _sec(icon, title, bg, border, content_html):
                            return (
                                f"<div style='margin:10px 0;border:1px solid {border};"
                                f"border-radius:8px;overflow:hidden;'>"
                                f"<div style='background:{bg};padding:6px 14px;"
                                f"font-size:0.72rem;font-weight:800;text-transform:uppercase;"
                                f"letter-spacing:0.07em;color:{border};'>{icon} {title}</div>"
                                f"<div style='padding:10px 14px;font-size:0.82rem;"
                                f"color:#1e293b;line-height:1.65;background:#fff;'>"
                                f"{content_html}</div></div>"
                            )

                        _guide_html = (
                            # ── Outer card ──
                            "<div style='border:1.5px solid #2563eb;border-radius:12px;"
                            "overflow:hidden;margin:10px 0;box-shadow:0 2px 12px rgba(37,99,235,0.08);'>"
                            # Header
                            "<div style='background:linear-gradient(90deg,#1e40af,#2563eb);"
                            "padding:12px 18px;display:flex;align-items:center;gap:10px;'>"
                            "<span style='font-size:1.1rem;'>🔍</span>"
                            "<div>"
                            "<div style='font-size:0.88rem;font-weight:800;color:#fff;"
                            "letter-spacing:0.04em;text-transform:uppercase;'>How to Test — Standardized Format</div>"
                            f"<div style='font-size:0.77rem;color:#bfdbfe;margin-top:2px;'>"
                            f"Threat: {_threat_name}</div>"
                            "</div></div>"
                            # Body
                            "<div style='padding:12px 14px;background:#f8fafc;'>"
                            + _sec("🎯", "Objective", "#eff6ff", "#2563eb",
                                   "Validate whether the identified threat is effectively mitigated by existing security controls. "
                                   "This is a <strong>defensive validation exercise</strong>, not an exploitation guide.")
                            + _sec("⚠️", "Preconditions", "#fff7ed", "#ea580c",
                                   "<ul style='margin:0;padding-left:18px;'>"
                                   "<li>Testing must be performed in a <strong>controlled environment</strong> (staging, sandbox, or isolated setup).</li>"
                                   "<li>Tester assumes the role of an external or internal attacker based on system exposure.</li>"
                                   "<li>No real production data or systems should be impacted.</li>"
                                   "</ul>")
                            + _sec("🔬", "Test Methodology", "#eef2ff", "#4f46e5",
                                   "<ol style='margin:0;padding-left:18px;'>"
                                   "<li style='margin-bottom:6px;'><strong>Simulate Attack Condition (Safely)</strong> — Introduce inputs or actions that represent the threat. Use benign or synthetic data. Do not execute real harmful payloads.</li>"
                                   "<li style='margin-bottom:6px;'><strong>Trigger System Behavior</strong> — Pass the simulated input through the actual system: API endpoints, model inference, training pipelines, retrieval systems, or agent/tool interactions.</li>"
                                   "<li><strong>Observe Control Enforcement</strong> — Validate whether controls are applied: input validation, access control checks, output filtering, rate limiting, data provenance checks, model integrity controls.</li>"
                                   "</ol>")
                            + _sec("✅", "Expected Outcomes", "#f0fdf4", "#16a34a",
                                   "At least one of the following must occur:<br/>"
                                   "<ul style='margin:4px 0 0 0;padding-left:18px;'>"
                                   "<li>The action is <strong>blocked</strong></li>"
                                   "<li>The input is <strong>sanitized or rejected</strong></li>"
                                   "<li>The system returns a <strong>safe/filtered response</strong></li>"
                                   "<li>A <strong>security alert or log</strong> is generated</li>"
                                   "<li>The action requires <strong>authorization or human approval</strong></li>"
                                   "</ul>")
                            + _sec("✖", "Failure Conditions (Control Gap)", "#fef2f2", "#dc2626",
                                   "A finding is confirmed if:<br/>"
                                   "<ul style='margin:4px 0 0 0;padding-left:18px;'>"
                                   "<li>The system processes the unsafe input <strong>without restriction</strong></li>"
                                   "<li>No validation, filtering, or control is applied</li>"
                                   "<li>No alert, log, or monitoring signal is generated</li>"
                                   "<li>The system performs <strong>unintended or unsafe actions</strong></li>"
                                   "</ul>")
                            + _sec("📋", "Evidence Collection", "#f1f5f9", "#475569",
                                   "<ul style='margin:0;padding-left:18px;'>"
                                   "<li>Request / response samples</li>"
                                   "<li>Logs (application, model, audit, SIEM)</li>"
                                   "<li>Alerts or monitoring signals</li>"
                                   "<li>Screenshots or outputs demonstrating behavior</li>"
                                   "<li>Model outputs or decision results</li>"
                                   "</ul>")
                            # Threat-specific example
                            + "<div style='margin:10px 0;border:1px solid #d97706;"
                            "border-radius:8px;overflow:hidden;'>"
                            "<div style='background:#fffbeb;padding:6px 14px;"
                            "font-size:0.72rem;font-weight:800;text-transform:uppercase;"
                            "letter-spacing:0.07em;color:#92400e;'>💡 Example — "
                            + _threat_name
                            + "</div>"
                            "<div style='padding:10px 14px;font-size:0.82rem;color:#1e293b;"
                            "line-height:1.65;background:#fff;'>"
                            + (f"<div style='font-size:0.78rem;color:#64748b;margin-bottom:6px;'><em>{_threat_reason}</em></div>" if _threat_reason else "")
                            + "<strong>Test Steps:</strong>"
                            f"<ol style='margin:4px 0 8px 0;padding-left:18px;'>{_ex_steps}</ol>"
                            f"<strong>Expected:</strong><ul style='margin:4px 0 8px 0;padding-left:18px;'>{_ex_expected}</ul>"
                            f"<strong>Failure:</strong><ul style='margin:4px 0 0 0;padding-left:18px;'>{_ex_failure}</ul>"
                            + _tools_section
                            + "</div></div>"
                            + _sec("📝", "Notes", "#f0fdfa", "#0d9488",
                                   "<ul style='margin:0;padding-left:18px;'>"
                                   "<li>Focus on <strong>validating controls</strong>, not exploiting systems</li>"
                                   "<li>Prefer repeatable, low-risk test cases</li>"
                                   "<li>Where applicable, automate tests in CI/CD pipelines</li>"
                                   "<li>Align test results with risk severity and control gaps</li>"
                                   "</ul>")
                            + _sec("📤", "Output Format (per finding)", "#faf5ff", "#7c3aed",
                                   "<ul style='margin:0;padding-left:18px;'>"
                                   "<li><strong>Test Scenario</strong> — what was tested</li>"
                                   "<li><strong>Steps Executed</strong> — exact inputs/actions used</li>"
                                   "<li><strong>Expected Behavior</strong> — what a passing control looks like</li>"
                                   "<li><strong>Failure Indicators</strong> — observed gap or unsafe behavior</li>"
                                   "<li><strong>Evidence</strong> — logs, screenshots, response samples</li>"
                                   "</ul>")
                            + "</div></div>"  # close body + outer card
                        )
                        _html(_guide_html)
                        if st.button(
                            "✕ Close",
                            key=f"btn_close_test_{index}_{hash(threat.get('threat',''))}",
                        ):
                            st.session_state[_dlg_key] = False
                            st.rerun()


def framework_table(title, framework_map, found_ids):
    """Modern framework coverage table with gradient header, subtle row tints,
    triggered-row left-rail accent, and 'pill' status badges."""
    _title_lower = title.lower()
    # (gradient_start, gradient_end, on_dark_text, accent_id_color, soft_tint)
    if "llm" in _title_lower:
        g1, g2, hdr_txt, id_color, tint = "#1e40af", "#3b82f6", "#dbeafe", "#3b82f6", "#eff6ff"
    elif "ml top" in _title_lower or "ml " in _title_lower:
        g1, g2, hdr_txt, id_color, tint = "#0f766e", "#14b8a6", "#ccfbf1", "#0d9488", "#f0fdfa"
    elif "agentic" in _title_lower or "asi" in _title_lower:
        g1, g2, hdr_txt, id_color, tint = "#6d28d9", "#8b5cf6", "#ede9fe", "#7c3aed", "#f5f3ff"
    elif "mcp" in _title_lower:
        g1, g2, hdr_txt, id_color, tint = "#9a3412", "#ea580c", "#ffedd5", "#ea580c", "#fff7ed"
    elif "mitre" in _title_lower:
        g1, g2, hdr_txt, id_color, tint = "#166534", "#22c55e", "#dcfce7", "#16a34a", "#f0fdf4"
    else:
        g1, g2, hdr_txt, id_color, tint = "#1e3a5f", "#3b82f6", "#dbeafe", "#3b82f6", "#eff6ff"

    triggered_count = sum(1 for k in framework_map if k in found_ids)
    total_count = len(framework_map)

    rows_html = ""
    for i, (risk_id, description) in enumerate(framework_map.items()):
        found = risk_id in found_ids
        # Subtle alternating row + triggered rows get the framework's tint
        if found:
            row_bg = tint
            row_left = f"3px solid {id_color}"
        else:
            row_bg = "#fafbfc" if i % 2 == 0 else "#ffffff"
            row_left = f"3px solid transparent"

        status_html = (
            f"<span style='background:linear-gradient(135deg,#16a34a,#22c55e);color:#ffffff;"
            f"font-weight:700;font-size:0.7rem;padding:3px 10px;border-radius:99px;"
            f"box-shadow:0 1px 2px rgba(22,163,74,0.25);white-space:nowrap;'>"
            f"&#10003; Triggered</span>"
            if found else
            "<span style='background:#f1f5f9;color:#94a3b8;font-weight:600;"
            "font-size:0.7rem;padding:3px 10px;border-radius:99px;"
            "border:1px solid #e2e8f0;white-space:nowrap;'>Not triggered</span>"
        )
        title_color = "#0f172a" if found else "#475569"
        title_weight = "600" if found else "500"
        rows_html += (
            f"<tr class='atm-fw-row' style='background:{row_bg};"
            f"border-bottom:1px solid #eef2f7;border-left:{row_left};'>"
            f"<td style='padding:7px 10px 7px 12px;font-size:0.76rem;font-weight:800;"
            f"font-family:\"JetBrains Mono\",monospace;color:{id_color};white-space:nowrap;"
            f"width:80px;'>{risk_id}</td>"
            f"<td style='padding:7px 12px;font-size:0.83rem;color:{title_color};"
            f"font-weight:{title_weight};line-height:1.4;'>{description}</td>"
            f"<td style='padding:7px 12px;text-align:right;white-space:nowrap;'>{status_html}</td>"
            f"</tr>"
        )
    coverage_pct = int(round(100 * triggered_count / max(total_count, 1)))
    _html(
        f"<div style='margin:14px 0 10px 0;border-radius:12px;overflow:hidden;"
        f"border:1px solid #e2e8f0;box-shadow:0 2px 6px rgba(15,23,42,0.06);'>"
        f"<div style='background:linear-gradient(135deg,{g1} 0%,{g2} 100%);"
        f"padding:9px 14px;display:flex;align-items:center;justify-content:space-between;gap:10px;'>"
        f"<span style='font-size:0.82rem;font-weight:800;color:{hdr_txt};"
        f"letter-spacing:0.02em;'>{title}</span>"
        f"<span style='font-size:0.7rem;font-weight:700;color:{hdr_txt};opacity:0.95;"
        f"background:rgba(255,255,255,0.18);border:1px solid rgba(255,255,255,0.22);"
        f"padding:2px 9px;border-radius:99px;letter-spacing:0.03em;'>"
        f"{triggered_count}/{total_count} &middot; {coverage_pct}%</span>"
        f"</div>"
        f"<table style='width:100%;border-collapse:collapse;background:#fff;'>"
        f"<thead><tr style='background:#f8fafc;border-bottom:1px solid #e2e8f0;'>"
        f"<th style='padding:7px 12px;text-align:left;font-size:0.66rem;"
        f"font-weight:800;letter-spacing:0.08em;text-transform:uppercase;"
        f"color:#64748b;width:80px;'>ID</th>"
        f"<th style='padding:7px 12px;text-align:left;font-size:0.66rem;"
        f"font-weight:800;letter-spacing:0.08em;text-transform:uppercase;"
        f"color:#64748b;'>Risk / Technique</th>"
        f"<th style='padding:7px 12px;text-align:right;font-size:0.66rem;"
        f"font-weight:800;letter-spacing:0.08em;text-transform:uppercase;"
        f"color:#64748b;'>Status</th>"
        f"</tr></thead>"
        f"<tbody>{rows_html}</tbody>"
        f"</table>"
        f"</div>"
    )


def _extract_owasp_ids(threat):
    ids = set()
    for part in str(threat.get("owasp", "")).split("|"):
        part = part.strip()
        if not part or part == "N/A":
            continue
        token = part.split(":", 1)[0].strip()
        if token:
            ids.add(token)
    return ids


def render_frameworks(found_ids):
    # Bug 4: show all four OWASP framework tables so the user can see every
    # framework we map to, not only LLM/ML. Tables are always rendered so a
    # project can visually confirm which ASI/MCP items landed.
    _owasp_relevance = {
        "OWASP LLM Top 10 (2025)":     lambda: is_llm_like_selection() or st.session_state.get("ai_type") in ["Large Language Model (LLM)", "Generative AI (e.g., Image/Audio Generation)", "RAG / AI Search", "Agentic AI (e.g., Autonomous Agents)", "Multimodal AI"],
        "OWASP ML Top 10 (Official)":  lambda: is_trad_ml_selection() or st.session_state.get("ai_type") == "Traditional ML",
        "OWASP Agentic (ASI) Top 10":  lambda: is_agentic_selection() or st.session_state.get("ai_type") == "Agentic AI (e.g., Autonomous Agents)",
        "OWASP MCP Top 10":            lambda: is_mcp_selection() or st.session_state.get("mcp_usage") == "Yes",
    }

    cols = st.columns(2)
    with cols[0]:
        fw_name = "OWASP LLM Top 10 (2025)"
        if _owasp_relevance.get(fw_name, lambda: True)():
            framework_table(fw_name, OWASP_LLM_TOP_10_DESCRIPTION_MAP, found_ids)
        else:
            ai_type = st.session_state.get("ai_type", "your selected AI architecture")
            _html(
                f"<div style='padding:10px;color:#64748b;font-size:0.82rem;background:#f8fafc;"
                f"border-radius:8px;border:1px solid #e2e8f0;margin:14px 0 10px 0;'>"
                f"ℹ️ <strong>{fw_name}</strong> is not applicable for your selected AI architecture ({ai_type}). "
                f"No findings from this framework were triggered.</div>"
            )

        fw_name = "OWASP ML Top 10 (Official)"
        if _owasp_relevance.get(fw_name, lambda: True)():
            framework_table(fw_name, OWASP_ML_TOP_10_DESCRIPTION_MAP, found_ids)
        else:
            ai_type = st.session_state.get("ai_type", "your selected AI architecture")
            _html(
                f"<div style='padding:10px;color:#64748b;font-size:0.82rem;background:#f8fafc;"
                f"border-radius:8px;border:1px solid #e2e8f0;margin:14px 0 10px 0;'>"
                f"ℹ️ <strong>{fw_name}</strong> is not applicable for your selected AI architecture ({ai_type}). "
                f"No findings from this framework were triggered.</div>"
            )
    with cols[1]:
        fw_name = "OWASP Agentic (ASI) Top 10"
        if _owasp_relevance.get(fw_name, lambda: True)():
            framework_table(fw_name, OWASP_AGENTIC_TOP_10_DESCRIPTION_MAP, found_ids)
        else:
            ai_type = st.session_state.get("ai_type", "your selected AI architecture")
            _html(
                f"<div style='padding:10px;color:#64748b;font-size:0.82rem;background:#f8fafc;"
                f"border-radius:8px;border:1px solid #e2e8f0;margin:14px 0 10px 0;'>"
                f"ℹ️ <strong>{fw_name}</strong> is not applicable for your selected AI architecture ({ai_type}). "
                f"No findings from this framework were triggered.</div>"
            )

        fw_name = "OWASP MCP Top 10"
        if _owasp_relevance.get(fw_name, lambda: True)():
            framework_table(fw_name, OWASP_MCP_TOP_10_DESCRIPTION_MAP, found_ids)
        else:
            ai_type = st.session_state.get("ai_type", "your selected AI architecture")
            _html(
                f"<div style='padding:10px;color:#64748b;font-size:0.82rem;background:#f8fafc;"
                f"border-radius:8px;border:1px solid #e2e8f0;margin:14px 0 10px 0;'>"
                f"ℹ️ <strong>{fw_name}</strong> is not applicable for your selected AI architecture ({ai_type}). "
                f"No findings from this framework were triggered.</div>"
            )


# ---------------------------------------------------------------------------
# PDF export — reportlab for rich, paginated output. Falls back gracefully if
# reportlab isn't installed (offering raw Markdown as a download instead).
# ---------------------------------------------------------------------------
def build_pdf_report(threats, inferred_compliances, compliance_gaps):
    """Return (bytes, mime, filename, error) for the threat report.
    Tries reportlab first (rich layout) and falls back to fpdf2 (plain layout).
    If neither is installed, bytes is None and error describes what to install."""
    # ------------- reportlab path ------------------------------------------
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, KeepTogether,
        )
        _have_reportlab = True
        _reportlab_err = None
    except Exception as exc:
        _have_reportlab = False
        _reportlab_err = f"{type(exc).__name__}: {exc}"

    if not _have_reportlab:
        # ------------- fpdf2 / fpdf fallback --------------------------------
        try:
            from fpdf import FPDF  # noqa: F401 — classic fpdf AND fpdf2 share this name
        except Exception as exc:
            return (
                None, None, None,
                f"Neither reportlab nor fpdf/fpdf2 is importable. "
                f"reportlab: {_reportlab_err}. fpdf: {type(exc).__name__}: {exc}. "
                f"Run: pip install reportlab (or fpdf2) and restart the app."
            )
        try:
            return (*_build_pdf_with_fpdf(threats, inferred_compliances, compliance_gaps), None)
        except Exception as exc:
            return (
                None, None, None,
                f"fpdf PDF build failed: {type(exc).__name__}: {exc}. "
                f"reportlab would give a better layout — run "
                f"`pip install reportlab` and restart the app.",
            )

    basic = sorted(threats["basic"], key=lambda item: SEVERITY_ORDER.get(item["severity"], 9))
    chained = sorted(threats["chained"], key=lambda item: SEVERITY_ORDER.get(item["severity"], 9))
    all_threats = basic + chained
    sev_counts = Counter(t["severity"] for t in all_threats)
    score = risk_score(sev_counts)

    project = st.session_state.project_name or "Untitled AI / ML Project"
    description = st.session_state.description or "No project description provided."
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    sev_color_map = {
        "Critical": colors.HexColor("#7f1d1d"),
        "High":     colors.HexColor("#ef4444"),
        "Medium":   colors.HexColor("#f59e0b"),
        "Low":      colors.HexColor("#10b981"),
    }

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"Threat Model — {project}",
        author="AI / ML Threat Modelling Assistant",
    )

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"],
                        textColor=colors.HexColor("#0b1220"), fontSize=18, spaceAfter=6)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"],
                        textColor=colors.HexColor("#1e293b"), fontSize=13, spaceAfter=4)
    h3 = ParagraphStyle("H3", parent=styles["Heading3"],
                        textColor=colors.HexColor("#1e293b"), fontSize=11, spaceAfter=2)
    body = ParagraphStyle("Body", parent=styles["BodyText"],
                          textColor=colors.HexColor("#1e293b"),
                          fontSize=9.5, leading=13, spaceAfter=4)
    meta = ParagraphStyle("Meta", parent=styles["BodyText"],
                          textColor=colors.HexColor("#64748b"),
                          fontSize=8.5, leading=11, spaceAfter=4)
    small = ParagraphStyle("Small", parent=styles["BodyText"],
                           textColor=colors.HexColor("#0b1220"),
                           fontSize=8.5, leading=11)

    elements = []

    # ---- Header block
    elements.append(Paragraph("Threat Modelling of AI / ML Project", h2))
    elements.append(Paragraph(project, h1))
    elements.append(Paragraph(description.replace("\n", "<br/>"), body))
    elements.append(Paragraph(
        f"Generated: {generated_at} · Stage: {st.session_state.project_stage} · "
        f"Business impact: {st.session_state.business_impact} · "
        f"AI type: {st.session_state.ai_type}",
        meta,
    ))
    # Bug R2.6: the PDF also tells the reader which persona view is inside.
    if is_developer_mode():
        elements.append(Paragraph(
            "<b>View:</b> Developer / ML Engineer — each finding has an "
            "<i>In short</i> summary and a <i>What to change in code</i> "
            "action line, alongside OWASP / MITRE mapping.",
            meta,
        ))
    else:
        elements.append(Paragraph(
            "<b>View:</b> Security Engineer — each finding has a "
            "<i>How to test</i> block with tools and step-by-step verification, "
            "alongside OWASP / MITRE / NIST mapping.",
            meta,
        ))
    elements.append(Spacer(1, 6))

    # ---- Executive summary table
    # Issue 1: Overall severity is the deterministic aggregate from
    # rules_engine.evaluate_threats (count-based + Public+no-auth override).
    _overall_sev = (
        threats.get("overall_severity")
        or (threats.get("risk_summary") or {}).get("severity")
        or "—"
    )
    summary_data = [
        ["Overall severity", _overall_sev.upper()],
        ["Risk score", str(score)],
        ["Critical",   str(sev_counts.get("Critical", 0))],
        ["High",       str(sev_counts.get("High", 0))],
        ["Medium",     str(sev_counts.get("Medium", 0))],
        ["Low",        str(sev_counts.get("Low", 0))],
        ["Findings",   str(len(basic))],
        ["Chains",     str(len(chained))],
    ]
    summary_tbl = Table(summary_data, colWidths=[55 * mm, 25 * mm])
    summary_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("TEXTCOLOR",  (0, 0), (0, -1), colors.HexColor("#1e293b")),
        ("FONTNAME",   (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9.5),
        ("BOX",        (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("INNERGRID",  (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING",   (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    elements.append(Paragraph("Executive summary", h2))
    elements.append(summary_tbl)
    elements.append(Spacer(1, 8))

    if inferred_compliances:
        elements.append(Paragraph(
            "<b>Inferred compliance regimes:</b> " + ", ".join(sorted(inferred_compliances)),
            body,
        ))
    if compliance_gaps:
        gaps_text = "<br/>".join(f"• {gap}" for gap in sorted(set(compliance_gaps)))
        elements.append(Paragraph("<b>Compliance gaps</b>", h3))
        elements.append(Paragraph(gaps_text, body))

    elements.append(Spacer(1, 6))

    def _safe(s):
        return (
            str(s or "")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    def _threat_block(threat, index, chain=False):
        sev = threat["severity"]
        sev_bg = sev_color_map.get(sev, colors.HexColor("#64748b"))
        chain_label = " · Chained" if chain else ""
        tag_table = Table(
            [[Paragraph(f"<font color='white'><b>{sev.upper()}</b>{chain_label}</font>", small)]],
            colWidths=[160 * mm],
        )
        tag_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), sev_bg),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))

        rows = [
            Paragraph(f"<b>{index}. {_safe(threat['threat'])}</b>", h3),
            tag_table,
            Paragraph(f"<b>OWASP / Framework:</b> {_safe(threat.get('owasp', ''))}", small),
            Paragraph(f"<b>MITRE ATLAS:</b> {_safe(threat.get('mitre', ''))}", small),
            Paragraph(f"<b>Reason:</b> {_safe(threat.get('reason', ''))}", body),
            Paragraph(f"<b>Description:</b> {_safe(threat.get('description', ''))}", body),
            Paragraph(f"<b>Mitigation:</b> {_safe(threat.get('mitigation', ''))}", body),
        ]

        # Bug R2.6: persona-specific block inside the PDF.
        owasp_ids = str(threat.get("owasp", "") or "").split("|")
        first_code = next(
            (p.strip().split(":", 1)[0].strip() for p in owasp_ids if p.strip()),
            "",
        )
        if is_developer_mode():
            picked = _DEV_SHORT_BY_OWASP.get(first_code)
            if picked:
                rows.append(Paragraph(
                    f"<b>In short (developer):</b> {_safe(picked['plain'])}", body,
                ))
                rows.append(Paragraph(
                    f"<b>What to change in code:</b> {_safe(picked['code'])}", body,
                ))
        else:
            picked = _TEST_GUIDANCE_BY_OWASP.get(first_code)
            if picked:
                rows.append(Paragraph(
                    f"<b>How to test (security persona):</b>", body,
                ))
                rows.append(Paragraph(
                    f"<b>Tools:</b> {_safe(picked['tools'])}", small,
                ))
                steps_html = "<br/>".join(
                    f"{i + 1}. {_safe(step)}"
                    for i, step in enumerate(picked["steps"])
                )
                rows.append(Paragraph(steps_html, body))

        nist_values = [n for n in (threat.get("nist") or []) if n]
        compl_values = [c for c in (threat.get("compliance") or []) if c]
        if nist_values:
            rows.append(Paragraph(
                f"<b>NIST impact:</b> {_safe(', '.join(nist_values))}", small,
            ))
        if compl_values:
            rows.append(Paragraph(
                f"<b>Compliance risks:</b> {_safe(', '.join(compl_values))}", small,
            ))

        if threat.get("attack_path"):
            steps_html = "<br/>".join(
                f"{i + 1}. {_safe(step)}"
                for i, step in enumerate(threat["attack_path"])
            )
            rows.append(Paragraph(f"<b>Attack path:</b><br/>{steps_html}", body))
        rows.append(Spacer(1, 6))
        return KeepTogether(rows)

    if chained:
        elements.append(PageBreak())
        elements.append(Paragraph("Attack chains", h2))
        for i, t in enumerate(chained, start=1):
            elements.append(_threat_block(t, i, chain=True))

    elements.append(PageBreak())
    elements.append(Paragraph("Priority findings", h2))
    if basic:
        for i, t in enumerate(basic, start=1):
            elements.append(_threat_block(t, i))
    else:
        elements.append(Paragraph("No individual findings detected.", body))

    # ---- Framework coverage tables
    found_ids = set()
    for t in all_threats:
        found_ids.update(_extract_owasp_ids(t))

    def _framework_tbl(title, frame_map):
        data = [[title, "Status"]]
        for rid, rdesc in frame_map.items():
            status = "Found" if rid in found_ids else "Not found"
            data.append([f"{rid} — {rdesc}", status])
        tbl = Table(data, colWidths=[135 * mm, 25 * mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 8.5),
            ("BOX",        (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("INNERGRID",  (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING",   (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        return tbl

    elements.append(PageBreak())
    elements.append(Paragraph("Framework coverage", h2))
    for title, frame_map in [
        ("OWASP LLM Top 10 (2025)", OWASP_LLM_TOP_10_DESCRIPTION_MAP),
        ("OWASP ML Top 10", OWASP_ML_TOP_10_DESCRIPTION_MAP),
        ("OWASP Agentic (ASI) Top 10", OWASP_AGENTIC_TOP_10_DESCRIPTION_MAP),
        ("OWASP MCP Top 10", OWASP_MCP_TOP_10_DESCRIPTION_MAP),
    ]:
        elements.append(Paragraph(title, h3))
        elements.append(_framework_tbl(title, frame_map))
        elements.append(Spacer(1, 6))

    doc.build(elements)
    pdf_bytes = buf.getvalue()
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_"
                        for c in (project or "threat_model")).strip("_") or "threat_model"
    filename = f"threat_model_{safe_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf"
    return pdf_bytes, "application/pdf", filename, None


def _build_pdf_with_fpdf(threats, inferred_compliances, compliance_gaps):
    """Simple layout fallback. Works with BOTH classic `fpdf` and modern
    `fpdf2`: we avoid the fpdf2-only ``new_x`` / ``new_y`` kwargs and use the
    legacy ``ln=1`` style that both libraries accept. Returns
    (bytes, mime, filename).
    """
    from fpdf import FPDF

    basic = sorted(threats["basic"], key=lambda item: SEVERITY_ORDER.get(item["severity"], 9))
    chained = sorted(threats["chained"], key=lambda item: SEVERITY_ORDER.get(item["severity"], 9))
    all_threats = basic + chained
    sev_counts = Counter(t["severity"] for t in all_threats)
    score = risk_score(sev_counts)

    project = st.session_state.project_name or "Untitled AI / ML Project"
    description = st.session_state.description or "No project description provided."
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # Classic fpdf chokes on non-Latin-1 glyphs that may appear in pasted
    # project names or descriptions (e.g. smart quotes). Stay safe.
    def _sanitize(s):
        try:
            return str(s or "").encode("latin-1", "replace").decode("latin-1")
        except Exception:
            return str(s or "")

    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 9, _sanitize("Threat Modelling of AI / ML Project"), ln=1)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 7, _sanitize(project[:95]), ln=1)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(100, 116, 139)
    pdf.multi_cell(0, 4.5, _sanitize(description[:500]))
    pdf.cell(0, 4, _sanitize(
        f"Generated {generated_at} | Stage {st.session_state.project_stage} | "
        f"Business impact {st.session_state.business_impact} | "
        f"Risk score {score}"
    ), ln=1)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(3)

    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, "Summary", ln=1)
    pdf.set_font("Helvetica", "", 9.5)
    for lbl in ("Critical", "High", "Medium", "Low"):
        pdf.cell(0, 5, f"  {lbl}: {sev_counts.get(lbl, 0)}", ln=1)
    pdf.cell(0, 5, f"  Findings: {len(basic)}    Chains: {len(chained)}", ln=1)
    pdf.ln(3)

    if inferred_compliances:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 5, "Inferred compliance regimes", ln=1)
        pdf.set_font("Helvetica", "", 9.5)
        pdf.multi_cell(0, 4.5, _sanitize(", ".join(sorted(inferred_compliances))))
        pdf.ln(1)

    if compliance_gaps:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 5, "Compliance gaps", ln=1)
        pdf.set_font("Helvetica", "", 9.5)
        for gap in sorted(set(compliance_gaps)):
            pdf.multi_cell(0, 4.5, _sanitize("  - " + str(gap)))
        pdf.ln(1)

    def _draw_threat(pdf, t, index, chain=False):
        pdf.set_font("Helvetica", "B", 11)
        title = f"{index}. [{t['severity']}{' / Chained' if chain else ''}] {t['threat']}"
        pdf.multi_cell(0, 6, _sanitize(title))
        pdf.set_font("Helvetica", "", 9.5)
        def _row(label, value):
            if not value:
                return
            pdf.set_font("Helvetica", "B", 9.5)
            pdf.cell(28, 4.8, _sanitize(label))
            pdf.set_font("Helvetica", "", 9.5)
            pdf.multi_cell(0, 4.8, _sanitize(str(value)))
        _row("OWASP:", t.get("owasp", ""))
        _row("MITRE:", t.get("mitre", ""))
        _row("Reason:", t.get("reason", ""))
        _row("Description:", t.get("description", ""))
        _row("Mitigation:", t.get("mitigation", ""))

        # Bug R2.6: persona-specific block inside the fallback PDF too.
        owasp_ids = str(t.get("owasp", "") or "").split("|")
        first_code = next(
            (p.strip().split(":", 1)[0].strip() for p in owasp_ids if p.strip()),
            "",
        )
        if is_developer_mode():
            picked = _DEV_SHORT_BY_OWASP.get(first_code)
            if picked:
                _row("In short:", picked["plain"])
                _row("Code action:", picked["code"])
        else:
            picked = _TEST_GUIDANCE_BY_OWASP.get(first_code)
            if picked:
                _row("Test tools:", picked["tools"])
                steps = " | ".join(
                    f"{i + 1}) {s}" for i, s in enumerate(picked["steps"])
                )
                _row("Test steps:", steps)

        nist = [n for n in (t.get("nist") or []) if n]
        compl = [c for c in (t.get("compliance") or []) if c]
        if nist: _row("NIST:", ", ".join(nist))
        if compl: _row("Compliance:", ", ".join(compl))
        if t.get("attack_path"):
            pdf.set_font("Helvetica", "B", 9.5)
            pdf.cell(0, 4.8, "Attack path:", ln=1)
            pdf.set_font("Helvetica", "", 9.5)
            for i, step in enumerate(t["attack_path"], start=1):
                pdf.multi_cell(0, 4.5, _sanitize(f"  {i}. {step}"))
        pdf.ln(2)

    if chained:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 7, "Attack chains", ln=1)
        pdf.ln(1)
        for i, t in enumerate(chained, start=1):
            _draw_threat(pdf, t, i, chain=True)

    pdf.add_page()
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 7, "Priority findings", ln=1)
    pdf.ln(1)
    if basic:
        for i, t in enumerate(basic, start=1):
            _draw_threat(pdf, t, i)
    else:
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 5, "No individual findings detected.", ln=1)

    out = pdf.output(dest="S")
    # Classic `fpdf` returns a *str* (latin-1 encoded text) — calling bytes(str)
    # without an encoding raises ``TypeError: string argument without an encoding``.
    # fpdf2 returns bytes/bytearray. Handle all three safely.
    if isinstance(out, str):
        data = out.encode("latin-1", "replace")
    elif isinstance(out, bytearray):
        data = bytes(out)
    elif isinstance(out, bytes):
        data = out
    else:
        # Unknown type — try best effort
        try:
            data = bytes(out)
        except (TypeError, ValueError, UnicodeError):
            data = str(out).encode("latin-1", "replace")
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_"
                        for c in (project or "threat_model")).strip("_") or "threat_model"
    filename = f"threat_model_{safe_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf"
    return data, "application/pdf", filename


def render_report(threats):
    basic = sorted(threats["basic"], key=lambda item: SEVERITY_ORDER.get(item["severity"], 9))
    chained = sorted(threats["chained"], key=lambda item: SEVERITY_ORDER.get(item["severity"], 9))
    all_threats = basic + chained
    severity_counts = Counter(t["severity"] for t in all_threats)
    score = risk_score(severity_counts)

    # ── Cluster findings by root_cause for deduplication ──────────────────────
    from collections import defaultdict as _defaultdict
    _clusters: dict = _defaultdict(list)
    for _f in all_threats:
        _root = _f.get("root_cause") or _f.get("id") or "unknown"
        _clusters[_root].append(_f)
    clustered_findings: list = []
    for _root, _items in _clusters.items():
        _primary = max(_items, key=lambda x: x.get("risk_value", 0))
        _related = [i for i in _items if i is not _primary]
        _primary = dict(_primary)
        _primary["related_findings"] = [
            {"title": i.get("title", i.get("threat", "")), "severity": i.get("severity", "")}
            for i in _related
        ]
        clustered_findings.append(_primary)
    clustered_findings = sorted(
        clustered_findings,
        key=lambda t: (SEVERITY_ORDER.get(t.get("severity"), 3), -t.get("risk_value", 0)),
    )

    found_ids = set()
    for threat in all_threats:
        found_ids.update(_extract_owasp_ids(threat))

    report_name = st.session_state.project_name or "Untitled AI Project"
    description = st.session_state.description or "No project description provided."

    # AI-type-aware framing in the hero (Fix 2 follow-up): surface
    # ai_type_summary near the report header so two different AI types
    # produce a visibly different report opening, not just different findings.
    _profile  = threats.get("ai_profile", "unknown")
    _ai_type  = st.session_state.get("ai_type", "")
    _summary  = threats.get("ai_type_summary", "")
    _PROFILE_BADGE = {
        "ml":         ("Classical ML",  "#1e3a8a", "#dbeafe"),
        "llm":        ("LLM",           "#5b21b6", "#ede9fe"),
        "rag":        ("RAG",           "#0e7490", "#cffafe"),
        "agentic":    ("Agentic",       "#9a3412", "#ffedd5"),
        "mcp":        ("MCP",           "#15803d", "#dcfce7"),
        "generative": ("Generative",    "#831843", "#fce7f3"),
    }
    _badge_label, _badge_fg, _badge_bg = _PROFILE_BADGE.get(
        _profile, ("AI", "#334155", "#e2e8f0")
    )
    _ai_type_disp = _ai_type or _badge_label
    _summary_block = (
        f"<div class='atm-ai-type-summary' "
        f"style='margin-top:14px;padding:12px 14px;border-radius:10px;"
        f"background:{_badge_bg};color:{_badge_fg};border:1px solid {_badge_fg}33;'>"
        f"<div style='font-size:0.7rem;font-weight:700;text-transform:uppercase;"
        f"letter-spacing:0.07em;opacity:0.85;margin-bottom:4px;'>"
        f"AI architecture: {_ai_type_disp} · profile: {_badge_label}</div>"
        f"<div style='font-size:0.92rem;line-height:1.5;'>{_summary}</div>"
        f"</div>"
    ) if _summary else ""

    _html(
        f"""
        <div class="atm-report-hero">
            <div class="atm-card-eyebrow">Threat report</div>
            <h2>{report_name}</h2>
            <p>{description}</p>
            {_summary_block}
        </div>
        """
    )

    # ── Summary metrics row — coloured HTML tiles in a flex grid ─────────────
    _rs = threats.get("risk_summary") or {}
    _sev_val  = _rs.get("severity", "—")
    _crit_val = severity_counts.get("Critical", 0)
    _high_val = severity_counts.get("High", 0)
    _tot_val  = len(basic)

    maturity_score = threats.get("maturity_score")
    maturity_level = threats.get("maturity_level", "")

    # Severity tile colour
    _sev_map = {
        "Critical": ("#7f1d1d", "#fee2e2", "#dc2626"),
        "High":     ("#7c2d12", "#ffedd5", "#ea580c"),
        "Medium":   ("#713f12", "#fef9c3", "#ca8a04"),
        "Low":      ("#14532d", "#dcfce7", "#16a34a"),
    }
    _sc, _sbg, _sbar = _sev_map.get(_sev_val, ("#1e293b", "#f1f5f9", "#64748b"))

    # Maturity tile colour
    _ml_colors = {
        "Advanced":   ("#166534", "#dcfce7", "#22c55e"),
        "Mature":     ("#1e40af", "#dbeafe", "#3b82f6"),
        "Developing": ("#92400e", "#fef9c3", "#f59e0b"),
        "Initial":    ("#991b1b", "#fee2e2", "#ef4444"),
    }
    _ml_c, _ml_bg, _ml_bar = _ml_colors.get(maturity_level, ("#374151", "#f3f4f6", "#94a3b8"))
    _mat_score_sub = (
        f"<div style='font-size:0.72rem;color:{_ml_c};opacity:0.75;margin-top:2px;'>"
        f"{maturity_score}/100</div>"
        if maturity_score is not None and maturity_score > 0
        else ""
    )

    _tile = (
        "flex:1;min-width:130px;border-radius:10px;padding:14px 16px;"
        "box-shadow:0 1px 4px rgba(0,0,0,0.07);border:1px solid"
    )
    _lbl = "font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.07em;margin-bottom:4px;"
    _val = "font-size:1.55rem;font-weight:800;line-height:1.1;"

    _maturity_tile = (
        f"<div style='{_tile} {_ml_bar}33;border-top:3px solid {_ml_bar};background:{_ml_bg};'>"
        f"<div style='{_lbl}color:{_ml_c};opacity:0.75;'>Maturity</div>"
        f"<div style='{_val}color:{_ml_c};'>{maturity_level or '—'}</div>"
        f"{_mat_score_sub}"
        f"</div>"
    ) if maturity_level else ""

    _html(f"""
    <div style='display:flex;flex-wrap:wrap;gap:10px;margin:12px 0 6px 0;width:100%;box-sizing:border-box;'>
      <div style='{_tile} {_sbar}33;border-top:3px solid {_sbar};background:{_sbg};'>
        <div style='{_lbl}color:{_sc};opacity:0.75;'>Severity</div>
        <div style='{_val}color:{_sc};'>{_sev_val}</div>
      </div>
      <div style='{_tile} #dc262633;border-top:3px solid #dc2626;background:#fff1f2;'>
        <div style='{_lbl}color:#9f1239;opacity:0.75;'>Critical</div>
        <div style='{_val}color:#9f1239;'>{_crit_val}</div>
      </div>
      <div style='{_tile} #ea580c33;border-top:3px solid #ea580c;background:#fff7ed;'>
        <div style='{_lbl}color:#9a3412;opacity:0.75;'>High</div>
        <div style='{_val}color:#9a3412;'>{_high_val}</div>
      </div>
      <div style='{_tile} #2563eb33;border-top:3px solid #2563eb;background:#dbeafe;'>
        <div style='{_lbl}color:#1e40af;opacity:0.75;'>Findings</div>
        <div style='{_val}color:#1e40af;'>{_tot_val}</div>
      </div>
      {_maturity_tile}
    </div>
    """)


    # Persona mode is silently applied — no banner shown in the report.

    # Always-visible compliance banner so regulatory regimes aren't buried.
    _inferred = sorted(threats.get("inferred_compliances") or [])
    _gaps = sorted(set(threats.get("compliance_gaps") or []))
    if _inferred or _gaps:
        pill_html = " ".join(f"<span class='atm-pill'>{reg}</span>" for reg in _inferred) \
            if _inferred else "<em>No regulated regimes inferred.</em>"
        # Show ALL gaps — each on its own line with a brief descriptor
        _GAP_DESC = {
            "GDPR":       "Personal data handling without confirmed security controls.",
            "HIPAA":      "PHI processed without access controls / transmission security.",
            "PCI DSS":    "Payment data without confirmed encryption and audit logging.",
            "SOC 2":      "Externally-accessed system with missing access / monitoring controls.",
            "ISO 27001":  "Data assets without confirmed classification and logging.",
            "EU AI Act":  "High-impact AI system without documented risk management.",
            "NIST AI RMF":"AI system without formal governance and risk measurement.",
            "CCPA":       "PII handling without consumer data-rights procedures.",
        }
        # Calibration: in Dev / PoC / Retired stages compliance gaps are
        # upcoming requirements rather than active violations — the banner
        # styling and language reflect that.
        _comp_status = threats.get("compliance_status", "active")
        if _gaps:
            _is_upcoming = _comp_status == "upcoming"
            _gap_color   = "#92400e" if _is_upcoming else "#dc2626"
            _gap_bg_brd  = "rgba(245,158,11,0.25)" if _is_upcoming else "rgba(220,38,38,0.2)"
            _gap_text    = "#78350f" if _is_upcoming else "#7f1d1d"
            _gap_icon    = "○" if _is_upcoming else "✗"
            _gap_header  = (f"⏱ {len(_gaps)} upcoming compliance requirement(s) — "
                             f"applies once you move to Pilot / Production:"
                             if _is_upcoming else
                             f"⚠ {len(_gaps)} compliance gap(s) — details in OWASP &amp; Compliance tab:")
            gap_rows = "".join(
                f"<div style='display:flex;align-items:baseline;gap:6px;margin:3px 0;'>"
                f"<span style='color:{_gap_color};font-weight:700;flex-shrink:0;'>{_gap_icon}</span>"
                f"<span><strong>{g}</strong> — {_GAP_DESC.get(g, 'Control gap detected.')}</span></div>"
                for g in _gaps
            )
            gap_section = (
                f"<div style='margin-top:8px;padding-top:8px;"
                f"border-top:1px solid {_gap_bg_brd};'>"
                f"<div style='font-size:0.75rem;font-weight:700;color:{_gap_color};"
                f"margin-bottom:5px;'>{_gap_header}</div>"
                f"<div style='font-size:0.76rem;color:{_gap_text};line-height:1.6;'>{gap_rows}</div>"
                f"</div>"
            )
        else:
            gap_section = (
                "<div style='margin-top:6px;font-size:0.76rem;color:#15803d;'>"
                "✓ No compliance gaps detected.</div>"
            )
        _html(
            f"""
            <div class='atm-compliance-regimes atm-compliance-banner'>
                <div><strong>Regulatory exposure:</strong> {pill_html}</div>
                {gap_section}
            </div>
            """
        )

    report_tabs = st.tabs([
        "Executive Summary",   # 0 — metrics, charts, compliance banner
        "Top Risks",           # 1 — top 5 decision-focused cards (detail view)
        "Detailed Findings",   # 2 — all findings clustered
        "Attack Paths",        # 3 — graph + rule-based chains
        "OWASP & Compliance",  # 4 — gap analysis, framework tables, compliance
        "Quick Wins",          # 5 — actionable low-effort fixes
    ])

    # ---- Executive Summary (overview charts + remediation compass)
    with report_tabs[0]:
        # ── Fix These First (Top 3) — top of Executive Summary ────────────────
        _fix_first = threats.get("fix_first") or []
        if _fix_first:
            _ff_items = []
            for f in _fix_first:
                _sev = f.get("severity", "")
                _sev_color = {"Critical": "#dc2626", "High": "#ea580c"}.get(_sev, "#64748b")
                _ftype = f.get("finding_type", "THREAT")
                _ff_items.append(
                    f"<div style='border:1px solid #e2e8f0;border-left:4px solid {_sev_color};"
                    f"border-radius:8px;padding:12px 14px;margin:8px 0;background:#fff;'>"
                    f"<div style='display:flex;align-items:center;gap:8px;margin-bottom:6px;'>"
                    f"<span style='font-size:0.7rem;font-weight:700;color:#fff;background:{_sev_color};"
                    f"padding:2px 9px;border-radius:99px;'>{_sev}</span>"
                    f"<span style='font-size:0.66rem;font-weight:700;color:#475569;background:#f1f5f9;"
                    f"padding:2px 8px;border-radius:99px;letter-spacing:0.05em;'>{_ftype.replace('_', ' ')}</span>"
                    f"<span style='font-weight:700;font-size:0.96rem;color:#0b1220;'>"
                    f"{f.get('title','')}</span></div>"
                    f"<div style='font-size:0.85rem;color:#334155;margin-bottom:6px;'>"
                    f"<strong>Why:</strong> {f.get('reason','')}</div>"
                    f"<div style='font-size:0.85rem;color:#0b1220;'>"
                    f"<strong>Quick fix:</strong> {f.get('quick_win','')}</div>"
                    f"</div>"
                )
            _html(
                "<div style='margin-bottom:14px;padding:14px 16px;border-radius:10px;"
                "background:#fef2f2;border:1px solid #fecaca;'>"
                "<div style='font-size:0.74rem;font-weight:800;letter-spacing:0.07em;"
                "color:#991b1b;text-transform:uppercase;margin-bottom:4px;'>"
                "Fix these first</div>"
                "<div style='font-size:0.82rem;color:#7f1d1d;margin-bottom:8px;'>"
                f"Top {len(_fix_first)} findings to remediate before anything else, "
                "ranked by severity → risk → confidence.</div>"
                + "".join(_ff_items) +
                "</div>"
            )

        _html(
            "<div class='atm-card-eyebrow'>Executive summary</div>"
            "<div class='atm-card-subtitle' style='margin-bottom:12px;'>"
            "Risk distribution, threat landscape, and compliance exposure at a glance. "
            "See the <strong>Top Risks</strong> tab for the five findings that need immediate action.</div>"
        )

        # ── AI-type-tailored guidance card ─────────────────────────────────────
        # Profile-specific framing and remediation emphasis. Two systems with
        # different ai_profile values render meaningfully different guidance.
        _PROFILE_GUIDE = {
            "ml": {
                "headline": "Data-centric remediation focus",
                "emphasis": [
                    "Lock down training-data provenance and consent.",
                    "Defend the inference API: rate limit, restrict confidence outputs, run membership-inference tests.",
                    "Add adversarial-robustness and drift monitoring before each release.",
                ],
                "deemphasize": "Prompt-injection / agentic-tool defences are not relevant here — they would be skipped.",
            },
            "llm": {
                "headline": "Prompt-surface remediation focus",
                "emphasis": [
                    "Front the model with an AI gateway (rate limit + content filter + audit).",
                    "Treat all user / retrieved / tool inputs as untrusted; sanitise before context insertion.",
                    "Add output filtering (PII, code, HTML) before returning text to callers.",
                ],
                "deemphasize": "Pure-ML attacks (membership inference, weight extraction) are lower priority unless a ML head exists.",
            },
            "rag": {
                "headline": "Retrieval-pipeline remediation focus",
                "emphasis": [
                    "Add per-tenant access filters on every retrieval call.",
                    "Sanitise documents at ingest — strip hidden text, scan for instruction-like patterns.",
                    "Cap retrieved context size; prioritise system instructions on context construction.",
                ],
                "deemphasize": "Inversion / model-stealing attacks matter less than retrieval-poisoning here.",
            },
            "agentic": {
                "headline": "Autonomy-boundary remediation focus",
                "emphasis": [
                    "Declare a tool / scope manifest; reject tool calls outside it.",
                    "Require HITL approval for destructive, write, send, or external-call tool actions.",
                    "Per-run cost & action budgets + execution isolation per agent run.",
                ],
                "deemphasize": "Static ML attacks are de-prioritised; tool misuse and goal drift dominate the risk surface.",
            },
            "mcp": {
                "headline": "Tool-integration remediation focus",
                "emphasis": [
                    "Allow-list MCP servers; reject any tool not on the approved manifest.",
                    "Sanitise tool descriptions and tool RESULTS (both can carry prompt-injection payloads).",
                    "Per-call audit log: caller identity, parameters, result digest — to immutable storage.",
                ],
                "deemphasize": "Direct prompt-injection still matters but is secondary to tool-schema and federation trust.",
            },
            "generative": {
                "headline": "Content-safety remediation focus",
                "emphasis": [
                    "Layer content moderation on prompts AND outputs.",
                    "Watermark outputs (C2PA / SynthID) and verify watermarks survive transformations.",
                    "Run a verbatim-reproduction filter against known copyrighted corpora to limit IP regurgitation.",
                ],
                "deemphasize": "Agentic tool-misuse and ML inversion are typically secondary unless the model is fine-tuned on sensitive data.",
            },
        }
        _g = _PROFILE_GUIDE.get(_profile)
        if _g:
            _emph = "".join(
                f"<li style='margin:3px 0;'>{e}</li>" for e in _g["emphasis"]
            )
            _html(
                f"""
                <div style='margin:10px 0 14px 0;padding:14px 16px;border-radius:10px;
                            background:{_badge_bg};border:1px solid {_badge_fg}33;'>
                    <div style='font-size:0.72rem;font-weight:700;text-transform:uppercase;
                                letter-spacing:0.07em;color:{_badge_fg};opacity:0.85;
                                margin-bottom:6px;'>
                        Tailored for {_badge_label} systems
                    </div>
                    <div style='font-weight:700;color:{_badge_fg};margin-bottom:6px;'>
                        {_g["headline"]}
                    </div>
                    <ul style='margin:6px 0 4px 18px;color:{_badge_fg};font-size:0.88rem;line-height:1.5;'>
                        {_emph}
                    </ul>
                    <div style='font-size:0.78rem;color:{_badge_fg};opacity:0.78;
                                margin-top:6px;font-style:italic;'>
                        {_g["deemphasize"]}
                    </div>
                </div>
                """
            )

        # Charts row
        left, right = st.columns([1.05, 1])
        with left:
            pie = severity_pie(all_threats)
            if pie:
                st.plotly_chart(pie, use_container_width=True, key="overview_pie")
            else:
                _html("<div class='atm-empty'>No risks detected from the selected answers.</div>")
        with right:
            # Attack chains summary
            if chained:
                _html(
                    "<div class='atm-card-eyebrow'>Attack chains</div>"
                    "<div class='atm-card-subtitle' style='margin-bottom:8px;'>"
                    "Multi-step attack paths — each requires all components to be remediated.</div>"
                )
                for threat in chained[:4]:
                    _html(
                        f"<div class='atm-finding {border_class(threat['severity'])}'>"
                        f"<div class='atm-finding-row'>"
                        f"<span class='atm-sev {severity_class(threat['severity'])}'>{threat['severity']}</span>"
                        f"<span class='atm-chain-tag'>Chained</span>"
                        f"</div>"
                        f"<div class='atm-finding-title'>{threat['threat']}</div>"
                        f"<div class='atm-finding-reason'>{threat['reason'][:100]}</div>"
                        f"</div>"
                    )

        chart_col, action_col = st.columns([1, 1.15])
        with chart_col:
            radar = nist_radar(all_threats, "NIST CIA + Abuse")
            if radar:
                st.plotly_chart(radar, use_container_width=True, key="overview_radar")
            compl = compliance_bar(
                all_threats,
                inferred=threats.get("inferred_compliances") or [],
            )
            if compl:
                st.plotly_chart(compl, use_container_width=True, key="overview_compliance")
        with action_col:
            _html(
                "<div class='atm-card-eyebrow'>Remediation order</div>"
                "<div class='atm-card-title'>Where to start</div>"
                "<div class='atm-card-subtitle'>Ordered by severity, confidence, and control gap.</div>"
            )
            for idx, threat in enumerate((chained + basic)[:5], start=1):
                conf_badge = ""
                if threat.get("confidence"):
                    conf_badge = f" <span style='font-size:0.7rem;color:#64748b;'>({threat['confidence']} conf)</span>"
                is_chain = threat.get("is_graph_chain", False)
                n_steps  = len(threat.get("reason_components") or [])
                if is_chain:
                    _html(
                        f"<div style='font-size:0.9rem;margin:6px 0 2px 0;font-weight:600;color:#0b1220;'>"
                        f"{idx}. {render_mitre_pill(threat.get('mitre', ''))}{conf_badge}</div>"
                        f"<div style='font-size:0.82rem;color:#475569;margin:2px 0 2px 10px;'>"
                        f"<strong>{n_steps}-step attack chain</strong> — multiple control gaps enable this path. "
                        f"See the <em>Attack Paths</em> tab for the full breakdown and each control to close.</div>"
                    )
                else:
                    _html(
                        f"<div style='font-size:0.9rem;margin:4px 0;'>"
                        f"{idx}. {render_mitre_pill(threat.get('mitre', ''))}{conf_badge}"
                        f" — {threat['mitigation']}</div>"
                    )

    # ---- Top Risks — five highest-risk findings, decision-focused
    with report_tabs[1]:
        top_priority = threats.get("top_priority") or []
        # Re-sort by risk_value descending (engine already does this, but explicit here)
        top_5 = sorted(all_threats, key=lambda x: x.get("risk_value", 0), reverse=True)[:5]
        _html(
            "<div class='atm-card-eyebrow'>Prioritized risk decisions</div>"
            "<div class='atm-card-title' style='margin-bottom:4px;'>Top 5 Risks That Matter</div>"
            "<div class='atm-card-subtitle' style='margin-bottom:14px;'>"
            "Ranked by risk value (likelihood × impact + control gap). "
            "These are the decisions a senior security lead would escalate first.</div>"
        )
        _goal_icon = {
            "Data Exfiltration":    "Data out",
            "Privilege Escalation": "Privilege up",
            "System Manipulation":  "System control",
            "Cost Exhaustion":      "Cost attack",
            "Model Theft":          "IP theft",
        }
        for idx, t in enumerate(top_5, start=1):
            sev    = t["severity"]
            goal   = t.get("attacker_goal", "")
            conf   = t.get("confidence", "")
            sev_c  = {"Critical": "#7f1d1d", "High": "#ef4444", "Medium": "#f59e0b", "Low": "#10b981"}.get(sev, "#94a3b8")
            conf_c = {"High": "#166534", "Medium": "#92400e", "Low": "#1e40af"}.get(conf, "#374151")
            conf_bg= {"High": "#dcfce7", "Medium": "#fef9c3", "Low": "#dbeafe"}.get(conf, "#f3f4f6")
            _gc, _gbg = {
                "Data Exfiltration":    ("#1e40af", "#dbeafe"),
                "Privilege Escalation": ("#6b21a8", "#f3e8ff"),
                "System Manipulation":  ("#9a3412", "#ffedd5"),
                "Cost Exhaustion":      ("#991b1b", "#fee2e2"),
                "Model Theft":          ("#065f46", "#d1fae5"),
            }.get(goal, ("#374151", "#f3f4f6"))
            reason = t.get("reason", "")[:140]
            qw     = t.get("quick_win", "")[:120]
            _html(
                f"<div style='border:1px solid #e2e8f0;border-left:5px solid {sev_c};"
                f"border-radius:8px;padding:14px 18px;margin:8px 0;background:#fff;"
                f"box-shadow:0 1px 3px rgba(0,0,0,0.06);'>"
                f"<div style='display:flex;align-items:center;gap:6px;margin-bottom:6px;flex-wrap:wrap;'>"
                f"<span style='font-size:0.73rem;font-weight:700;color:{sev_c};"
                f"background:{sev_c}18;padding:2px 9px;border-radius:99px;'>{sev}</span>"
                f"<span style='font-size:0.7rem;font-weight:600;color:{conf_c};"
                f"background:{conf_bg};padding:2px 7px;border-radius:99px;'>{conf} confidence</span>"
                f"<span style='font-size:0.7rem;font-weight:600;color:{_gc};background:{_gbg};"
                f"padding:2px 8px;border-radius:99px;'>Goal: {goal}</span>"
                f"<span style='font-size:0.7rem;color:#64748b;margin-left:auto;'>"
                f"risk score: {t.get('risk_value','—')}</span>"
                f"</div>"
                f"<div style='font-weight:700;font-size:0.97rem;color:#0b1220;margin-bottom:4px;'>"
                f"{idx}. {t['threat']}</div>"
                f"<div style='font-size:0.85rem;color:#475569;margin-bottom:6px;'>{reason}{'…' if len(t.get('reason','')) > 140 else ''}</div>"
                f"<div style='font-size:0.83rem;background:#f0fdf4;border-left:3px solid #22c55e;"
                f"padding:5px 10px;border-radius:3px;color:#166534;'>"
                f"<strong>Quick win:</strong> {qw}{'…' if len(t.get('quick_win','')) > 120 else ''}</div>"
                f"</div>"
            )
        _html("<div class='atm-divider'></div>")

    # ---- Detailed Findings — grouped by finding_type (THREAT / CONTROL_GAP /
    #      GOVERNANCE_GAP), then root-cause clustered + persona-filtered.
    with report_tabs[2]:
        if not clustered_findings:
            _html("<div class='atm-empty'>No individual findings detected.</div>")
        else:
            persona = "Developer" if is_developer_mode() else "Security Engineer"
            chart_col, list_col = st.columns([0.85, 1.35])
            with chart_col:
                compl = compliance_bar(
                    clustered_findings,
                    inferred=threats.get("inferred_compliances") or [],
                )
                if compl:
                    st.plotly_chart(compl, use_container_width=True, key="priority_compliance")
                else:
                    _html("<div class='atm-empty'>No compliance regimes flagged by these findings.</div>")
            with list_col:
                # Bucket clustered findings by finding_type (set in the engine
                # post-processing). Default to THREAT for older code paths
                # that may not have the field populated yet.
                _SECTIONS = [
                    ("THREAT",         "Top Threats",
                     "Exploitable risks with an attack path."),
                    ("CONTROL_GAP",    "Security Control Gaps",
                     "Missing or weak technical controls that enable threats."),
                    ("GOVERNANCE_GAP", "Governance &amp; Compliance Gaps",
                     "Documentation, process, and regulatory gaps."),
                ]
                _buckets = {k: [] for k, _, _ in _SECTIONS}
                for f in clustered_findings:
                    ft = f.get("finding_type", "THREAT")
                    if ft not in _buckets:
                        ft = "THREAT"
                    _buckets[ft].append(f)
                _global_idx = 1
                for key, label, blurb in _SECTIONS:
                    bucket = _buckets[key]
                    if not bucket:
                        continue
                    _html(
                        f"<div class='atm-card-eyebrow' style='margin-top:14px;'>"
                        f"{label}</div>"
                        f"<div class='atm-card-subtitle' style='margin-bottom:8px;'>"
                        f"{blurb} &nbsp;·&nbsp; {len(bucket)} finding(s)</div>"
                    )
                    for f in bucket:
                        data = format_finding(f, persona)
                        render_threat_card(data, _global_idx)
                        _global_idx += 1

    # ---- Attack Paths (graph-based + rule-based chains)
    with report_tabs[3]:
        # ── Attacker type context banner ───────────────────────────────────────
        _exposure = st.session_state.get("exposure", "Public")
        if _exposure in ("Public", "Partner / third-party API"):
            _attacker_label = "External attacker"
            _attacker_desc  = f"public exposure ({_exposure})"
            _attacker_color = "#991b1b"
            _attacker_bg    = "#fee2e2"
            _attacker_border= "#ef4444"
        else:
            _attacker_label = "Internal / authenticated user"
            _attacker_desc  = f"restricted access ({_exposure})"
            _attacker_color = "#1e40af"
            _attacker_bg    = "#dbeafe"
            _attacker_border= "#3b82f6"
        _html(
            f"<div style='background:{_attacker_bg};border:1px solid {_attacker_border}33;"
            f"border-left:4px solid {_attacker_border};border-radius:6px;"
            f"padding:10px 16px;margin-bottom:14px;display:flex;align-items:center;gap:10px;'>"
            f"<div>"
            f"<span style='font-size:0.72rem;font-weight:700;color:{_attacker_color};"
            f"background:{_attacker_color}18;padding:2px 9px;border-radius:99px;"
            f"margin-right:8px;'>Attacker type</span>"
            f"<strong style='color:{_attacker_color};font-size:0.95rem;'>{_attacker_label}</strong>"
            f"<span style='color:{_attacker_color};font-size:0.82rem;margin-left:6px;'>"
            f"— {_attacker_desc}</span>"
            f"</div></div>"
        )
        if not chained:
            _html("<div class='atm-empty'>No chained risks detected. Individual weaknesses may still need remediation.</div>")
        else:
            top_col, radar_col = st.columns([1.25, 0.9])
            with top_col:
                for index, threat in enumerate(chained, start=1):
                    render_threat_card(threat, index, chain=True)
            with radar_col:
                chained_radar = nist_radar(chained, "Chained risk impact")
                if chained_radar:
                    st.plotly_chart(chained_radar, use_container_width=True, key="chained_radar")

    # ---- Quick Wins (Fix #9: max 10, HIGH+CRITICAL only, specific actions)
    with report_tabs[5]:
        _html(
            "<div class='atm-card-eyebrow'>Quick wins</div>"
            "<div class='atm-card-title'>Top 10 fixes — high severity, &lt; 1 day to land</div>"
            "<div class='atm-card-subtitle' style='margin-bottom:16px;'>"
            "Only HIGH and CRITICAL findings shown. Each item is a concrete, specific "
            "action you can complete in under a day to materially reduce risk.</div>"
        )
        # Sort by severity then risk_value, keep only HIGH/CRITICAL with a real
        # quick_win string, cap at 10 items.
        _sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        eligible_qw = sorted(
            (t for t in all_threats
                 if t.get("severity") in ("Critical", "High")
                    and (t.get("quick_win") or "").strip()),
            key=lambda t: (_sev_order.get(t["severity"], 9), -t.get("risk_value", 0)),
        )[:10]
        wins_found = 0
        for threat in eligible_qw:
            qw = threat.get("quick_win", "")
            wins_found += 1
            sev = threat["severity"]
            sev_color = {"Critical": "#ef4444", "High": "#f97316"}.get(sev, "#94a3b8")
            _html(
                f"<div style='border:1px solid #e2e8f0;border-left:4px solid {sev_color};"
                f"border-radius:6px;padding:12px 16px;margin:8px 0;background:#fff;'>"
                f"<div style='display:flex;align-items:center;gap:8px;margin-bottom:4px;'>"
                f"<span style='font-size:0.72rem;font-weight:700;color:{sev_color};"
                f"background:{sev_color}18;padding:2px 8px;border-radius:99px;'>{sev}</span>"
                f"<span style='font-weight:600;font-size:0.92rem;color:#0b1220;'>{threat['threat'].replace(' (Chained)', '')}</span>"
                f"</div>"
                f"<div style='font-size:0.88rem;color:#1e293b;'>{qw}</div>"
                f"</div>"
            )
        if wins_found == 0:
            _html(
                "<div class='atm-empty'>No HIGH or CRITICAL quick wins detected. "
                "Review the Priority Findings tab for the full remediation list.</div>"
            )

    # ---- OWASP & Compliance
    with report_tabs[4]:
        render_frameworks(found_ids)
        mitre_chart = mitre_bar(all_threats)
        if mitre_chart:
            st.plotly_chart(mitre_chart, use_container_width=True, key="frameworks_mitre")

        # ── Compliance view ────────────────────────────────────────────────────
        _html(
            "<div class='atm-card-eyebrow' style='margin-top:24px;'>Regulatory exposure</div>"
            "<div class='atm-card-title' style='margin-bottom:4px;'>Compliance View</div>"
        )
        inferred = sorted(threats.get("inferred_compliances") or [])
        if inferred:
            pills = " ".join(
                f"<span class='atm-pill' style='font-size:0.82rem;padding:4px 12px;'>{reg}</span>"
                for reg in inferred
            )
            _html(f"<div style='margin:8px 0 14px 0;'><strong>Inferred regimes:</strong> {pills}</div>")
        else:
            _html(
                "<div class='atm-empty' style='margin-bottom:10px;'>No regulated regimes inferred — "
                "add PII / PHI / regulated-domain selections in the Data step if they apply.</div>"
            )

        # ── Compliance gaps — prominent red section ────────────────────────────
        compliance_gaps = sorted(set(threats.get("compliance_gaps", [])))
        _html("<div class='atm-card-eyebrow' style='margin-top:10px;color:#991b1b;'>Compliance gaps</div>")
        if compliance_gaps:
            _html(
                f"<div style='background:#fef2f2;border:1px solid #fecaca;border-left:4px solid #ef4444;"
                f"border-radius:8px;padding:14px 18px;margin:8px 0 16px 0;'>"
                f"<div style='font-weight:700;color:#991b1b;font-size:0.95rem;margin-bottom:8px;'>"
                f"⚠ {len(compliance_gaps)} compliance regime(s) have unmitigated control gaps</div>"
                f"<div style='font-size:0.84rem;color:#7f1d1d;margin-bottom:10px;'>"
                f"These regulatory obligations are triggered by your project configuration but the "
                f"relevant security controls are not confirmed as 'Yes'. Each gap represents a potential "
                f"non-compliance risk that requires remediation.</div>"
                f"<div style='display:flex;flex-wrap:wrap;gap:8px;'>"
                + "".join(
                    f"<span style='background:#fee2e2;border:1px solid #fca5a5;color:#991b1b;"
                    f"font-weight:700;font-size:0.8rem;padding:4px 12px;border-radius:6px;'>{g}</span>"
                    for g in compliance_gaps
                )
                + f"</div></div>"
            )
            # Detailed article-level breakdown — always expanded so gaps are immediately visible
            from rules_engine import COMPLIANCE_DETAIL  # type: ignore
            _REGIME_TRIGGER_HINT = {
                "GDPR":       "Triggered because your project handles PII or operates in EU-regulated context.",
                "HIPAA":      "Triggered because your project handles Protected Health Information (PHI).",
                "PCI DSS":    "Triggered because your project handles financial or payment data.",
                "SOC 2":      "Triggered because access controls or audit logging are missing on an externally-accessed system.",
                "ISO 27001":  "Triggered because data encryption at rest is not confirmed.",
                "EU AI Act":  "Triggered because this is a high/critical-impact AI system deployed in the EU.",
                "NIST AI RMF":"Triggered because the system is an AI/ML system requiring formal risk management.",
                "CCPA":       "Triggered because your project handles PII and serves consumers or operates in a regulated commercial domain — indicating a likely California-resident user base subject to CCPA.",
            }
            _html(
                "<div style='font-weight:600;font-size:0.9rem;color:#374151;margin:12px 0 6px 0;'>"
                "Specific obligations requiring attention — expand each regime for article details:</div>"
            )
            _REGIME_COLORS = {
                "GDPR":      ("#1e40af", "#dbeafe", "#3b82f6"),
                "HIPAA":     ("#065f46", "#d1fae5", "#10b981"),
                "PCI DSS":   ("#78350f", "#fef3c7", "#f59e0b"),
                "SOC 2":     ("#4c1d95", "#ede9fe", "#8b5cf6"),
                "ISO 27001": ("#1e3a5f", "#e0f2fe", "#0ea5e9"),
                "EU AI Act": ("#1d4ed8", "#dbeafe", "#6366f1"),
                "NIST AI RMF":("#166534", "#dcfce7", "#22c55e"),
                "CCPA":      ("#9a3412", "#ffedd5", "#f97316"),
            }
            # Per-article "what's missing" + "how to fix" lookup
            _ARTICLE_DETAIL = {
                # GDPR
                "GDPR Art.5(1)(f) – integrity & confidentiality": (
                    "Personal data is stored or processed without confirmed encryption or access controls.",
                    "Enable encryption at rest for all PII data stores; enforce least-privilege access; confirm in Data and Deployment steps."
                ),
                "GDPR Art.32 – security of processing": (
                    "No confirmed technical/organisational measures protecting personal data during processing.",
                    "Implement input validation, output filtering, access controls, and audit logging; document these controls for your DPO."
                ),
                "GDPR Art.35 – DPIA for high-risk AI": (
                    "This AI system processes personal data at scale or uses profiling — a Data Protection Impact Assessment is required.",
                    "Conduct a DPIA: document purpose, data flows, risks, and mitigations. Assign a DPO and schedule annual reviews."
                ),
                # HIPAA
                "HIPAA §164.312(a)(1) – access controls": (
                    "PHI is accessible without confirmed role-based access controls.",
                    "Implement unique user IDs, auto-logoff, MFA, and emergency access procedures for all PHI stores."
                ),
                "HIPAA §164.312(e)(1) – transmission security": (
                    "PHI is transmitted without confirmed encryption in transit.",
                    "Enforce TLS 1.2+ for all PHI in transit; confirm data_encrypted_at_rest and WAF settings in the Deployment step."
                ),
                "HIPAA §164.308(a)(1) – security management": (
                    "No documented security risk assessment and management process for PHI.",
                    "Perform an annual HIPAA risk assessment; implement a sanction policy and AI-specific incident response plan."
                ),
                # PCI DSS
                "PCI DSS Req.3.4 – protect stored data": (
                    "Financial/payment data stored without confirmed encryption.",
                    "Encrypt cardholder data at rest using AES-256 or equivalent; implement key management controls and key rotation."
                ),
                "PCI DSS Req.6.2 – secure development": (
                    "No confirmed secure development practices for systems handling payment data.",
                    "Implement code reviews, SAST/DAST scanning, and annual penetration testing for payment-handling components."
                ),
                "PCI DSS Req.10.2 – implement audit logs": (
                    "No confirmed logging of access to cardholder data.",
                    "Enable immutable audit logs for all access to payment data; retain for at least 12 months with 3-month online availability."
                ),
                # SOC 2
                "SOC2 CC6.1 – logical access controls": (
                    "Insufficient access controls on an externally-accessible system.",
                    "Implement MFA, least-privilege access, quarterly access reviews, and account lifecycle management."
                ),
                "SOC2 CC6.6 – network boundary protection": (
                    "No confirmed network boundary controls (WAF, firewall, segmentation).",
                    "Deploy WAF and/or API gateway in front of the model endpoint; enforce network segmentation between model hosts and data stores."
                ),
                "SOC2 CC7.2 – system monitoring": (
                    "No confirmed monitoring for anomalies, abuse, or unauthorised access.",
                    "Implement real-time alerting on login failures, anomalous API call patterns, and privilege escalations; review alerts weekly."
                ),
                # ISO 27001
                "ISO 27001 A.8.2 – information classification": (
                    "Data assets aren't classified by sensitivity level.",
                    "Define a data classification policy (Public / Internal / Confidential / Restricted); apply labels to model inputs, outputs, and training data."
                ),
                "ISO 27001 A.9.4 – system access control": (
                    "System and application access is not sufficiently controlled.",
                    "Enforce access control lists, MFA, and session timeouts; review access quarterly and remove stale accounts promptly."
                ),
                "ISO 27001 A.12.4 – logging & monitoring": (
                    "Insufficient logging of system events and model interactions.",
                    "Capture and retain audit logs for all model API calls, authentication events, and data modifications for at least 1 year."
                ),
                # NIST AI RMF
                "NIST AI RMF – GOVERN 1.2": (
                    "No AI-specific governance policy or accountable owner identified.",
                    "Assign clear ownership for AI risk; establish an AI governance committee; document risk tolerance thresholds and review cadence."
                ),
                "NIST AI RMF – MAP 2.3": (
                    "AI risks haven't been systematically identified and categorised.",
                    "Use this threat model's findings as your risk register; document likelihood and impact per category; update after each model change."
                ),
                "NIST AI RMF – MEASURE 2.5": (
                    "AI system performance and safety metrics aren't tracked over time.",
                    "Define KPIs for model accuracy, fairness, robustness, and safety; run automated evals on every release; publish results internally."
                ),
                # EU AI Act
                "EU AI Act Art.9 – risk management system": (
                    "No documented lifecycle risk management process for this AI system.",
                    "Establish a written risk management plan: identify hazards, estimate severity and likelihood, define mitigations. Review before each major release."
                ),
                "EU AI Act Art.13 – transparency": (
                    "Users are not clearly informed they are interacting with AI, or system documentation is absent.",
                    "Add visible AI disclosure to user-facing interfaces; publish a model card covering capabilities, limitations, training data, and known failure modes."
                ),
                "EU AI Act Art.15 – accuracy, robustness & cybersecurity": (
                    "Accuracy metrics, adversarial robustness testing, and cybersecurity controls are not documented.",
                    "Document baseline accuracy metrics; run adversarial / red-team tests at least quarterly; confirm input validation and output filtering are active."
                ),
                # CCPA
                "CCPA §1798.100 – right to know": (
                    "No mechanism for California residents to request what personal data the system holds about them.",
                    "Implement a DSAR (Data Subject Access Request) process; document what PII is collected, used, shared, and retained per user."
                ),
                "CCPA §1798.150 – security breach liability": (
                    "No confirmed security controls that would limit liability in a breach involving California residents.",
                    "Implement encryption, access controls, and incident response; establish a breach notification process within 30 days of discovery."
                ),
            }

            for regime in compliance_gaps:
                articles = COMPLIANCE_DETAIL.get(regime, [regime])
                trigger_hint = _REGIME_TRIGGER_HINT.get(regime, "Triggered by your project configuration.")
                _rc_dark, _rc_light, _rc_accent = _REGIME_COLORS.get(regime, ("#374151", "#f3f4f6", "#6b7280"))
                with st.expander(f"📋 {regime} — {len(articles)} obligation(s)", expanded=True):
                    _html(
                        f"<div style='font-size:0.82rem;color:{_rc_dark};background:{_rc_light};"
                        f"border-left:3px solid {_rc_accent};padding:7px 11px;border-radius:6px;"
                        f"margin-bottom:10px;'><strong>Why this gap was flagged:</strong> {trigger_hint}</div>"
                    )
                    articles_html = ""
                    for article in articles:
                        _what, _fix = _ARTICLE_DETAIL.get(article, ("Control gap detected.", "Review and confirm the relevant control in the questionnaire steps."))
                        articles_html += (
                            f"<div style='padding:10px 14px;border-bottom:1px solid #f1f5f9;background:#fff;'>"
                            f"<div style='display:flex;gap:8px;align-items:flex-start;margin-bottom:6px;'>"
                            f"<span style='color:{_rc_accent};font-size:0.9rem;flex-shrink:0;'>📌</span>"
                            f"<span style='font-size:0.86rem;font-weight:700;color:#1e293b;'>{article}</span></div>"
                            f"<div style='margin-left:22px;'>"
                            f"<div style='font-size:0.78rem;color:#7f1d1d;background:#fef2f2;"
                            f"border-radius:5px;padding:4px 9px;margin-bottom:5px;'>"
                            f"<strong>What's missing:</strong> {_what}</div>"
                            f"<div style='font-size:0.78rem;color:#14532d;background:#f0fdf4;"
                            f"border-radius:5px;padding:4px 9px;'>"
                            f"<strong>How to fix:</strong> {_fix}</div>"
                            f"</div></div>"
                        )
                    _html(
                        f"<div style='border:1px solid {_rc_accent}30;border-radius:8px;"
                        f"overflow:hidden;'>{articles_html}</div>"
                    )
        else:
            _html(
                "<div style='background:#f0fdf4;border:1px solid #bbf7d0;border-left:4px solid #22c55e;"
                "border-radius:8px;padding:12px 16px;font-size:0.88rem;color:#166534;'>"
                "✓ No compliance gaps detected — all controls tied to inferred regimes appear to be in place.</div>"
            )

    # ── PDF download — bottom of full report ──────────────────────────────────
    _html("<div class='atm-divider' style='margin:28px 0 16px 0;'></div>")
    _html(
        "<div style='font-size:0.8rem;color:#64748b;margin-bottom:8px;'>"
        "Export the complete threat model as a PDF for sharing with stakeholders, "
        "security teams, or auditors.</div>"
    )
    _pdf_bytes, _pdf_mime, _pdf_name, _pdf_err = build_pdf_report(
        threats,
        threats.get("inferred_compliances") or [],
        threats.get("compliance_gaps") or [],
    )
    if _pdf_bytes:
        st.download_button(
            label="⬇ Download full threat report as PDF",
            data=_pdf_bytes,
            file_name=_pdf_name,
            mime=_pdf_mime,
            key="download_pdf_report",
            use_container_width=False,
        )
    else:
        st.warning(
            _pdf_err or "PDF builder returned no bytes. Install reportlab and restart."
        )

# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------
initialize_state()
normalize_conditional_defaults()
clamp_step()
inject_css()

steps = build_steps()
current_idx = int(st.session_state.get("step_index") or 0)

render_sidebar(steps, current_idx)

if st.session_state.report_requested:
    with st.spinner("Analyzing answers and building threat report..."):
        render_report(evaluate_threats(selected_inputs()))
else:
    render_wizard(steps, current_idx)

_autosave()
