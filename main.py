# main.py
import streamlit as st
from rules_engine import evaluate_threats
from collections import Counter
import plotly.graph_objects as go
import plotly.io as pio
import re

st.set_page_config(page_title="AI Threat Modeling (Rule-Based)", layout="wide")
st.title("🛡️ AI Threat Modeling Assistant (Rule-Based)")

with st.form("ai_threat_form"):
    st.header("📘 General Info")
    project_name = st.text_input("Project Name")
    description = st.text_area("Project Description")

    st.header("🧠 Model Details")
    ai_type = st.selectbox("AI Type", ["LLM", "GenAI", "Traditional ML", "Other"])
    model_type = st.selectbox("Model Type", ["Classifier", "RAG", "Multi-modal", "Agent", "Other"])
    model_source = st.selectbox("Model Source", ["Open-source", "Vendor", "Fine-tuned", "Proprietary", "Other"])
    model_updates = st.radio("Is model regularly updated?", ["Yes", "No"])

    st.header("☁️ Infrastructure")
    infra = st.selectbox("Deployment Infra", ["AWS", "Azure", "GCP", "On-prem", "Edge", "Other"])
    exposure = st.selectbox("Exposure Level", ["Public", "Internal", "Authenticated"])
    access_control = st.selectbox("Access Control", ["None", "API Key", "OAuth2", "RBAC"])
    isolation = st.selectbox("Model Isolation", ["Container", "Shared Runtime", "VM", "None"])
    logging = st.radio("Logging & Monitoring Enabled?", ["Yes", "No"])
    sandboxing = st.radio("Sandboxing in Place?", ["Yes", "No"])

    st.header("📊 Data")
    training_data = st.multiselect("Training Data Includes", ["Public", "Internal", "PII", "PHI", "Synthetic"])
    realtime = st.radio("Real-time Inference?", ["Yes", "No"])
    user_influence = st.radio("User influence on model?", ["Yes", "No"])
    external_sources = st.radio("Model uses external data (RAG, scraping)?", ["Yes", "No"])

    st.header("🔁 Input/Output")
    input_validation = st.selectbox("Input Validation", ["None", "Regex", "Schema", "Semantic"])
    output_filtering = st.selectbox("Output Filtering", ["None", "Keyword", "Vector", "Moderation API"])
    output_type = st.multiselect("Output Type", ["Text", "Image", "Code", "JSON", "Recommendation"])
    prompt_template = st.radio("Are prompts templated?", ["Yes", "No"])
    direct_query = st.radio("Can users query model directly?", ["Yes", "No"])
    auto_action = st.radio("Are model outputs used automatically?", ["Yes", "No"])
    can_override = st.radio("Can outputs be overridden?", ["Yes", "No"])
    plugin_access = st.radio("Model accesses tools/plugins?", ["Yes", "No"])

    st.header("🔐 Security")
    waf = st.radio("WAF / API Gateway Enabled?", ["Yes", "No"])
    llm_firewall = st.multiselect("LLM Guardrails", ["None", "OpenAI Moderation", "Rebuff", "Prompt Armor", "Custom"])
    adv_testing = st.radio("Adversarial Testing Done?", ["Yes", "No"])
    red_team = st.radio("Red Team Assessment Done?", ["Yes", "No"])

    st.header("👥 User & Actor Model")
    users = st.multiselect("User Types", ["Internal", "Anonymous", "Authenticated", "Customer", "Partner", "Other"])

    submitted = st.form_submit_button("Evaluate Threats")

if submitted:
    inputs = {
        "project_name": project_name,
        "description": description,
        "ai_type": ai_type,
        "model_type": model_type,
        "model_source": model_source,
        "model_updates": model_updates,
        "infra": infra,
        "exposure": exposure,
        "access_control": access_control,
        "isolation": isolation,
        "logging": logging,
        "sandboxing": sandboxing,
        "training_data": training_data,
        "realtime": realtime,
        "user_influence": user_influence,
        "external_sources": external_sources,
        "input_validation": input_validation,
        "output_filtering": output_filtering,
        "output_type": output_type,
        "prompt_template": prompt_template,
        "direct_query": direct_query,
        "auto_action": auto_action,
        "can_override": can_override,
        "plugin_access": plugin_access,
        "waf": waf,
        "llm_firewall": llm_firewall,
        "adversarial_testing": adv_testing,
        "red_team": red_team,
        "users": users
    }

    threats = evaluate_threats(inputs)

    st.header("🛡️ Threat Report")
    if threats:
        for t in threats:
            st.markdown(f"### 🚨 {t['threat']}")
            st.markdown(f"**Description:** {t['description']}")
            st.markdown(f"**OWASP Mapping:** {t['owasp']}")
            st.markdown(f"**MITRE Tactic:** {t['mitre']}")
            st.markdown(f"**NIST Impact:** {', '.join(t['nist'])}")
            st.markdown(f"**Mitigation:** {t['mitigation']}")
            st.markdown(f"**Compliance Risks:** {', '.join(t['compliance'])}")
            if "attack_path" in t:
                st.markdown("**Attack Path:**")
                for step in t["attack_path"]:
                    st.markdown(f"⬇️ **{step}**")
            st.markdown("---")
    else:
        st.success("✅ No major threats found based on current rules.")

    # === CIA Radar ===
    cia_all = [c for t in threats for c in t["nist"]]
    cia_counts = Counter(cia_all)
    categories = ["Confidentiality", "Integrity", "Availability", "Abuse"]
    values = [cia_counts.get(c, 0) for c in categories]
    values += values[:1]
    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(r=values, theta=categories + [categories[0]], fill='toself', name='CIA Coverage'))
    fig.update_layout(title="🔐 CIA + Abuse Coverage", showlegend=False)
    st.plotly_chart(fig)

    # === MITRE Chart ===
    mitre_hits = [t["mitre"] for t in threats]
    mitre_counts = Counter(mitre_hits)
    mitre_fig = go.Figure([go.Bar(x=list(mitre_counts.keys()), y=list(mitre_counts.values()), marker_color='indianred')])
    mitre_fig.update_layout(title="📊 MITRE ATLAS Tactic Mapping", xaxis_title="Tactic", yaxis_title="Count")
    st.plotly_chart(mitre_fig)

