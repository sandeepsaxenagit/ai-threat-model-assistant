import streamlit as st
from rules_engine import evaluate_threats
from collections import Counter
import plotly.graph_objects as go
import plotly.io as pio

st.set_page_config(page_title="🛡️ AI Threat Modeling Assistant", layout="wide")
st.title("🛡️ AI Threat Modeling Assistant")

st.markdown("Answer the following to generate your AI threat report:")

with st.form("threat_model_form"):
    st.header("📘 General Info")
    project_name = st.text_input("Project Name")
    description = st.text_area("Project Description")

    st.header("🧠 Model Details")
    ai_type = st.selectbox("AI Type", ["Traditional ML", "Generative AI", "LLM"])
    model_type = st.selectbox("Model Type", ["Classifier", "CNN", "Transformer", "LLM", "Custom"])
    model_source = st.selectbox("Model Source", ["Open-source", "Pretrained (Vendor)", "Fine-tuned", "Proprietary"])
    model_updates = st.radio("Is the model updated regularly?", ["Yes", "No"])

    st.header("📊 Data")
    training_data = st.multiselect("Training Data Type", ["Public", "Internal", "PII", "PHI", "Synthetic"])
    external_sources = st.radio("Uses external sources (e.g. RAG)?", ["Yes", "No"])
    real_time = st.radio("Real-time inputs during inference?", ["Yes", "No"])
    user_influence = st.radio("Can users influence training or inference data?", ["Yes", "No"])

    st.header("☁️ Deployment & Exposure")
    infra = st.selectbox("Infrastructure", ["AWS", "GCP", "Azure", "On-prem", "Edge"])
    exposure = st.selectbox("Exposure", ["Public", "Internal-only", "Authenticated Users Only"])
    access_control = st.selectbox("Access Control", ["None", "Token-based", "Role-based"])
    waf = st.radio("WAF or API Gateway present?", ["Yes", "No"])

    st.header("🧪 Model Behavior & Integration")
    outputs = st.multiselect("Model Outputs", ["Text", "Image", "Code", "Labels", "Recommendations"])
    users = st.multiselect("Primary Users", ["Internal", "Customers", "Anonymous"])
    direct_query = st.radio("Can users query the model directly?", ["Yes", "No"])
    auto_action = st.radio("Are outputs auto-used in decisions?", ["Yes", "No"])
    plugin_access = st.radio("Can model access tools/plugins?", ["Yes", "No"])
    external_systems = st.radio("Can model access external systems?", ["Yes", "No"])
    can_override = st.radio("Can outputs be overridden?", ["Yes", "No"])

    st.header("🛡️ Security Controls")
    input_validation = st.radio("Input validated before inference?", ["Yes", "No"])
    output_filtering = st.radio("Output filtered before showing?", ["Yes", "No"])
    prompt_template = st.selectbox("Prompt strategy", ["Free-form", "Templated"])
    llm_firewall = st.multiselect("LLM Guardrails Used", ["None", "OpenAI Moderation API", "Rebuff", "Guardrails.ai", "Prompt Armor"])
    sandboxing = st.radio("Is plugin/tool execution sandboxed?", ["Yes", "No"])
    logging = st.radio("Logs & Monitoring enabled?", ["Yes", "No"])
    adversarial_testing = st.radio("Adversarial testing performed?", ["Yes", "No"])
    red_team = st.radio("Red teaming conducted?", ["Yes", "No"])

    st.header("📋 Compliance & Governance")
    compliance = st.multiselect("Compliance followed", ["None", "GDPR", "HIPAA", "CCPA", "SOC2", "PCI"])
    model_card = st.radio("Model documentation maintained (Model Card)?", ["Yes", "No"])
    rl_feedback = st.radio("RLHF used?", ["Yes", "No"])
    output_watermark = st.radio("Output traceable/watermarked?", ["Yes", "No"])

    submitted = st.form_submit_button("Generate Threat Report")

if submitted:
    st.success("✅ Generating threat model report...")

    inputs = {
        "project_name": project_name,
        "description": description,
        "ai_type": ai_type,
        "model_type": model_type,
        "model_source": model_source,
        "model_updates": model_updates,
        "training_data": training_data,
        "external_sources": external_sources,
        "real_time": real_time,
        "user_influence": user_influence,
        "infra": infra,
        "exposure": exposure,
        "access_control": access_control,
        "waf": waf,
        "outputs": outputs,
        "users": users,
        "direct_query": direct_query,
        "auto_action": auto_action,
        "plugin_access": plugin_access,
        "external_systems": external_systems,
        "can_override": can_override,
        "input_validation": input_validation,
        "output_filtering": output_filtering,
        "prompt_template": prompt_template,
        "llm_firewall": llm_firewall,
        "sandboxing": sandboxing,
        "logging": logging,
        "adversarial_testing": adversarial_testing,
        "red_team": red_team,
        "compliance": compliance,
        "model_card": model_card,
        "rl_feedback": rl_feedback,
        "output_watermark": output_watermark
    }

    threats = evaluate_threats(inputs)

    # ========================
    # 🚨 Display Basic Threats
    # ========================
    if threats["basic"]:
        st.header("🚨 Threats")
        for threat in threats["basic"]:
            st.subheader(threat["threat"])
            st.markdown(f"**Description:** {threat['description']}")
            st.markdown(f"**OWASP:** {threat['owasp']}")
            st.markdown(f"**MITRE ATLAS:** {threat['mitre']}")
            st.markdown(f"**NIST:** {', '.join(threat['nist'])}")
            st.markdown(f"**Mitigation:** {threat['mitigation']}")
            st.markdown(f"**Compliance Risks:** {', '.join(threat['compliance'])}")
            st.markdown("**Attack Path:**")
            for step in threat["attack_path"]:
                st.markdown(f"⬇️ {step}")

    # ==========================
    # 🔗 Display Threat Chains
    # ==========================
    if threats["chained"]:
        st.header("🔗 Threat Chain")
        for threat in threats["chained"]:
            st.subheader(threat["threat"])
            st.markdown(f"**Description:** {threat['description']}")
            st.markdown(f"**OWASP:** {threat['owasp']}")
            st.markdown(f"**MITRE ATLAS:** {threat['mitre']}")
            st.markdown(f"**NIST:** {', '.join(threat['nist'])}")
            st.markdown(f"**Mitigation:** {threat['mitigation']}")
            st.markdown(f"**Compliance Risks:** {', '.join(threat['compliance'])}")
            st.markdown("**Attack Path:**")
            for step in threat["attack_path"]:
                st.markdown(f"⬇️ {step}")

    # =====================================
    # 📊 NIST CIA + Abuse Radar Chart
    # =====================================
    all_nist = []
    for t in threats["basic"] + threats["chained"]:
        all_nist.extend(t["nist"])

    cia_counts = Counter(all_nist)
    categories = ['Confidentiality', 'Integrity', 'Availability', 'Abuse']
    values = [cia_counts.get(c, 0) for c in categories]
    values += values[:1]

    radar = go.Figure()
    radar.add_trace(go.Scatterpolar(
        r=values,
        theta=categories + [categories[0]],
        fill='toself',
        name='CIA+Abuse',
        line=dict(color='royalblue')
    ))
    radar.update_layout(
        title="🔐 NIST CIA + Abuse Mapping",
        polar=dict(radialaxis=dict(visible=True)),
        showlegend=False
    )
    st.plotly_chart(radar)

    # =====================================
    # 📊 MITRE ATLAS Tactic Frequency Chart
    # =====================================
    mitre_counts = Counter()
    for t in threats["basic"] + threats["chained"]:
        mitre_counts[t["mitre"]] += 1

    mitre_fig = go.Figure([go.Bar(
        x=list(mitre_counts.keys()),
        y=list(mitre_counts.values()),
        marker_color='darkred'
    )])
    mitre_fig.update_layout(
        title="⚔️ MITRE ATLAS Tactic Frequency",
        xaxis_title="Tactic",
        yaxis_title="Count"
    )
    st.plotly_chart(mitre_fig)

