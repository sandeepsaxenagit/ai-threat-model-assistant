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
    user_influence = st.radio("Can users influence training or inference data? (e.g., via feedback loops)", ["Yes", "No"])

    st.header("☁️ Deployment & Exposure")
    infra = st.selectbox("Infrastructure", ["AWS", "GCP", "Azure", "On-prem", "Edge"])
    exposure = st.selectbox("Exposure", ["Public", "Internal-only", "Authenticated Users Only"])
    access_control = st.selectbox("Access Control", ["None", "Token-based", "Role-based"])
    waf = st.radio("WAF or API Gateway present?", ["Yes", "No"])

    st.header("🛡️ Infrastructure Security")
    data_encrypted_at_rest = st.radio("Is training/inference data encrypted at rest?", ["Yes", "No"])
    artifacts_encrypted_at_rest = st.radio("Are model artifacts (e.g., weights) encrypted at rest?", ["Yes", "No"])
    env_patching_scanning = st.radio("Is the model's environment (containers/VMs) regularly patched and scanned?", ["Yes", "No"])
    secrets_managed_securely = st.radio("Are secrets (API keys, credentials) managed securely (e.g., using a secrets manager)?", ["Yes", "No"])
    network_segmentation = st.radio("Is network segmentation applied to model deployment environments?", ["Yes", "No"])

    st.header("🧪 Model Behavior & Integration")
    outputs = st.multiselect("Model Outputs", ["Text", "Image", "Code", "Labels", "Recommendations"])
    users = st.multiselect("Primary Users", ["Internal", "Customers", "Anonymous"])
    direct_query = st.radio("Can users query the model directly?", ["Yes", "No"])
    auto_action = st.radio("Are outputs auto-used in decisions?", ["Yes", "No"])
    plugin_access = st.radio("Can model access tools/plugins?", ["Yes", "No"])
    external_systems = st.radio("Can model access external systems?", ["Yes", "No"])
    can_override = st.radio("Can outputs be overridden by human review?", ["Yes", "No"])

    st.header("🚧 Core Security Controls")
    input_validation = st.radio("Input validated before inference?", ["Yes", "No"])
    output_filtering = st.radio("Output filtered before showing?", ["Yes", "No"])
    prompt_template = st.selectbox("Prompt strategy (for LLMs)", ["Free-form", "Templated"])
    llm_firewall = st.multiselect("LLM Specific Guardrails Used", ["None", "OpenAI Moderation API", "Rebuff", "Guardrails.ai", "Prompt Armor"])
    sandboxing = st.radio("Is plugin/tool execution sandboxed?", ["Yes", "No"])
    logging = st.radio("Logs & Monitoring enabled?", ["Yes", "No"])
    adversarial_test_types = st.multiselect("Adversarial Testing Types Performed?", ["None", "Data Poisoning", "Model Evasion", "Model Inversion", "Membership Inference"])
    adversarial_test_tools = st.multiselect("Adversarial Testing Tools Used?", ["None", "CleverHans", "IBM ART", "Microsoft Counterfit", "Custom Scripts"])
    red_team = st.radio("Red teaming conducted?", ["Yes", "No"])

    st.header("📋 Compliance & Governance")
    compliance = st.multiselect("Compliance followed", ["None", "GDPR", "HIPAA", "CCPA", "SOC2", "PCI"])
    model_card = st.radio("Model documentation maintained (Model Card)?", ["Yes", "No"])
    rl_feedback = st.radio("Reinforcement Learning from Human Feedback (RLHF) used?", ["Yes", "No"])
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
        "data_encrypted_at_rest": data_encrypted_at_rest,
        "artifacts_encrypted_at_rest": artifacts_encrypted_at_rest,
        "env_patching_scanning": env_patching_scanning,
        "secrets_managed_securely": secrets_managed_securely,
        "network_segmentation": network_segmentation,
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
        "adversarial_test_types": adversarial_test_types,
        "adversarial_test_tools": adversarial_test_tools,
        "red_team": red_team,
        "compliance": compliance,
        "model_card": model_card,
        "rl_feedback": rl_feedback,
        "output_watermark": output_watermark
    }

    threats = evaluate_threats(inputs)

    # =====================================
    # 📝 Project Summary
    # =====================================
    st.header("📝 Project Summary")
    st.markdown(f"**Project Name:** {project_name if project_name else 'N/A'}")
    st.markdown(f"**Description:** {description if description else 'N/A'}")
    st.markdown(f"**AI Type:** {ai_type}")
    st.markdown(f"**Model Type:** {model_type}")
    st.markdown(f"**Exposure:** {exposure}")
    st.markdown(f"**Key Compliance:** {', '.join(compliance) if compliance else 'None'}")
    st.markdown("---")


    # --- OWASP Top 10 Table Logic ---

    OWASP_LLM_TOP_10_DESCRIPTION_MAP = {
        "LLM01": "Prompt Injection",
        "LLM02": "Insecure Output Handling",
        "LLM03": "Training Data Poisoning",
        "LLM04": "Model Denial of Service",
        "LLM05": "Supply Chain Vulnerabilities",
        "LLM06": "Sensitive Information Disclosure",
        "LLM07": "Insecure Plugin Design",
        "LLM08": "Excessive Agency",
        "LLM09": "Overreliance",
        "LLM10": "Model Theft",
    }

    OWASP_ML_TOP_10_DESCRIPTION_MAP = {
        "ML01": "Training Data Poisoning",
        "ML02": "Model Theft",
        "ML03": "Inference API Abuse",
        "ML04": "Adversarial Examples",
        "ML05": "Unauthorized Access to ML Models",
        "ML06": "Data Leakage (Sensitive Data Exposure)",
        "ML07": "Insufficient Data Privacy Controls",
        "ML08": "Insecure ML Deployment",
        "ML09": "Inadequate Logging and Monitoring",
        "ML10": "Lack of Governance",
    }

    found_owasp_ids = set()
    for threat_list in [threats["basic"], threats["chained"]]:
        for threat in threat_list:
            owasp_id_part = threat["owasp"].split(':')[0].strip()
            found_owasp_ids.add(owasp_id_part)

    def display_owasp_table(title, owasp_map, found_ids):
        st.header(title)
        table_html = "<table style='width:100%; border-collapse: collapse;'>"
        table_html += "<tr style='background-color:#f0f2f6;'>"\
                      "<th style='padding: 8px; border: 1px solid #ddd; text-align: left;'>ID</th>"\
                      "<th style='padding: 8px; border: 1px solid #ddd; text-align: left;'>Threat</th>"\
                      "<th style='padding: 8px; border: 1px solid #ddd; text-align: left;'>Status</th>"\
                      "</tr>"

        for owasp_id, description in owasp_map.items():
            is_found = owasp_id in found_ids
            row_style = "color: red; font-weight: bold;" if is_found else ""
            status_text = "🚨 Found" if is_found else "✅ Not Found"
            
            table_html += f"<tr style='{row_style}'>" \
                          f"<td style='padding: 8px; border: 1px solid #ddd;'>{owasp_id}</td>" \
                          f"<td style='padding: 8px; border: 1px solid #ddd;'>{description}</td>" \
                          f"<td style='padding: 8px; border: 1px solid #ddd;'>{status_text}</td>" \
                          "</tr>"
        table_html += "</table>"
        st.markdown(table_html, unsafe_allow_html=True)

    show_llm_table_by_selection = inputs["ai_type"] in ["LLM", "Generative AI"]
    show_ml_table_by_selection = inputs["ai_type"] == "Traditional ML"

    has_llm_threats_detected = any(id.startswith("LLM") for id in found_owasp_ids)
    has_ml_threats_detected = any(id.startswith("ML") for id in found_owasp_ids)

    if has_llm_threats_detected and has_ml_threats_detected:
        display_owasp_table("📊 OWASP LLM Top 10 Risks", OWASP_LLM_TOP_10_DESCRIPTION_MAP, found_owasp_ids)
        display_owasp_table("📊 OWASP ML Top 10 Risks", OWASP_ML_TOP_10_DESCRIPTION_MAP, found_owasp_ids)
    elif show_llm_table_by_selection:
        display_owasp_table("📊 OWASP LLM Top 10 Risks", OWASP_LLM_TOP_10_DESCRIPTION_MAP, found_owasp_ids)
    elif show_ml_table_by_selection:
        display_owasp_table("📊 OWASP ML Top 10 Risks", OWASP_ML_TOP_10_DESCRIPTION_MAP, found_owasp_ids)


    # ========================
    # 🚨 Display Individual Threats
    # ========================
    if threats["basic"]:
        st.header("🚨 Individual Threats")
        basic_threat_count = 0
        for threat in threats["basic"]:
            basic_threat_count += 1
            with st.container(border=True): # Start of the box for each threat
                st.subheader(f"{basic_threat_count}. {threat['threat']}")
                st.markdown(f"**Reason for Threat:** <span style='color:red;'>{threat['reason']}</span>", unsafe_allow_html=True)
                st.markdown(f"**Description:** {threat['description']}")
                st.markdown(f"**OWASP:** {threat['owasp']}")
                st.markdown(f"**MITRE ATLAS:** {threat['mitre']}")
                st.markdown(f"**NIST:** {', '.join(threat['nist'])}")
                st.markdown(f"**Mitigation:** {threat['mitigation']}")
                st.markdown(f"**Compliance Risks:** {', '.join(threat['compliance'])}")
                st.markdown("**Attack Path:**")
                for step in threat["attack_path"]:
                    st.markdown(f"⬇️ {step}")
            st.markdown("---") # Separator between boxes

    # ==========================
    # 🔗 Display Threat Chains
    # ==========================
    if threats["chained"]:
        st.header("🔗 Threat Chains")
        chained_threat_count = 0
        for threat in threats["chained"]:
            chained_threat_count += 1
            with st.container(border=True): # Start of the box for each threat
                st.subheader(f"{chained_threat_count}. {threat['threat']}")
                st.markdown(f"**Reason for Threat:** <span style='color:red;'>{threat['reason']}</span>", unsafe_allow_html=True)
                st.markdown(f"**Description:** {threat['description']}")
                st.markdown(f"**OWASP:** {threat['owasp']}")
                st.markdown(f"**MITRE ATLAS:** {threat['mitre']}")
                st.markdown(f"**NIST:** {', '.join(threat['nist'])}")
                st.markdown(f"**Mitigation:** {threat['mitigation']}")
                st.markdown(f"**Compliance Risks:** {', '.join(threat['compliance'])}")
                st.markdown("**Attack Path:**")
                for step in threat["attack_path"]:
                    st.markdown(f"⬇️ {step}")

                st.markdown("---")
                st.subheader(f"NIST Impact for: {threat['threat']}")
                
                current_threat_nist_counts = Counter(threat["nist"])
                nist_categories = ['Confidentiality', 'Integrity', 'Availability', 'Abuse']
                nist_values = [current_threat_nist_counts.get(c, 0) for c in nist_categories]

                nist_fig_single = go.Figure([go.Bar(
                    x=nist_categories,
                    y=nist_values,
                    marker_color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728']
                )])
                nist_fig_single.update_layout(
                    title_text=f"NIST Impact for '{threat['threat']}'",
                    xaxis_title="NIST Principle",
                    yaxis_title="Count",
                    yaxis_range=[0, max(nist_values) + 0.5 if nist_values else 1]
                )
                st.plotly_chart(nist_fig_single)
            st.markdown("---") # Separator between boxes

    # =====================================
    # 📊 NIST CIA + Abuse Radar Chart (Overall)
    # =====================================
    all_nist = []
    for t in threats["basic"] + threats["chained"]:
        all_nist.extend(t["nist"])

    if all_nist:
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
            title="🔐 Overall NIST CIA + Abuse Mapping",
            polar=dict(radialaxis=dict(visible=True)),
            showlegend=False
        )
        st.plotly_chart(radar)
    else:
        st.info("No threats detected, so overall NIST CIA + Abuse Mapping chart is not generated.")


    # =====================================
    # 📊 MITRE ATLAS Tactic Frequency Chart (Overall)
    # =====================================
    mitre_counts = Counter()
    for t in threats["basic"] + threats["chained"]:
        mitre_counts[t["mitre"]] += 1

    if mitre_counts:
        mitre_fig = go.Figure([go.Bar(
            x=list(mitre_counts.keys()),
            y=list(mitre_counts.values()),
            marker_color='darkred'
        )])
        mitre_fig.update_layout(
            title="⚔️ Overall MITRE ATLAS Tactic Frequency",
            xaxis_title="Tactic",
            yaxis_title="Count"
        )
        st.plotly_chart(mitre_fig)
    else:
        st.info("No threats detected, so overall MITRE ATLAS Tactic Frequency chart is not generated.")

    st.markdown("---")
    st.info("💡 **Tip:** To save this report, use your browser's print-to-PDF function (usually Ctrl+P or Cmd+P and select 'Save as PDF').")
