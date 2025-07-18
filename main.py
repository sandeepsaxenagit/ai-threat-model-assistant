import streamlit as st
from rules_engine import evaluate_threats # Import evaluate_threats from rules_engine

from collections import Counter
import plotly.graph_objects as go
import plotly.io as pio

# --- Define initial_values globally at the very top to ensure scope ---
initial_values = {
    'project_name': "", 'description': "", 'ai_type': "Traditional ML",
    'model_type': "Classifier", 'model_source': "Open-source", 'model_updates': "No",
    'training_data': [], 'external_sources': "No", 'real_time': "No",
    'user_influence': "No", 'infra': "AWS", 'exposure': "Public",
    'access_control': "None", 'waf': "No", 'data_encrypted_at_rest': "No",
    'artifacts_encrypted_at_rest': "No", 'env_patching_scanning': "No",
    'secrets_managed_securely': "No", 'network_segmentation': "No",
    'outputs': [], 'users': [], 'direct_query': "No", 'auto_action': "No",
    'plugin_access': "No", 'external_systems': "No", 'can_override': "No",
    'input_validation': "No", 'output_filtering': "No", 'prompt_template': "Not Applicable",
    'llm_firewall': ["None"], 'sandboxing': "No", 'logging': "No", 'auditing': "No",
    'adversarial_test_types': ["None"], 'adversarial_test_tools': ["None"],
    'red_team': "No", 'model_card': "No", 'rl_feedback': "No", 'output_watermarking': "No",
    'explainability': "No",
    'agentic_autonomous': "Not Applicable", 'agentic_tool_access': "Not Applicable",
    'agentic_logging': "Not Applicable", 'agentic_hitl': "Not Applicable",
    'agentic_sensitive_data': "Not Applicable", 'agentic_malicious_input_detection': "Not Applicable"
}


# Set Plotly default template for a polished look
pio.templates.default = "plotly_white"

st.set_page_config(page_title="🛡️ AI Threat Modeling Assistant", layout="wide", initial_sidebar_state="expanded")

# --- Cool Banner (using HTML/CSS for background color effect and adjusted whitespace) ---
st.markdown(
    """
    <style>
    /* Remove default Streamlit top margin more aggressively */
    .stApp {
        margin-top: -75px; /* Adjust as needed, play with this value */
    }
    .banner {
        background: linear-gradient(to right, #4682B4, #5F9EA0); /* SteelBlue to CadetBlue gradient */
        padding: 15px 10px; /* Reduced padding for less whitespace */
        border-radius: 8px;
        text-align: center;
        margin-bottom: 20px; /* Reduced margin */
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        color: white;
    }
    .banner h1 {
        font-size: 2.5em; /* Slightly smaller font size */
        margin-bottom: 0px;
        text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.3);
    }
    .banner h3 {
        font-size: 1em; /* Slightly smaller font size */
        margin-top: 5px;
        opacity: 0.9;
    }
    </style>
    <div class="banner">
        <h1>🛡️ AI Threat Modeling Assistant</h1>
        <h3>Gain actionable insights into your project's security posture.</h3>
    </div>
    """,
    unsafe_allow_html=True
)

st.markdown("Answer the following questions to generate a comprehensive threat report for your AI/ML project. Identify vulnerabilities related to **AI ML threat modeling**, **generative AI security**, and **agentic AI risks**.")

# --- Left Sidebar for Useful Links ---
with st.sidebar:
    st.header("💡 About This Tool")
    st.markdown("This tool provides a comprehensive, accessible assessment of potential security threats in your AI/ML projects based on common industry frameworks.")
    st.markdown("Feel free to contribute or suggest improvements on [GitHub](https://github.com/sandeepsaxenagit/ai-threat-model-assistant)!")
    st.markdown("---")
    st.header("🔗 Useful Links")
    st.markdown("### AI/ML Security Resources")
    st.markdown("- [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)")
    st.markdown("- [OWASP Top 10 for Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)")
    st.markdown("- [MITRE ATLAS](https://atlas.mitre.org/)")
    st.markdown("- [AI Risk and Threat Taxonomy](https://csrc.nist.gov/csrc/media/Presentations/2024/ai-risk-and-threat-taxonomy/Vassilev-Day1-AI_Risk_and_Threat_Taxonomy.pdf)")
    st.markdown("- [Prompt Injection Explained](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)")
    st.markdown("---")


# --- Initialize all form variables in st.session_state (Robust Initialization) ---
# This loop runs on every rerun, ensuring defaults are set if keys are missing.
for key, default_value in initial_values.items():
    if key not in st.session_state:
        st.session_state[key] = default_value

# --- AI Type Selection (Outside Form for Immediate Conditional Rendering) ---
st.markdown("---")
st.header("🧠 Model Type Selection")
st.info("💡 **Select your AI Type first to dynamically tailor the questions below.**")
st.session_state.ai_type = st.radio(
    "**Select AI Type to Tailor Questions**",
    ["Traditional ML", "Generative AI (e.g., Image/Audio Generation)", "Large Language Model (LLM)", "Agentic AI (e.g., Autonomous Agents)"],
    index=["Traditional ML", "Generative AI (e.g., Image/Audio Generation)", "Large Language Model (LLM)", "Agentic AI (e.g., Autonomous Agents)"].index(st.session_state.ai_type),
    horizontal=True,
    help="This crucial selection determines which specific security questions are relevant to your project.",
    key="ai_type_selector_outside_form"
)
st.markdown("---") # Visual separator


# --- Main Content Form ---
with st.form("threat_model_form"):
    st.header("📘 Project Information")
    st.session_state.project_name = st.text_input("Project Name", value=st.session_state.project_name, help="A descriptive name for your AI/ML project.")
    st.session_state.description = st.text_area("Project Description", value=st.session_state.description, help="Briefly describe your project's purpose and functionality.")

    st.markdown("---")
    st.header("🧠 Model Details (Continued)")
    # Model type options aligned with AI Type categories
    st.session_state.model_type = st.selectbox(
        "Model Type", 
        ["Classifier", "CNN", "Transformer", "LLM (Generic)", "LLM (Custom/Fine-tuned)", "Other Custom"],
        index=["Classifier", "CNN", "Transformer", "LLM (Generic)", "LLM (Custom/Fine-tuned)", "Other Custom"].index(st.session_state.model_type), 
        help="Specify the architectural type of your model."
    )
    st.session_state.model_source = st.selectbox("Model Source", ["Open-source", "Pretrained (Vendor)", "Fine-tuned", "Proprietary"], index=["Open-source", "Pretrained (Vendor)", "Fine-tuned", "Proprietary"].index(st.session_state.model_source), help="Where did your base model originate.")
    st.session_state.model_updates = st.radio("Is the model updated regularly?", ["Yes", "No"], index=0 if st.session_state.model_updates == "Yes" else 1, horizontal=True, help="Does your model undergo continuous training or updates?")

    # --- Issue 4: Model Type and AI Type Mismatch Validation ---
    if st.session_state.ai_type == "Traditional ML" and \
       st.session_state.model_type in ["Transformer", "LLM (Generic)", "LLM (Custom/Fine-tuned)"]:
        st.warning(
            "⚠️ **Validation Warning:** A '{st.session_state.model_type}' model type is typically not classified under 'Traditional ML'. "
            "Consider adjusting your AI Type or Model Type for more accurate threat modeling."
        )
    elif st.session_state.ai_type == "Generative AI (e.g., Image/Audio Generation)" and \
         st.session_state.model_type in ["Classifier", "CNN", "LLM (Generic)", "LLM (Custom/Fine-tuned)"]: # Allow LLM types under GenAI, but warn if not common for non-LLM GenAI
        st.warning(
            "⚠️ **Validation Warning:** For 'Generative AI (e.g., Image/Audio Generation)', '{st.session_state.model_type}' might not be the most appropriate model type. "
            "If your Generative AI uses LLMs, select 'Large Language Model (LLM)' as AI Type. Otherwise, consider 'Transformer' or 'Other Custom'."
        )
    elif st.session_state.ai_type == "Large Language Model (LLM)" and \
         st.session_state.model_type not in ["Transformer", "LLM (Generic)", "LLM (Custom/Fine-tuned)"]:
        st.warning(
            "⚠️ **Validation Warning:** When 'Large Language Model (LLM)' is selected as AI Type, 'Transformer' or 'LLM' based Model Types are expected."
        )
    elif st.session_state.ai_type == "Agentic AI (e.g., Autonomous Agents)" and \
         st.session_state.model_type not in ["Transformer", "LLM (Generic)", "LLM (Custom/Fine-tuned)", "Other Custom"]: # Allow custom for agents
        st.warning(
            "⚠️ **Validation Warning:** For 'Agentic AI', '{st.session_state.model_type}' might not be the most appropriate model type. Consider 'Transformer', 'LLM (Generic)', 'LLM (Custom/Fine-tuned)', or 'Other Custom'."
        )
            
    st.markdown("---")
    st.header("📊 Data Considerations")
    st.session_state.training_data = st.multiselect("Training Data Type", ["Public", "Internal", "PII", "PHI", "Synthetic"], default=st.session_state.training_data, help="What kind of data is used for training? (Select all that apply)")
    st.session_state.external_sources = st.radio("Uses external sources (e.g., RAG, external APIs) during inference?", ["Yes", "No"], index=0 if st.session_state.external_sources == "Yes" else 1, horizontal=True, help="Does your model fetch information from outside its core dataset during operation?")
    st.session_state.real_time = st.radio("Processes real-time inputs during inference? (e.g., sensor data, live user input)", ["Yes", "No"], index=0 if st.session_state.real_time == "Yes" else 1, horizontal=True, help="Is your model processing data as it comes in, or batch processing?")
    st.session_state.user_influence = st.radio("Can users influence training or inference data? (e.g., via feedback loops, user-generated content)", ["Yes", "No"], index=0 if st.session_state.user_influence == "Yes" else 1, horizontal=True, help="Can user interactions directly or indirectly alter the model's behavior or data?")

    st.markdown("---")
    st.header("🚀 Deployment & Operations")
    st.session_state.infra = st.selectbox("Infrastructure", ["AWS", "GCP", "Azure", "On-prem", "Edge"], index=["AWS", "GCP", "Azure", "On-prem", "Edge"].index(st.session_state.infra), help="Where is your model deployed?")
    st.session_state.exposure = st.selectbox("Exposure", ["Public", "Internal-only", "Authenticated Users Only"], index=["Public", "Internal-only", "Authenticated Users Only"].index(st.session_state.exposure), help="How accessible is your model's API/interface?")
    st.session_state.access_control = st.selectbox("Access Control", ["None", "Token-based", "Role-based"], index=["None", "Token-based", "Role-based"].index(st.session_state.access_control), help="Type of access control for the model.")
    st.session_state.waf = st.radio("WAF or API Gateway present?", ["Yes", "No"], index=0 if st.session_state.waf == "Yes" else 1, horizontal=True, help="Is there a web application firewall or API gateway protecting the model endpoint?")

    st.markdown("---")
    st.header("🛡️ Infrastructure Security")
    st.session_state.data_encrypted_at_rest = st.radio("Is training/inference data encrypted at rest?", ["Yes", "No"], index=0 if st.session_state.data_encrypted_at_rest == "Yes" else 1, horizontal=True, help="Is data stored on disk encrypted?")
    st.session_state.artifacts_encrypted_at_rest = st.radio("Are model artifacts (e.g., weights) encrypted at rest?", ["Yes", "No"], index=0 if st.session_state.artifacts_encrypted_at_rest == "Yes" else 1, horizontal=True, help="Are stored model files encrypted?")
    st.session_state.env_patching_scanning = st.radio("Is the model's environment (containers/VMs) regularly patched and scanned?", ["Yes", "No"], index=0 if st.session_state.env_patching_scanning == "Yes" else 1, horizontal=True, help="Are underlying systems kept up-to-date with security patches?")
    st.session_state.secrets_managed_securely = st.radio("Are secrets (API keys, credentials) managed securely (e.g., using a secrets manager)?", ["Yes", "No"], index=0 if st.session_state.secrets_managed_securely == "Yes" else 1, horizontal=True, help="Are sensitive credentials stored and accessed securely?")
    st.session_state.network_segmentation = st.radio("Is network segmentation applied to model deployment environments?", ["Yes", "No"], index=0 if st.session_state.network_segmentation == "Yes" else 1, horizontal=True, help="Are model environments isolated from other parts of your network?")

    st.markdown("---")
    st.header("🧪 Model Behavior & Integration")
    st.session_state.outputs = st.multiselect("Model Outputs", ["Text", "Image", "Code", "Labels", "Recommendations"], default=st.session_state.outputs, help="What kind of outputs does your model generate? (Select all that apply)")
    st.session_state.users = st.multiselect("Primary Users", ["Internal", "Customers", "Anonymous"], default=st.session_state.users, help="Who are the main consumers of the model's outputs? (Select all that apply)")
    st.session_state.direct_query = st.radio("Can users query the model directly?", ["Yes", "No"], index=0 if st.session_state.direct_query == "Yes" else 1, horizontal=True, help="Can users directly send inputs to the model's API?")
    st.session_state.auto_action = st.radio("Are outputs auto-used in decisions/actions without human review?", ["Yes", "No"], index=0 if st.session_state.auto_action == "Yes" else 1, horizontal=True, help="Does the model's output trigger automated actions?")
    st.session_state.plugin_access = st.radio("Can model access tools/plugins?", ["Yes", "No"], index=0 if st.session_state.plugin_access == "Yes" else 1, horizontal=True, help="Can your model interact with external functionalities (e.g., web browsers, code interpreters)?")
    st.session_state.external_systems = st.radio("Can model access external systems?", ["Yes", "No"], index=0 if st.session_state.external_systems == "Yes" else 1, horizontal=True, help="Does your model initiate connections to other systems (e.g., databases, other APIs)?")
    st.session_state.can_override = st.radio("Can outputs be overridden by human review?", ["Yes", "No"], index=0 if st.session_state.can_override == "Yes" else 1, horizontal=True, help="Is there a human-in-the-loop mechanism to correct or approve outputs?")

    st.markdown("---")
    st.header("🚧 Core Security Controls")
    st.session_state.input_validation = st.radio("Input validated before inference?", ["Yes", "No"], index=0 if st.session_state.input_validation == "Yes" else 1, horizontal=True, help="Are inputs checked for malicious content or unexpected formats?")
    st.session_state.output_filtering = st.radio("Output filtered before showing?", ["Yes", "No"], index=0 if st.session_state.output_filtering == "Yes" else 1, horizontal=True, help="Are model outputs checked for sensitive data or harmful content before display?")

    # Conditional LLM-specific questions
    if st.session_state.ai_type in ["Large Language Model (LLM)", "Generative AI (e.g., Image/Audio Generation)", "Agentic AI (e.g., Autonomous Agents)"] or st.session_state.model_type in ["LLM (Generic)", "LLM (Custom/Fine-tuned)"]: # Enhanced condition
        current_prompt_template_options = ["Free-form", "Templated"]
        current_prompt_template_index = 0
        if st.session_state.prompt_template in current_prompt_template_options:
            current_prompt_template_index = current_prompt_template_options.index(st.session_state.prompt_template)
        st.session_state.prompt_template = st.selectbox("Prompt strategy (for LLMs/Generative AIs)", current_prompt_template_options, index=current_prompt_template_index, help="How are prompts constructed?")
        st.session_state.llm_firewall = st.multiselect("LLM Specific Guardrails Used", ["None", "OpenAI Moderation API", "Rebuff", "Guardrails.ai", "Prompt Armor"], default=st.session_state.llm_firewall, help="Which LLM security tools are employed? (Select all that apply)")
    # No `else` block needed as variables are initialized in session_state at the top

    st.session_state.sandboxing = st.radio("Is plugin/tool execution sandboxed?", ["Yes", "No"], index=0 if st.session_state.sandboxing == "Yes" else 1, horizontal=True, help="Are there security measures to contain plugin actions?")
    st.session_state.logging = st.radio("Logs & Monitoring enabled?", ["Yes", "No"], index=0 if st.session_state.logging == "Yes" else 1, horizontal=True, help="Is there detailed logging to track model behavior and detect anomalies?")
    st.session_state.auditing = st.radio("Are regular security audits and penetration testing performed?", ["Yes", "No"], index=0 if st.session_state.auditing == "Yes" else 1, horizontal=True, help="Are independent security assessments conducted?")
    st.session_state.adversarial_test_types = st.multiselect("Adversarial Testing Types Performed?", ["None", "Data Poisoning", "Model Evasion", "Model Inversion", "Membership Inference"], default=st.session_state.adversarial_test_types, help="Which adversarial testing techniques are applied? (Select all that apply)")
    st.session_state.adversarial_test_tools = st.multiselect("Adversarial Testing Tools Used?", ["None", "CleverHans", "IBM ART", "Microsoft Counterfit", "Custom Scripts"], default=st.session_state.adversarial_test_tools, help="Which tools are used for adversarial testing? (Select all that apply)")
    st.session_state.red_team = st.radio("Red teaming conducted?", ["Yes", "No"], index=0 if st.session_state.red_team == "Yes" else 1, horizontal=True, help="Are dedicated red team exercises performed to find vulnerabilities?")

    st.markdown("---")
    st.header("📋 Governance & Lifecycle")
    st.session_state.model_card = st.radio("Model documentation maintained (Model Card)?", ["Yes", "No"], index=0 if st.session_state.model_card == "Yes" else 1, horizontal=True, help="Is clear documentation about your model's characteristics, risks, and biases available?")
    st.session_state.rl_feedback = st.radio("Reinforcement Learning from Human Feedback (RLHF) used?", ["Yes", "No"], index=0 if st.session_state.rl_feedback == "Yes" else 1, horizontal=True, help="Is human feedback used to refine the model's behavior?")
    st.session_state.output_watermarking = st.radio("Output traceable/watermarked?", ["Yes", "No"], index=0 if st.session_state.output_watermarking == "Yes" else 1, horizontal=True, help="Can model-generated outputs be identified as such?")
    st.session_state.explainability = st.radio("Is there explainability/interpretability for model decisions (e.g., feature importance, rationale)?", ["Yes", "No"], index=0 if st.session_state.explainability == "Yes" else 1, horizontal=True, help="Can you understand why your model makes certain decisions?")

    # --- New section for Agentic AI Specifics (Conditional) ---
    if st.session_state.ai_type == "Agentic AI (e.g., Autonomous Agents)":
        st.markdown("---")
        st.header("🤖 Agentic AI Specifics")
        st.info("These questions are critical for autonomous AI systems that can take actions in the real world or digital environments.")

        st.session_state.agentic_autonomous = st.radio("Does your AI model operate autonomously (e.g., self-planning, self-executing actions without constant human prompting)?", ["Yes", "No"], index=0 if st.session_state.agentic_autonomous == "Yes" else 1, horizontal=True, help="Is the agent capable of independent action sequences?")
        st.session_state.agentic_tool_access = st.radio("Does the agent have access to external tools or APIs (beyond basic model interaction)?", ["Yes", "No"], index=0 if st.session_state.agentic_tool_access == "Yes" else 1, horizontal=True, help="Can the agent call external services, manipulate files, or browse the web?")
        st.session_state.agentic_logging = st.radio("Are the agent's internal thought processes, actions, and decision-making fully logged and auditable?", ["Yes", "No"], index=0 if st.session_state.agentic_logging == "Yes" else 1, horizontal=True, help="Can you reconstruct the agent's chain of reasoning and actions?")
        st.session_state.agentic_hitl = st.radio("Are there clear human-in-the-loop (HITL) review processes or circuit breakers for sensitive agent actions?", ["Yes", "No"], index=0 if st.session_state.agentic_hitl == "Yes" else 1, horizontal=True, help="Can a human intervene or stop the agent before critical actions are taken?")
        st.session_state.agentic_sensitive_data = st.radio("Does the agent handle or process Personally identifiable Information (PII), Protected Health Information (PHI), or other highly sensitive data?", ["Yes", "No"], index=0 if st.session_state.agentic_sensitive_data == "Yes" else 1, horizontal=True, help="Is the agent exposed to regulated or highly confidential data?")
        st.session_state.agentic_malicious_input_detection = st.radio("Does the agent have specific mechanisms to detect and mitigate adversarial attacks (e.g., prompt injection, memory poisoning, goal hijacking)?", ["Yes", "No"], index=0 if st.session_state.agentic_malicious_input_detection == "Yes" else 1, horizontal=True, help="Are there defenses against malicious inputs aimed at subverting the agent's intent?")

    # Submit button MUST be inside the st.form() block
    submitted = st.form_submit_button("Generate Threat Report 🚀")

# The rest of the report generation and display logic remains outside the form,
# triggered only if `submitted` is True.
if submitted:
    st.success("✅ Generating AI Threat Report...")

    # Collect all inputs into a dictionary directly from st.session_state
    inputs_for_evaluation = {key: st.session_state[key] for key in initial_values.keys()}
    # Sort lists within the inputs_for_evaluation to ensure consistent caching key
    for k in ['training_data', 'outputs', 'users', 'adversarial_test_types', 'adversarial_test_tools', 'llm_firewall']:
        if isinstance(inputs_for_evaluation.get(k), list):
            inputs_for_evaluation[k] = sorted(inputs_for_evaluation[k])

    # Call the cached evaluate_threats function
    threats = evaluate_threats(inputs_for_evaluation)


    st.header(f"📝 Threat Report for {st.session_state.project_name}")
    st.markdown(f"**Description:** {st.session_state.description if st.session_state.description else 'N/A'}")
    st.markdown(f"**AI Type:** {st.session_state.ai_type}")
    st.markdown(f"**Model Type:** {st.session_state.model_type}")
    st.markdown(f"**Exposure:** {st.session_state.exposure}")

    # Display Compliance Summary Table
    st.subheader("📋 Compliance Risk Summary")
    if threats["inferred_compliances"]:
        compliance_summary_html = "<table style='width:100%; border-collapse: collapse;'>"
        compliance_summary_html += "<tr style='background-color:#e0e6ea;'>"\
                                   "<th style='padding: 8px; border: 1px solid #c0c8cf; text-align: left;'>Compliance Framework</th>"\
                                   "<th style='padding: 8px; border: 1px solid #c0c8cf; text-align: left;'>Risk Status</th>"\
                                   "</tr>"

        for comp_framework in threats["inferred_compliances"]:
            status_text = "✅ No Risk Identified"
            status_color = "green"
            # Check if this framework has any specific gaps listed
            if any(comp_framework in gap for gap in threats["compliance_gaps"]):
                status_text = "🚨 Risk Identified"
                status_color = "red"

            compliance_summary_html += f"<tr style='color: black;'>"\
                                       f"<td style='padding: 8px; border: 1px solid #ddd;'>{comp_framework}</td>"\
                                       f"<td style='padding: 8px; border: 1px solid #ddd; font-weight: bold; color: {status_color};'>{status_text}</td>"\
                                       "</tr>"
        compliance_summary_html += "</table>"
        st.markdown(compliance_summary_html, unsafe_allow_html=True)

        if threats["compliance_gaps"]:
            st.warning("⚠️ **Details of Identified Compliance Gaps:**")
            compliance_details_html = "<table style='width:100%; border-collapse: collapse;'>"
            compliance_details_html += "<tr style='background-color:#ffe0b2;'>"\
                                       "<th style='padding: 8px; border: 1px solid #ffcc80; text-align: left;'>Identified Gap</th>"\
                                       "</tr>"
            unique_compliance_gaps = sorted(list(set(threats["compliance_gaps"])))
            for gap in unique_compliance_gaps:
                compliance_details_html += f"<tr style='color: black;'>"\
                                           f"<td style='padding: 8px; border: 1px solid #ddd;'>{gap}</td>"\
                                           "</tr>"
            compliance_details_html += "</table>"
            st.markdown(compliance_details_html, unsafe_allow_html=True)
    else:
        st.info("No specific compliance frameworks inferred based on your inputs.")
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
            owasp_id_part = threat["owasp"].split(':')[0].strip() if ":" in threat["owasp"] else threat["owasp"].strip()
            # Only add to found_owasp_ids if it's an actual OWASP ID and not 'N/A'
            if owasp_id_part != "N/A":
                found_owasp_ids.add(owasp_id_part)


    def display_owasp_table(title, owasp_map, found_ids):
        st.header(title)
        table_html = "<table style='width:100%; border-collapse: collapse;'>"
        table_html += "<tr style='background-color:#e0e6ea;'>"\
                      "<th style='padding: 8px; border: 1px solid #c0c8cf; text-align: left;'>ID</th>"\
                      "<th style='padding: 8px; border: 1px solid #c0c8cf; text-align: left;'>Threat</th>"\
                      "<th style='padding: 8px; border: 1px solid #c0c8cf; text-align: left;'>Status</th>"\
                      "</tr>"

        for owasp_id, description in owasp_map.items():
            is_found = owasp_id in found_ids
            status_color = "red" if is_found else "green"
            status_icon = "🚨" if is_found else "✅"
            status_text = f"{status_icon} Found" if is_found else f"{status_icon} Not Found"

            table_html += f"<tr style='color: black;'>" \
                          f"<td style='padding: 8px; border: 1px solid #ddd;'>{owasp_id}</td>" \
                          f"<td style='padding: 8px; border: 1px solid #ddd;'>{description}</td>" \
                          f"<td style='padding: 8px; border: 1px solid #ddd; font-weight: bold; color: {status_color};'>{status_text}</td>" \
                          "</tr>"
        table_html += "</table>"
        st.markdown(table_html, unsafe_allow_html=True)

    has_llm_threats_detected = any(id.startswith("LLM") for id in found_owasp_ids)
    has_ml_threats_detected = any(id.startswith("ML") for id in found_owasp_ids)


    # Display logic for OWASP tables - FINAL FIX ATTEMPT
    # This now relies purely on whether an LLM/ML OWASP ID was *actually* added by rules_engine,
    # combined with the selected AI Type for initial display choice.
    
    # Show LLM table if the AI type is explicitly LLM/Generative/Agentic,
    # OR if model_type is specifically an LLM type.
    if st.session_state.ai_type in ["Large Language Model (LLM)", "Generative AI (e.g., Image/Audio Generation)", "Agentic AI (e.g., Autonomous Agents)"] or \
       st.session_state.model_type in ["LLM (Generic)", "LLM (Custom/Fine-tuned)"]:
        if has_llm_threats_detected: # Only display if actual LLM threats are detected for these types
            display_owasp_table("📊 OWASP LLM Top 10 Risks", OWASP_LLM_TOP_10_DESCRIPTION_MAP, found_owasp_ids)
        else:
            st.info(f"✅ No specific LLM Top 10 Risks identified for {st.session_state.ai_type} based on your inputs.")
    
    # Only show ML table if it's Traditional ML and ML threats were detected.
    if st.session_state.ai_type == "Traditional ML":
        if has_ml_threats_detected:
            display_owasp_table("📊 OWASP ML Top 10 Risks", OWASP_ML_TOP_10_DESCRIPTION_MAP, found_owasp_ids)
        else:
            st.info(f"✅ No specific ML Top 10 Risks identified for {st.session_state.ai_type} based on your inputs.")
    
    # If it's a Generative/LLM/Agentic type AND some ML threats (from universal rules) were detected, show a relevant ML table.
    elif st.session_state.ai_type != "Traditional ML" and has_ml_threats_detected:
        st.info("💡 Some general ML threats were detected that also have an ML Top 10 mapping.")
        display_owasp_table("📊 Relevant ML Top 10 Risks (General Applicability)", OWASP_ML_TOP_10_DESCRIPTION_MAP, found_owasp_ids)
    
    # If no threats of either type were detected, inform the user
    if not has_llm_threats_detected and not has_ml_threats_detected:
        st.info("✅ No specific OWASP Top 10 risks identified based on your selections. This is a good sign!")


    # ========================
    # 🚨 Display Individual Threats
    # ========================
    if threats["basic"]:
        st.header("🚨 Individual Threats")
        basic_threat_count = 0
        for threat in threats["basic"]:
            basic_threat_count += 1
            with st.container(border=True):
                st.subheader(f"🔴 {basic_threat_count}. {threat['threat']}")
                st.markdown(f"**Severity:** <span style='color:{'red' if threat['severity'] in ['Critical', 'High'] else 'orange' if threat['severity'] == 'Medium' else 'green'}; font-weight:bold;'>{threat['severity']}</span>", unsafe_allow_html=True)
                st.markdown(f"**Reason for Threat:** <span style='color:#b22222; font-weight:bold;'>{threat['reason']}</span>", unsafe_allow_html=True)
                st.markdown(f"**Description:** {threat['description']}")
                st.markdown(f"**OWASP:** `{threat['owasp']}`")
                st.markdown(f"**MITRE ATLAS:** `{threat['mitre']}`")
                st.markdown(f"**NIST:** `{', '.join(threat['nist'])}`")
                st.markdown(f"**Mitigation:** {threat['mitigation']}")
                st.markdown(f"**Compliance Risks:** `{', '.join(threat['compliance'])}`")
                st.markdown("**Attack Path:**")
                for step_idx, step in enumerate(threat["attack_path"]):
                    st.markdown(f"**{step_idx + 1}.** {step}")
            st.markdown("---")

    # ==========================
    # 🔗 Display Threat Chains
    # ==========================
    if threats["chained"]:
        st.header("🔗 Threat Chains")
        chained_threat_count = 0
        for threat in threats["chained"]:
            chained_threat_count += 1
            with st.container(border=True):
                st.subheader(f"⛓️ {chained_threat_count}. {threat['threat']}")
                st.markdown(f"**Severity:** <span style='color:{'red' if threat['severity'] in ['Critical', 'High'] else 'orange' if threat['severity'] == 'Medium' else 'green'}; font-weight:bold;'>{threat['severity']}</span>", unsafe_allow_html=True)
                st.markdown(f"**Reason for Threat (Chain Trigger):** <span style='color:#b22222; font-weight:bold;'>{threat['reason']}</span>", unsafe_allow_html=True)
                st.markdown(f"**Description:** {threat['description']}")
                st.markdown(f"**OWASP:** `{threat['owasp']}`")
                st.markdown(f"**MITRE ATLAS:** `{threat['mitre']}`")
                st.markdown(f"**NIST:** `{', '.join(threat['nist'])}`")
                st.markdown(f"**Mitigation:** {threat['mitigation']}")
                st.markdown(f"**Compliance Risks:** `{', '.join(threat['compliance'])}`")
                st.markdown("**Attack Path:**")
                for step_idx, step in enumerate(threat["attack_path"]):
                    if step_idx < len(threat["attack_path"]) - 1:
                        st.markdown(f"**{step_idx + 1}.** {step} &nbsp; ➡️")
                    else:
                        st.markdown(f"**{step_idx + 1}.** {step}")

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
            st.markdown("---")

    # =====================================
    # 📊 Overall Threat Visualizations
    # =====================================
    st.header("📊 Overall Threat Visualizations")

    # Overall Severity Distribution Pie Chart
    all_threats_for_severity = threats["basic"] + threats["chained"]
    if all_threats_for_severity:
        severity_counts = Counter(t["severity"] for t in all_threats_for_severity)
        severity_labels = ["Critical", "High", "Medium", "Low"] # Define order
        severity_values = [severity_counts.get(label, 0) for label in severity_labels]
        severity_colors = {"Critical": "#DC3545", "High": "#FD7E14", "Medium": "#FFC107", "Low": "#28A745"} # Red, Orange, Yellow, Green

        # Filter out severities with zero count for cleaner pie chart
        filtered_labels = [label for i, label in enumerate(severity_labels) if severity_values[i] > 0]
        filtered_values = [value for value in severity_values if value > 0]
        filtered_colors = [severity_colors[label] for label in filtered_labels]

        if filtered_values:
            severity_pie_fig = go.Figure(data=[go.Pie(labels=filtered_labels, values=filtered_values,
                                                     marker_colors=filtered_colors, hole=.3)])
            severity_pie_fig.update_layout(title_text="Threats by Severity Distribution")
            st.plotly_chart(severity_pie_fig)
        else:
            st.info("No threats detected to generate severity distribution chart.")
    else:
        st.info("No threats detected to generate severity distribution chart.")


    # Overall Basic vs Chained Threats Pie Chart
    total_basic = len(threats["basic"])
    total_chained = len(threats["chained"])
    total_threats = total_basic + total_chained

    if total_threats > 0:
        pie_labels = ['Individual Threats', 'Chained Threats']
        pie_values = [total_basic, total_chained]
        pie_colors = ['#4CAF50', '#FFC107'] # Green for basic, Amber for chained

        pie_fig = go.Figure(data=[go.Pie(labels=pie_labels, values=pie_values, marker_colors=pie_colors, hole=.3)])
        pie_fig.update_layout(title_text="Distribution of Individual vs. Chained Threats")
        st.plotly_chart(pie_fig)
    else:
        st.info("No threats detected, so threat distribution chart is not generated.")


    # Overall NIST CIA + Abuse Radar Chart
    all_nist = []
    for t in threats["basic"] + threats["chained"]:
        all_nist.extend(t["nist"])

    if all_nist:
        cia_counts = Counter(all_nist)
        categories = ['Confidentiality', 'Integrity', 'Availability', 'Abuse']
        values = [cia_counts.get(c, 0) for c in categories]

        radar = go.Figure()
        radar.add_trace(go.Scatterpolar(
            r=values + [values[0]],
            theta=categories + [categories[0]],
            fill='toself',
            name='CIA+Abuse',
            line=dict(color='darkblue', width=2),
            marker=dict(symbol="circle", size=8, color='darkblue')
        ))
        radar.update_layout(
            title="🔐 Aggregate NIST CIA + Abuse Impact",
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, max(values) + 1] if values else [0, 1]
                )
            ),
            showlegend=False,
            font=dict(size=12)
        )
        st.plotly_chart(radar)
    else:
        st.info("No threats detected, so overall NIST CIA + Abuse Impact chart is not generated.")


    # Overall MITRE ATLAS Tactic Frequency Chart
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
            yaxis_title="Count",
            xaxis_tickangle=-45
        )
        st.plotly_chart(mitre_fig)
    else:
        st.info("No threats detected, so overall MITRE ATLAS Tactic Frequency chart is not generated.")

    st.markdown("---")
    st.info("💡 **Tip:** To save this report, use your browser's print-to-PDF function (usually Ctrl+P or Cmd+P and select 'Save as PDF').")
