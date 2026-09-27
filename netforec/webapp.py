import streamlit as st
import pandas as pd
import json
import os
import altair as alt
from pathlib import Path
from tempfile import NamedTemporaryFile
from netforec.pipeline import run_pipeline
from netforec.validation import validate_input

st.set_page_config(page_title="NETFOREC Dashboard", layout="wide", initial_sidebar_state="collapsed")

# --- Custom Styling (Premium SOC Aesthetic) ---
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@400;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    
    /* Global Background */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }

    /* Subheader Overrides */
    h1, h2, h3 {
        font-family: 'Inter', sans-serif;
        font-weight: 800;
        letter-spacing: -0.5px;
    }
    h1 {
        background: linear-gradient(90deg, #58a6ff, #3fb950, #d29922, #f85149);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0rem;
    }
    h3 {
        color: #f0f6fc !important;
        margin-top: 1rem;
        margin-bottom: 1rem;
    }
    
    /* Fix uploader look */
    [data-testid="stFileUploadDropzone"] {
        background-color: #161b22;
        border: 2px dashed #30363d;
        border-radius: 12px;
    }

    /* Expander Restyling */
    .streamlit-expanderHeader {
        font-weight: 600 !important;
        font-size: 1.1rem !important;
        color: #58a6ff !important;
        background-color: transparent !important;
        border-bottom: 1px solid #30363d;
    }
    .streamlit-expanderContent {
        background-color: rgba(22, 27, 34, 0.3) !important;
        border: 1px solid #30363d !important;
        border-top: none !important;
        border-radius: 0 0 12px 12px !important;
    }
    </style>
""", unsafe_allow_html=True)

def styled_metric(label, value, risk_level="LOW", is_normal=True):
    if is_normal:
        border_color = "#3fb950"
        value_color = "#3fb950"
    else:
        border_color = "#f85149" if risk_level == "HIGH" else ("#d29922" if risk_level == "MEDIUM" else "#58a6ff")
        value_color = "#f0f6fc"

    st.markdown(f"""
        <div style="
            background: linear-gradient(145deg, #161b22, #0d1117);
            border: 1px solid #30363d;
            border-bottom: 3px solid {border_color};
            border-radius: 12px;
            padding: 24px;
            text-align: center;
            box-shadow: 0 8px 24px rgba(0,0,0,0.6);
            margin-bottom: 1.5rem;
        ">
            <div style="color: #8b949e; font-size: 0.85rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; font-family: 'Inter', sans-serif;">
                {label}
            </div>
            <div style="color: {value_color}; font-size: 2.4rem; font-weight: 800; font-family: 'JetBrains Mono', monospace; line-height: 1; text-shadow: 0 0 10px rgba(255,255,255,0.1);">
                {value}
            </div>
        </div>
    """, unsafe_allow_html=True)

def styled_mitre_block(tactic, technique, technique_id, description):
    st.markdown(f"""
        <div style="background: linear-gradient(90deg, rgba(248, 81, 73, 0.15) 0%, rgba(22, 27, 34, 0) 100%); border-left: 4px solid #f85149; padding: 20px; border-radius: 0 12px 12px 0; margin-bottom: 1.5rem; box-shadow: 0 4px 12px rgba(0,0,0,0.3);">
            <div style="font-family: 'Inter', sans-serif;">
                <div style="margin-bottom: 12px;">
                    <span style="background-color: #f85149; color: #ffffff; padding: 4px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; box-shadow: 0 0 10px rgba(248,81,73,0.4);">{tactic}</span>
                    <span style="background-color: #30363d; color: #c9d1d9; padding: 4px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: 700; margin-left: 8px; font-family: 'JetBrains Mono', monospace;">{technique_id}</span>
                </div>
                <div style="color: #f0f6fc; font-weight: 800; font-size: 1.3rem; margin-bottom: 6px; letter-spacing: -0.3px;">{technique}</div>
                <div style="color: #8b949e; font-size: 1.0rem; line-height: 1.6;">{description}</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

def styled_evidence(feature, effect, description):
    effect_color = "#f85149" if effect.lower() == "positive" else "#58a6ff"
    st.markdown(f"""
        <div style="background-color: #161b22; border: 1px solid #30363d; border-left: 4px solid {effect_color}; padding: 16px 20px; border-radius: 12px; margin-bottom: 10px; display: flex; align-items: start; box-shadow: 0 4px 6px rgba(0,0,0,0.2);">
            <div>
                <div style="color: #f0f6fc; font-weight: 700; font-size: 1.05rem; margin-bottom: 4px; font-family: 'JetBrains Mono', monospace;">{feature}</div>
                <div style="color: #8b949e; font-size: 0.95rem; line-height: 1.5;">{description}</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

def styled_investigation(srcs, dsts):
    st.markdown(f"""
        <div style="display: flex; gap: 1.5rem; font-family: 'JetBrains Mono', monospace;">
            <div style="flex: 1; background: linear-gradient(145deg, #161b22, #0d1117); border: 1px solid #f85149; padding: 20px; border-radius: 12px; box-shadow: inset 0 0 20px rgba(248,81,73,0.05), 0 4px 12px rgba(0,0,0,0.4);">
                <div style="color: #f85149; font-size: 0.8rem; text-transform: uppercase; margin-bottom: 8px; font-family: 'Inter', sans-serif; font-weight: 800; letter-spacing: 1px;">Target Source IPs</div>
                <div style="color: #ff7b72; font-weight: 700; font-size: 1.15rem; word-break: break-all; line-height: 1.5;">{srcs}</div>
            </div>
            <div style="flex: 1; background: linear-gradient(145deg, #161b22, #0d1117); border: 1px solid #d29922; padding: 20px; border-radius: 12px; box-shadow: inset 0 0 20px rgba(210,153,34,0.05), 0 4px 12px rgba(0,0,0,0.4);">
                <div style="color: #d29922; font-size: 0.8rem; text-transform: uppercase; margin-bottom: 8px; font-family: 'Inter', sans-serif; font-weight: 800; letter-spacing: 1px;">Target Dest Ports</div>
                <div style="color: #e3b341; font-weight: 700; font-size: 1.15rem; word-break: break-all; line-height: 1.5;">{dsts}</div>
            </div>
        </div>
    """, unsafe_allow_html=True)


# --- Dashboard Layout ---
st.title("NETFOREC")
st.markdown("<p style='font-size: 1.2rem; color: #8b949e; margin-top: -15px; margin-bottom: 30px;'>Offline AI-Powered Flow Diagnostics & Trajectory Forecasting</p>", unsafe_allow_html=True)

uploaded_file = st.file_uploader("Ingest Network Telemetry (CSV)", type=["csv"])
tmp_path = None

if uploaded_file is None:
    bundled = Path(__file__).parent.parent / "test_data" / "syn_flood_shaped.csv"
    if bundled.exists():
        st.info("No file uploaded. Running internal telemetry (`syn_flood_shaped.csv`) for live demonstration.")
        with open(bundled, 'rb') as f:
            uploaded_bytes = f.read()
    else:
        uploaded_bytes = None
else:
    uploaded_bytes = uploaded_file.getvalue()

if uploaded_bytes is not None:
    with NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
        tmp.write(uploaded_bytes)
        tmp_path = Path(tmp.name)

    val = validate_input(tmp_path)
    if not val.is_valid:
        st.markdown("<h3 style='color: #f85149;'>Validation Failed</h3>", unsafe_allow_html=True)
        for e in val.errors:
            st.error(f"✗ {e}")
    else:
        with st.spinner("Analyzing temporal dynamics..."):
            try:
                result = run_pipeline(str(tmp_path), log=lambda x: None)
                is_normal = (result.predicted_class == "Normal")
                
                # --- Topline Metrics ---
                col1, col2, col3 = st.columns(3)
                with col1:
                    styled_metric("Predicted Threat", result.predicted_class.upper(), result.risk_level, is_normal)
                with col2:
                    styled_metric("Confidence", f"{result.confidence * 100:.1f}%", result.risk_level, is_normal)
                with col3:
                    styled_metric("Risk Level", result.risk_level, result.risk_level, is_normal)
                
                st.markdown("<br>", unsafe_allow_html=True)
                
                # --- Twin Visualizations ---
                c_left, c_right = st.columns(2)
                
                with c_left:
                    st.markdown("<h3>Probability Distribution</h3>", unsafe_allow_html=True)
                    probs = [{"Class": name, "Probability": float(p)*100} for name, p in result.class_probabilities]
                    df_probs = pd.DataFrame(probs)
                    
                    bar_chart = alt.Chart(df_probs).mark_bar(cornerRadiusEnd=6, size=24).encode(
                        y=alt.Y("Class:N", sort="-x", title="", axis=alt.Axis(labelColor="#c9d1d9", labelFont="Inter", grid=False, labelFontSize=12)),
                        x=alt.X("Probability:Q", title="Probability (%)", scale=alt.Scale(domain=[0, 100]), axis=alt.Axis(labelColor="#c9d1d9", titleColor="#8b949e", gridColor="#30363d")),
                        color=alt.condition(
                            alt.datum.Class == result.predicted_class,
                            alt.value("#f85149" if not is_normal else "#3fb950"),
                            alt.value("#21262d")
                        ),
                        tooltip=["Class", alt.Tooltip("Probability", format=".1f")]
                    ).properties(height=320).configure_view(strokeWidth=0)
                    
                    st.altair_chart(bar_chart, use_container_width=True)
                
                raw = getattr(result, "raw_json", {})
                
                with c_right:
                    st.markdown("<h3>K-Step Forward Forecast</h3>", unsafe_allow_html=True)
                    if "forecast" in raw and "predictions" in raw["forecast"]:
                        preds = raw["forecast"]["predictions"]
                        df_k = pd.DataFrame(preds)
                        
                        line_color = "#f85149" if not is_normal else "#3fb950"
                        df_k["Infiltration Probability (%)"] = df_k["infiltration_probability"] * 100
                        
                        area = alt.Chart(df_k).mark_area(
                            line={'color': line_color, 'strokeWidth': 3},
                            color=alt.Gradient(
                                gradient='linear',
                                stops=[alt.GradientStop(color=line_color, offset=0),
                                       alt.GradientStop(color='rgba(22, 27, 34, 0)', offset=1)],
                                x1=1, x2=1, y1=1, y2=0
                            ),
                            interpolate='monotone'
                        ).encode(
                            x=alt.X("time_ahead_minutes:Q", title="Minutes Ahead", axis=alt.Axis(labelColor="#c9d1d9", titleColor="#8b949e", gridColor="#30363d", labelFontSize=12)),
                            y=alt.Y("Infiltration Probability (%):Q", title="Infiltration Probability (%)", scale=alt.Scale(domain=[0, 100]), axis=alt.Axis(labelColor="#c9d1d9", titleColor="#8b949e", gridColor="#30363d")),
                            tooltip=["time_ahead_minutes", alt.Tooltip("Infiltration Probability (%)", format=".1f")]
                        )
                        
                        points = alt.Chart(df_k).mark_circle(size=80, color=line_color).encode(
                            x="time_ahead_minutes:Q",
                            y="Infiltration Probability (%):Q",
                            tooltip=["time_ahead_minutes", alt.Tooltip("Infiltration Probability (%)", format=".1f")]
                        )
                        
                        layered_chart = (area + points).properties(height=320).configure_view(strokeWidth=0)
                        
                        st.altair_chart(layered_chart, use_container_width=True)

                st.markdown("<hr style='border-color: #30363d; margin-top: 2rem; margin-bottom: 2rem;'>", unsafe_allow_html=True)

                # --- Threat Intel & Diagnostics ---
                if not is_normal:
                    st.markdown("<h3>Deep Diagnostics</h3>", unsafe_allow_html=True)
                    
                    styled_mitre_block(result.mitre_tactic, result.mitre_technique, result.mitre_technique_id, result.mitre_description)
                    
                    if "evidence" in raw and len(raw["evidence"]) > 0:
                        st.markdown("<p style='font-family: Inter; font-weight: 600; color: #c9d1d9; margin-top: 1.5rem; margin-bottom: 0.5rem;'>TOP INDICATORS (ATTRIBUTION VECTORS)</p>", unsafe_allow_html=True)
                        for e in raw["evidence"][:3]: 
                            styled_evidence(e['feature'], e['effect'], e['description'])

                    st.markdown("<p style='font-family: Inter; font-weight: 600; color: #c9d1d9; margin-top: 1.5rem; margin-bottom: 0.5rem;'>INVESTIGATE ACTIONABLE TARGETS</p>", unsafe_allow_html=True)
                    inv = raw.get("investigation", {})
                    srcs = ", ".join(inv.get("source_ips", [])) or "None"
                    dsts = ", ".join(str(p) for p in inv.get("destination_ports", [])) or "None"
                    
                    styled_investigation(srcs, dsts)
                    st.markdown("<p style='font-size: 0.8rem; color: #8b949e; margin-top: 12px; font-family: Inter;'>ℹ Internal model does not currently assign attribution scores to individual IPs; logging active IPs in the affected flow window.</p>", unsafe_allow_html=True)
                
            except Exception as e:
                st.error(f"Analysis iteration failed: {e}")
                
    if tmp_path and tmp_path.exists():
        try:
            os.remove(tmp_path)
        except:
            pass
