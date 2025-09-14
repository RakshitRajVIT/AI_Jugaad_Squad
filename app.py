"""
AI for Digital Security — Streamlit MVP

Files: single-file app (this document). Save as: app.py

Purpose:
A minimal, deployable MVP that demonstrates automated detection and basic analysis of digital threats using simple AI techniques:
- Anomaly detection on network/log features using IsolationForest
- URL heuristics to flag suspicious domains
- Text/content heuristics (keyword + entropy) to flag manipulated information
- Simple alert export (CSV) and a 1-minute demo script printed inside the app

How to run (on your laptop):
1. Create a virtualenv (optional): python -m venv venv && source venv/bin/activate.
2. Install: pip install -r requirements.txt
   If you don't have a requirements.txt, run: pip install streamlit pandas numpy scikit-learn matplotlib tldextract
3. Run: streamlit run app.py

Input data format (CSV recommended): columns MAY include any of these (the app will adapt):
- timestamp (ISO or anything parseable)
- src_ip
- dst_ip
- url
- user_agent
- payload (text)
- bytes (numeric)

If you don't have logs, use the built-in sample generator.

Notes:
- This is a defensive tool — it flags anomalies and suspicious content. It is NOT a complete production IDS/IPS.
- For production use, integrate with threat intelligence feeds, use larger labeled datasets and proper ML ops.

"""

import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import tldextract
import io
import time
import math
from collections import Counter

st.set_page_config(page_title="AI for Digital Security — MVP", layout="wide")

st.title("AI for Digital Security — MVP")
st.markdown("""
This small app demonstrates an automated detection pipeline for digital security events using lightweight AI methods.

Features:
- Upload logs (CSV) or generate sample data
- Lightweight feature engineering per source IP
- IsolationForest anomaly detection
- URL heuristics (suspicious TLDs, long domains)
- Text heuristics (keyword flags + entropy) to spot manipulated / obfuscated content
- Export anomalies for submission
""")

# ----------------- Helpers -----------------

def generate_sample_data(n=1000):
    import random
    import datetime
    rows = []
    base = datetime.datetime.now()
    common_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'curl/7.68.0',
        'Mozilla/5.0 (Linux; Android 10)',
        'python-requests/2.25.1'
    ]
    domains = ['example.com','login-secure.com','banking-update.net','free-downloads.io','goog1e.com','safe-site.org']
    for i in range(n):
        t = base - datetime.timedelta(seconds=random.randint(0, 86400))
        src = f"192.168.{random.randint(0,5)}.{random.randint(1,254)}"
        dst = f"10.0.0.{random.randint(1,254)}"
        url = 'https://' + random.choice(domains) + f"/p={random.randint(1,200)}"
        ua = random.choice(common_agents)
        payload = 'normal request' if random.random() > 0.02 else ('<script>eval(\"malicious\")</script>' if random.random()>0.5 else 'CLICK HERE to win $$$')
        b = random.randint(100,2000) if 'normal' in payload else random.randint(1000,10000)
        rows.append({'timestamp': t.isoformat(), 'src_ip': src, 'dst_ip': dst, 'url': url, 'user_agent': ua, 'payload': payload, 'bytes': b})
    return pd.DataFrame(rows)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    import math
    ent = - sum([p * math.log2(p) for p in prob])
    return ent


def url_heuristics(url: str) -> dict:
    if not isinstance(url, str):
        return {'susp_tld': False, 'long_domain': False, 'looks_obfuscated': False}
    ext = tldextract.extract(url)
    domain = ext.domain + ('.' + ext.suffix if ext.suffix else '')
    suspicious_tlds = set(['pw','info','biz','top'])
    susp_tld = ext.suffix in suspicious_tlds
    long_domain = len(ext.domain) > 20
    looks_obfuscated = any(ch.isdigit() for ch in ext.domain) and sum(ch.isdigit() for ch in ext.domain) > 3
    return {'susp_tld': susp_tld, 'long_domain': long_domain, 'looks_obfuscated': looks_obfuscated, 'domain': domain}

# ----------------- Input -----------------

st.sidebar.header('Input data')
upload = st.sidebar.file_uploader('Upload CSV log file (optional)', type=['csv'])
use_sample = st.sidebar.checkbox('Use sample generated data', value=True)

if upload is not None:
    df = pd.read_csv(upload)
    st.sidebar.success('Loaded uploaded CSV')
elif use_sample:
    df = generate_sample_data(1200)
    st.sidebar.info('Using generated sample data')
else:
    st.warning('Please upload a CSV or enable sample data.')
    st.stop()

st.subheader('Raw data (first 200 rows)')
st.dataframe(df.head(200))

# ----------------- Feature engineering -----------------
st.subheader('Feature engineering per source IP')

# Ensure columns exist
for col in ['src_ip','url','payload','bytes','timestamp','user_agent']:
    if col not in df.columns:
        df[col] = None

# Basic features aggregated by src_ip
agg = df.groupby('src_ip').agg(
    requests=('src_ip','count'),
    avg_bytes=('bytes','mean'),
    unique_urls=('url', lambda x: x.nunique()),
    unique_agents=('user_agent', lambda x: x.nunique())
).reset_index()

# Add payload entropy and keyword flags aggregated
keyword_list = ['click here','win','free','update your','bank','password','malicious','<script>','eval(']

payload_info = []
for ip, group in df.groupby('src_ip'):
    texts = ' '.join([str(x) for x in group['payload'].fillna('')])
    ent = shannon_entropy(texts)
    kcounts = sum(1 for k in keyword_list if k in texts.lower())
    payload_info.append({'src_ip': ip, 'payload_entropy': ent, 'keyword_count': kcounts})

payload_df = pd.DataFrame(payload_info)

feat = agg.merge(payload_df, on='src_ip', how='left')

# URL heuristics aggregated: fraction of suspicious URLs
susp_list = []
for ip, group in df.groupby('src_ip'):
    checks = [url_heuristics(u) for u in group['url'].fillna('')]
    if checks:
        susp = sum(1 for c in checks if c['susp_tld'] or c['long_domain'] or c['looks_obfuscated']) / max(1, len(checks))
    else:
        susp = 0
    susp_list.append({'src_ip': ip, 'suspicious_url_fraction': susp})

susp_df = pd.DataFrame(susp_list)
feat = feat.merge(susp_df, on='src_ip', how='left')

st.dataframe(feat.head(200))

# ----------------- Anomaly detection -----------------
st.subheader('Anomaly detection (IsolationForest)')
use_iforest = st.checkbox('Run IsolationForest', value=True)
contamination = st.sidebar.slider('Contamination (expected fraction anomalies)', 0.001, 0.2, 0.02)

if use_iforest:
    X = feat[['requests','avg_bytes','unique_urls','unique_agents','payload_entropy','keyword_count','suspicious_url_fraction']].fillna(0)
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    model = IsolationForest(contamination=contamination, random_state=42)
    model.fit(Xs)
    scores = model.decision_function(Xs)
    preds = model.predict(Xs)  # -1 anomaly, 1 normal
    feat['anomaly_score'] = -scores  # higher = more anomalous
    feat['is_anomaly'] = (preds == -1)

    st.metric('Anomalies detected', int(feat['is_anomaly'].sum()))

    # Show top anomalies
    top = feat.sort_values('anomaly_score', ascending=False).head(20)
    st.markdown('Top anomalies (by anomaly score)')
    st.dataframe(top[['src_ip','requests','avg_bytes','payload_entropy','keyword_count','suspicious_url_fraction','anomaly_score','is_anomaly']])

    # Plot distribution
    fig, ax = plt.subplots()
    ax.hist(feat['anomaly_score'], bins=40)
    ax.set_title('Anomaly score distribution')
    ax.set_xlabel('anomaly score (higher = more unusual)')
    st.pyplot(fig)

else:
    st.info('IsolationForest not run. Enable checkbox to run it.')

# ----------------- Show sample suspicious records -----------------
st.subheader('Sample suspicious raw records (from flagged IPs)')

if 'is_anomaly' in feat.columns:
    flagged_ips = feat.loc[feat['is_anomaly'], 'src_ip'].tolist()
    flagged_rows = df[df['src_ip'].isin(flagged_ips)].sort_values('timestamp').head(200)
    st.dataframe(flagged_rows)

    # allow export
    buffer = io.StringIO()
    flagged_rows.to_csv(buffer, index=False)
    st.download_button('Download flagged raw rows (CSV)', buffer.getvalue(), file_name='flagged_rows.csv')

# ----------------- Simple alerts & remediation suggestions -----------------
st.subheader('Automatic suggestions (simple)')

if 'is_anomaly' in feat.columns:
    examples = feat.loc[feat['is_anomaly']].head(10)
    for _, row in examples.iterrows():
        st.markdown(f"*IP:* {row['src_ip']} — anomaly_score={row['anomaly_score']:.2f}")
        reasons = []
        if row['suspicious_url_fraction'] > 0.2:
            reasons.append('High fraction of suspicious URLs')
        if row['keyword_count'] > 0:
            reasons.append(f"{int(row['keyword_count'])} suspicious payload keywords")
        if row['payload_entropy'] > 4.5:
            reasons.append('High payload entropy (possible obfuscation)')
        if row['requests'] > feat['requests'].quantile(0.99):
            reasons.append('Very high request volume')
        if not reasons:
            reasons.append('Unusual combination of numeric features')
        for r in reasons:
            st.write('-', r)
        st.write('---')

# ----------------- Quick demo script for judges -----------------
st.sidebar.header('Demo script')
if st.sidebar.button('Show 1-min demo script'):
    st.sidebar.markdown('''
    1. Open app; show sample data loaded (30s)
    2. Run IsolationForest (auto) — show top anomalies and explain features (30s)
    3. Click a flagged IP, show raw rows and explain suggested mitigations (30s)
    4. Download flagged CSV to show how alerts are exported (10s)
    ''')

# ----------------- Exporting model here (htis is optional step) -----------------
st.subheader('Export results & model (optional)')
if st.button('Export anomalies CSV') and 'is_anomaly' in feat.columns:
    buf = io.StringIO()
    feat.to_csv(buf, index=False)
    st.download_button('Download features+anomalies', buf.getvalue(), file_name='features_and_anomalies.csv')

st.markdown('---')
st.caption('This MVP is intended for hackathon demonstration purposes. For production-readiness: add labeled datasets, feature stores, integration with SIEM, alerting pipelines, and model monitoring.')

# End of app