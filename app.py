from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import time

import requests

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="CISA KEV | Vulnerability Intelligence",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# THEME / CSS
# ============================================================
st.markdown(
    """
    <style>
        :root {
            --bg: #f3f7fb;
            --panel: #ffffff;
            --panel-2: #eaf4fa;
            --line: #d8e4ee;
            --text: #163047;
            --muted: #61798d;
            --cyan: #087fa7;
            --teal: #13877e;
            --red: #c94c5a;
            --amber: #bd7a14;
            --green: #23795f;
            --navy: #102b43;
        }

        .stApp {
            background:
                radial-gradient(circle at 96% 0%, rgba(0, 150, 190, 0.07), transparent 25%),
                linear-gradient(180deg, #f7fafc 0%, #edf4f9 100%);
            color: var(--text);
        }

        [data-testid="stHeader"] {
            background: rgba(247, 250, 252, 0.92);
            border-bottom: 1px solid #dfe8f0;
        }

        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #112c44 0%, #173b55 100%);
            border-right: 1px solid #234b66;
        }
        [data-testid="stSidebar"] * { color: #edf6fb; }
        [data-testid="stSidebar"] [data-testid="stCaptionContainer"] p {
            color: #b6cbd9 !important;
        }
        [data-testid="stSidebar"] hr { border-color: rgba(210, 232, 244, 0.18); }
        [data-testid="stSidebar"] [data-baseweb="select"] > div,
        [data-testid="stSidebar"] [data-baseweb="input"] > div {
            background: #f8fbfd;
            border-color: #c9d9e5;
            color: #163047;
        }
        [data-testid="stSidebar"] [data-baseweb="select"] *,
        [data-testid="stSidebar"] [data-baseweb="input"] * { color: #163047; }

        .block-container {
            padding-top: 1.5rem;
            padding-bottom: 3rem;
            max-width: 1480px;
        }

        h1, h2, h3, h4 {
            color: #14344d;
            letter-spacing: -0.025em;
        }
        p, label, .stMarkdown, [data-testid="stCaptionContainer"] p {
            color: var(--text);
        }

        .hero {
            position: relative;
            overflow: hidden;
            padding: 1.45rem 1.6rem 1.4rem 1.6rem;
            border: 1px solid #cfdfeb;
            border-left: 5px solid var(--cyan);
            border-radius: 18px;
            background: linear-gradient(110deg, #ffffff 0%, #f2f9fc 72%, #e8f5fa 100%);
            box-shadow: 0 8px 28px rgba(24, 61, 88, 0.07);
            margin-bottom: 1.25rem;
        }
        .hero:after {
            content: "";
            position: absolute;
            right: -26px;
            top: -54px;
            width: 190px;
            height: 190px;
            border: 1px solid rgba(8, 127, 167, 0.16);
            border-radius: 50%;
            box-shadow: 0 0 0 24px rgba(8, 127, 167, 0.035),
                        0 0 0 48px rgba(8, 127, 167, 0.025);
            pointer-events: none;
        }
        .eyebrow {
            color: var(--cyan);
            font-size: 0.75rem;
            font-weight: 800;
            letter-spacing: 0.15em;
            text-transform: uppercase;
            margin-bottom: 0.45rem;
        }
        .hero-title {
            color: #12324b;
            font-size: clamp(1.55rem, 2.3vw, 2.15rem);
            font-weight: 800;
            line-height: 1.15;
            margin: 0;
            max-width: 940px;
        }
        .hero-sub {
            color: #587287;
            margin-top: 0.55rem;
            max-width: 930px;
            line-height: 1.6;
            font-size: 0.98rem;
        }

        .metric-card {
            padding: 1.05rem 1.1rem;
            border: 1px solid #d7e4ed;
            border-top: 3px solid var(--cyan);
            border-radius: 15px;
            background: #ffffff;
            min-height: 112px;
            box-shadow: 0 5px 18px rgba(24, 61, 88, 0.045);
        }
        .metric-label {
            color: #637d91;
            font-size: 0.73rem;
            font-weight: 750;
            text-transform: uppercase;
            letter-spacing: 0.075em;
        }
        .metric-value {
            color: #153a55;
            font-size: 1.85rem;
            font-weight: 800;
            line-height: 1.25;
            margin-top: 0.22rem;
        }
        .metric-note { color: #71879a; font-size: 0.76rem; margin-top: 0.24rem; }

        .section-title {
            color: #173b55;
            margin-top: 1.5rem;
            margin-bottom: 0.25rem;
            font-size: 1.2rem;
            font-weight: 800;
        }
        .section-note {
            color: #667f92;
            font-size: 0.88rem;
            margin-bottom: 0.8rem;
            line-height: 1.5;
        }
        .insight {
            padding: 0.95rem 1.05rem;
            border: 1px solid #d0e4ed;
            border-left: 4px solid var(--cyan);
            border-radius: 12px;
            background: #eaf6fb;
            color: #20465d;
            line-height: 1.6;
        }
        .risk-high {
            border-color: #f0c7cb;
            border-left-color: var(--red);
            background: #fff1f2;
            color: #6e2932;
        }
        .sdg {
            display: inline-block;
            padding: 0.34rem 0.62rem;
            margin: 0.18rem 0.18rem 0 0;
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 999px;
            font-size: 0.72rem;
            font-weight: 700;
            color: #f2f8fb;
            background: rgba(255,255,255,0.09);
        }
        .small { color: #6b8295; font-size: 0.78rem; }
        .cluster-pill {
            display: inline-block;
            padding: 0.22rem 0.58rem;
            border-radius: 999px;
            background: #e4f5f7;
            color: #087c88;
            border: 1px solid #b8e1e5;
            font-size: 0.75rem;
            font-weight: 800;
        }

        div[data-testid="stDataFrame"] {
            border: 1px solid #d9e5ee;
            border-radius: 12px;
            overflow: hidden;
            background: white;
        }
        div[data-testid="stPlotlyChart"] {
            background: #ffffff;
            border: 1px solid #dce7ef;
            border-radius: 14px;
            padding: 0.25rem;
            box-shadow: 0 4px 16px rgba(24, 61, 88, 0.035);
        }
        div[data-testid="stMetric"] {
            background: #ffffff;
            border: 1px solid #d8e5ee;
            border-radius: 14px;
            padding: 0.7rem 0.85rem;
        }
        .stButton > button, .stDownloadButton > button {
            border-radius: 10px;
            border: 1px solid #b9d5e3;
            background: #e9f5fa;
            color: #17445f;
            font-weight: 700;
        }
        .stButton > button:hover, .stDownloadButton > button:hover {
            border-color: var(--cyan);
            background: #dff1f8;
            color: #0d3a54;
        }
        div[data-baseweb="select"] > div, div[data-baseweb="input"] > div {
            border-color: #cbdce7;
            border-radius: 9px;
        }
        .stTabs [data-baseweb="tab-list"] { gap: 0.4rem; }
        .stTabs [data-baseweb="tab"] {
            background: #edf4f8;
            border-radius: 9px 9px 0 0;
            color: #456478;
        }
        .stTabs [aria-selected="true"] {
            background: #dff2f8 !important;
            color: #086f91 !important;
        }
        hr { border-color: #d9e5ed; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ============================================================
# CONSTANTS
# ============================================================
# Data diambil langsung dari API publik, bukan MySQL lokal atau CSV.
# CISA-maintained GitHub feed dipakai sebagai mirror katalog resmi agar lebih
# andal saat aplikasi berjalan dari server cloud.
KEV_API_URLS = [
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
]
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
API_CACHE_SECONDS = 6 * 60 * 60  # refresh data paling lama setiap 6 jam


SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
ATTACK_ORDER = ["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"]

CLUSTER_PROFILES = pd.DataFrame(
    [
        [0, 183, 0.106, 6.1, 0.07, "Dampak ringan, EPSS rendah", 11],
        [1, 347, 0.200, 8.8, 0.15, "Dampak tinggi, EPSS rendah", 11],
        [2, 427, 0.246, 9.8, 0.97, "Paling kritis: mudah, parah, EPSS tinggi", 31],
        [3, 130, 0.075, 7.5, 0.88, "Mudah dieksploitasi, dampak terbatas", 24],
        [4, 303, 0.175, 8.1, 0.83, "EPSS tinggi, sering butuh interaksi pengguna", 26],
        [5, 343, 0.198, 7.8, 0.06, "Butuh hak akses rendah, EPSS rendah", 18],
    ],
    columns=[
        "cluster",
        "jumlah_CVE",
        "proporsi",
        "cvss_median",
        "epss_median",
        "ciri_utama",
        "ransomware_pct",
    ],
)

CLUSTER_ORDER = [2, 4, 1, 5, 3, 0]

# ============================================================
# DATA LOADING — DIRECT PUBLIC APIs
# ============================================================
def _http_json(url: str, *, params=None, timeout=45):
    """GET JSON with a clear error when a public source is unavailable."""
    response = requests.get(
        url,
        params=params,
        timeout=timeout,
        headers={"User-Agent": "KEV-Intelligence-Student-Dashboard/1.0"},
    )
    response.raise_for_status()
    return response.json()


@st.cache_data(ttl=API_CACHE_SECONDS, show_spinner=False)
def fetch_kev_records():
    """Fetch the current CISA KEV catalog, with an official-source fallback."""
    errors = []
    for url in KEV_API_URLS:
        try:
            payload = _http_json(url, timeout=35)
            rows = payload.get("vulnerabilities", [])
            if not rows:
                raise ValueError("Respons katalog KEV tidak memiliki data vulnerabilities.")
            frame = pd.DataFrame(rows)
            frame = frame.drop_duplicates(subset=["cveID"], keep="last")
            return frame, {
                "catalogVersion": payload.get("catalogVersion", "unknown"),
                "dateReleased": payload.get("dateReleased", "unknown"),
                "count": int(payload.get("count", len(frame))),
                "source": url,
            }
        except Exception as exc:
            errors.append(f"{url}: {exc}")
    raise RuntimeError("Katalog CISA KEV gagal diakses. " + " | ".join(errors))


def _parse_nvd_record(item):
    """Flatten the useful CVSS and date fields from one NVD CVE record."""
    cve = item.get("cve", {})
    metrics = cve.get("metrics", {}) or {}
    metric = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        choices = metrics.get(key) or []
        if choices:
            # Prefer NVD's primary metric when present.
            metric = next((m for m in choices if m.get("type") == "Primary"), choices[0])
            break

    cvss_data = (metric or {}).get("cvssData", {}) or {}
    score = cvss_data.get("baseScore")
    severity = (metric or {}).get("baseSeverity") or cvss_data.get("baseSeverity")

    # CVSS v3 fields are preferred. For CVSS v4, some impact field names differ;
    # these are kept as blanks rather than inventing conversions.
    row = {
        "cveID": cve.get("id"),
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "cvssScore": score,
        "nvdSeverity": severity,
        "attackVector": cvss_data.get("attackVector"),
        "attackComplexity": cvss_data.get("attackComplexity"),
        "privilegesRequired": cvss_data.get("privilegesRequired"),
        "userInteraction": cvss_data.get("userInteraction"),
        "scope": cvss_data.get("scope"),
        "confidentialityImpact": cvss_data.get("confidentialityImpact"),
        "integrityImpact": cvss_data.get("integrityImpact"),
        "availabilityImpact": cvss_data.get("availabilityImpact"),
        "cvssVector": cvss_data.get("vectorString"),
    }
    return row


@st.cache_data(ttl=API_CACHE_SECONDS, show_spinner=False)
def fetch_nvd_records():
    """Fetch CVEs that NVD currently flags as present in CISA KEV.

    In normal operation the KEV result fits in one response. Pagination is kept
    as a safeguard if the catalog grows beyond NVD's 2,000-record page size.
    """
    page_size = 2000
    start_index = 0
    total_results = None
    records = []
    while total_results is None or start_index < total_results:
        url = f"{NVD_API_URL}?hasKev&resultsPerPage={page_size}&startIndex={start_index}"
        payload = _http_json(url, timeout=60)
        items = payload.get("vulnerabilities", []) or []
        if total_results is None:
            total_results = int(payload.get("totalResults", len(items)))
        records.extend(_parse_nvd_record(item) for item in items)
        if not items:
            break
        start_index += len(items)
        if start_index < total_results:
            # Respect NVD's lower unauthenticated API request rate.
            time.sleep(6.5)
    cols = [
        "cveID", "published", "lastModified", "cvssScore", "nvdSeverity",
        "attackVector", "attackComplexity", "privilegesRequired", "userInteraction",
        "scope", "confidentialityImpact", "integrityImpact", "availabilityImpact", "cvssVector",
    ]
    frame = pd.DataFrame(records, columns=cols)
    if not frame.empty:
        frame = frame.drop_duplicates(subset=["cveID"], keep="last")
    return frame


def _epss_batches(cve_ids, max_chars=1800):
    batch, chars = [], 0
    for cve_id in cve_ids:
        token_len = len(cve_id) + (1 if batch else 0)
        if batch and chars + token_len > max_chars:
            yield batch
            batch, chars = [], 0
            token_len = len(cve_id)
        batch.append(cve_id)
        chars += token_len
    if batch:
        yield batch


def _fetch_epss_batch(batch):
    payload = _http_json(EPSS_API_URL, params={"cve": ",".join(batch), "limit": 10000}, timeout=30)
    return payload.get("data", []) or []


@st.cache_data(ttl=API_CACHE_SECONDS, show_spinner=False)
def fetch_epss_records(cve_ids):
    """Fetch latest EPSS scores for the current KEV population in batches."""
    batches = list(_epss_batches(list(cve_ids)))
    records, errors = [], []
    # Parallelise a modest number of public API calls to avoid a long cold start.
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(_fetch_epss_batch, batch): batch for batch in batches}
        for future in as_completed(futures):
            try:
                records.extend(future.result())
            except Exception as exc:
                errors.append(str(exc))
    rows = []
    for item in records:
        rows.append({
            "cveID": item.get("cve"),
            "epssScore": item.get("epss"),
            "percentile": item.get("percentile"),
            "scoreDate": item.get("date"),
        })
    frame = pd.DataFrame(rows, columns=["cveID", "epssScore", "percentile", "scoreDate"])
    if not frame.empty:
        frame = frame.drop_duplicates(subset=["cveID"], keep="last")
    return frame, errors


@st.cache_data(ttl=API_CACHE_SECONDS, show_spinner=False)
def build_master():
    kev, catalog_meta = fetch_kev_records()
    warnings = []

    # NVD is requested once for the whole KEV cohort rather than once per CVE.
    try:
        nvd = fetch_nvd_records()
    except Exception as exc:
        nvd = pd.DataFrame(columns=[
            "cveID", "published", "lastModified", "cvssScore", "nvdSeverity",
            "attackVector", "attackComplexity", "privilegesRequired", "userInteraction",
            "scope", "confidentialityImpact", "integrityImpact", "availabilityImpact", "cvssVector",
        ])
        warnings.append(f"NVD gagal diakses; nilai CVSS/attack metrics mungkin kosong ({exc}).")

    # Pull EPSS for the current CISA catalog, not for an old exported snapshot.
    cve_ids = tuple(kev["cveID"].dropna().astype(str).unique().tolist())
    try:
        epss, epss_errors = fetch_epss_records(cve_ids)
        if epss_errors:
            warnings.append(
                f"Sebagian batch EPSS gagal diakses ({len(epss_errors)} batch). "
                "Sebagian nilai EPSS bisa kosong; muat ulang beberapa saat lagi."
            )
    except Exception as exc:
        epss = pd.DataFrame(columns=["cveID", "epssScore", "percentile", "scoreDate"])
        warnings.append(f"EPSS gagal diakses; nilai EPSS mungkin kosong ({exc}).")

    # Ensure expected columns exist even if an upstream API has a partial schema.
    kev_defaults = {
        "vendorProject": "Unknown", "product": "Unknown", "vulnerabilityName": "",
        "dateAdded": None, "dueDate": None, "knownRansomwareCampaignUse": "Unknown",
        "shortDescription": "", "requiredAction": "", "notes": "", "cwes": "",
    }
    for col, default in kev_defaults.items():
        if col not in kev.columns:
            kev[col] = default

    for col in ["cvssScore", "published", "lastModified", "attackVector", "attackComplexity",
                "privilegesRequired", "userInteraction", "scope", "confidentialityImpact",
                "integrityImpact", "availabilityImpact"]:
        if col not in nvd.columns:
            nvd[col] = np.nan
    for col in ["epssScore", "percentile", "scoreDate"]:
        if col not in epss.columns:
            epss[col] = np.nan

    for frame in (kev, nvd, epss):
        if "cveID" in frame.columns:
            frame.drop_duplicates(subset=["cveID"], keep="last", inplace=True)

    for frame, date_cols in [
        (kev, ["dateAdded", "dueDate"]),
        (nvd, ["published", "lastModified"]),
        (epss, ["scoreDate"]),
    ]:
        for col in date_cols:
            if col in frame.columns:
                frame[col] = pd.to_datetime(frame[col], errors="coerce", utc=True).dt.tz_localize(None)

    for frame, numeric_cols in [(nvd, ["cvssScore"]), (epss, ["epssScore", "percentile"])]:
        for col in numeric_cols:
            if col in frame.columns:
                frame[col] = pd.to_numeric(frame[col], errors="coerce")

    master = kev.merge(
        nvd,
        on="cveID",
        how="left",
        suffixes=("", "_nvd"),
        validate="one_to_one",
    )
    master = master.merge(
        epss,
        on="cveID",
        how="left",
        suffixes=("", "_epss"),
        validate="one_to_one",
    )

    categorical = [
        "attackVector", "attackComplexity", "privilegesRequired", "userInteraction",
        "scope", "confidentialityImpact", "integrityImpact", "availabilityImpact",
        "knownRansomwareCampaignUse",
    ]
    for col in categorical:
        if col in master.columns:
            master[col] = master[col].astype("string").str.strip().str.upper()

    master["cvssSeverity"] = pd.cut(
        master["cvssScore"],
        bins=[-0.01, 3.9, 6.9, 8.9, 10.0],
        labels=SEVERITY_ORDER,
    )
    master["remediationWindowDays"] = (master["dueDate"] - master["dateAdded"]).dt.days
    master["publishedYear"] = master["published"].dt.year
    master["kevYear"] = master["dateAdded"].dt.year

    meta = {
        "catalogVersion": catalog_meta.get("catalogVersion", "unknown"),
        "dateReleased": catalog_meta.get("dateReleased", "unknown"),
        "count": len(kev),
        "source": catalog_meta.get("source", "CISA KEV API"),
    }
    return kev, nvd, epss, master, warnings, meta


# ============================================================
# CHART HELPERS
# ============================================================
def spearman_corr(x: pd.Series, y: pd.Series) -> float:
    """Hitung korelasi Spearman tanpa dependensi SciPy.

    Spearman = Pearson correlation pada ranking data.
    """
    pair = pd.DataFrame({"x": x, "y": y}).dropna()
    if len(pair) < 2:
        return np.nan
    x_rank = pair["x"].rank(method="average")
    y_rank = pair["y"].rank(method="average")
    return float(x_rank.corr(y_rank, method="pearson"))


def base_layout(fig, height=450):
    fig.update_layout(
        height=height,
        paper_bgcolor="rgba(255,255,255,0)",
        plot_bgcolor="rgba(255,255,255,0)",
        font=dict(family="Inter, Aptos, sans-serif", color="#24465d", size=12),
        margin=dict(l=24, r=24, t=66, b=36),
        legend=dict(bgcolor="rgba(255,255,255,0)", font=dict(color="#4c687b")),
        title=dict(font=dict(size=16, color="#173b55"), x=0.02, xanchor="left"),
        colorway=["#087fa7", "#13877e", "#4476c4", "#d49a35", "#c94c5a"],
    )
    fig.update_xaxes(
        showgrid=False, zeroline=False, linecolor="#d7e4ed",
        tickfont=dict(color="#60798d"), title_font=dict(color="#34566d")
    )
    fig.update_yaxes(
        showgrid=True, gridcolor="#e8eff4", zeroline=False,
        tickfont=dict(color="#60798d"), title_font=dict(color="#34566d")
    )
    return fig


# ============================================================
# LOAD LIVE DATA
# ============================================================
if st.sidebar.button("🔄 Refresh data sekarang", use_container_width=True):
    st.cache_data.clear()
    st.rerun()

with st.spinner("Mengambil katalog KEV, metrik NVD, dan skor EPSS terbaru..."):
    try:
        df_kev, df_nvd, df_epss, df, API_WARNINGS, API_META = build_master()
    except Exception as exc:
        st.error("Dashboard gagal mengambil katalog CISA KEV dari API publik.")
        st.markdown(
            "Pastikan Streamlit Cloud memiliki akses internet dan coba muat ulang aplikasi. "
            "Sumber utama: CISA KEV, NVD CVE API 2.0, dan FIRST EPSS API."
        )
        st.exception(exc)
        st.stop()

for api_warning in API_WARNINGS:
    st.warning(api_warning)

# ============================================================
# SIDEBAR
# ============================================================
st.sidebar.markdown("## 🔐 KEV Intelligence")
st.sidebar.caption("CISA KEV × NVD × EPSS")

page = st.sidebar.radio(
    "Navigasi",
    [
        "Overview",
        "Q1 · Vendor & Product",
        "Q2 · CVSS vs EPSS",
        "Q3 · Attack Pattern",
        "Q4 · Vulnerability Profiles",
        "CVE Explorer",
    ],
)

st.sidebar.markdown("---")

# Global filters used by most pages.
vendors = sorted(df["vendorProject"].dropna().astype(str).unique().tolist())
clusters = CLUSTER_PROFILES["cluster"].tolist()

selected_vendor = st.sidebar.selectbox("Vendor", ["All"] + vendors)
selected_severity = st.sidebar.multiselect(
    "Severity",
    SEVERITY_ORDER,
    default=[],
)
selected_attack = st.sidebar.multiselect(
    "Attack Vector",
    [x for x in ATTACK_ORDER if x in set(df["attackVector"].dropna())],
    default=[],
)

filtered = df.copy()
if selected_vendor != "All":
    filtered = filtered[filtered["vendorProject"].astype(str) == selected_vendor]
if selected_severity:
    filtered = filtered[filtered["cvssSeverity"].astype(str).isin(selected_severity)]
if selected_attack:
    filtered = filtered[filtered["attackVector"].astype(str).isin(selected_attack)]

st.sidebar.markdown("---")
st.sidebar.markdown(
    '<span class="sdg">SDG 9 · Infrastruktur</span>'
    '<span class="sdg">SDG 16 · Kelembagaan Tangguh</span>',
    unsafe_allow_html=True,
)
st.sidebar.caption("Sumber langsung: CISA KEV · NVD API · FIRST EPSS API · cache 6 jam")

# ============================================================
# HEADER
# ============================================================
st.markdown(
    f"""
    <div class="hero">
        <div class="eyebrow">Cybersecurity data science</div>
        <div class="hero-title">CISA Known Exploited Vulnerabilities</div>
        <div class="hero-sub">
            Analisis interaktif atas vulnerability yang telah diketahui dieksploitasi, diperkaya dengan karakteristik teknis NVD dan probabilitas eksploitasi EPSS.
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)
st.caption(
    f"Data live dari API publik · Katalog KEV versi {API_META.get('catalogVersion', 'unknown')} "
    f"(dirilis {API_META.get('dateReleased', 'unknown')}) · "
    f"{len(df):,} CVE dimuat · cache API maksimum 6 jam; gunakan tombol Refresh data untuk memaksa update."
)

# ============================================================
# OVERVIEW
# ============================================================
if page == "Overview":
    total = len(df)
    known_ransom = int((df["knownRansomwareCampaignUse"] == "KNOWN").sum())
    median_cvss = float(df["cvssScore"].median())
    median_epss = float(df["epssScore"].median())

    cols = st.columns(4)
    metrics = [
        ("CVE", f"{total:,}", "CISA KEV population"),
        ("Median CVSS", f"{median_cvss:.1f}", "Technical severity"),
        ("Median EPSS", f"{median_epss:.2f}", "30-day exploit probability"),
        ("Ransomware Known", f"{known_ransom:,}", f"{known_ransom / total * 100:.1f}% of CVE"),
    ]
    for col, (label, value, note) in zip(cols, metrics):
        col.markdown(
            f'<div class="metric-card"><div class="metric-label">{label}</div>'
            f'<div class="metric-value">{value}</div><div class="metric-note">{note}</div></div>',
            unsafe_allow_html=True,
        )

    st.markdown('<div class="section-title">Risk snapshot</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-note">Gunakan dashboard ini untuk membaca populasi KEV dari beberapa sudut, bukan satu skor saja.</div>',
        unsafe_allow_html=True,
    )

    c1, c2 = st.columns(2)
    with c1:
        sev_counts = (
            df["cvssSeverity"].value_counts()
            .reindex(SEVERITY_ORDER)
            .fillna(0)
            .rename_axis("severity")
            .reset_index(name="jumlah")
        )
        fig = px.bar(sev_counts, x="severity", y="jumlah", text="jumlah")
        fig.update_traces(marker_color="#087fa7")
        fig.update_traces(textposition="outside")
        base_layout(fig, 390)
        fig.update_layout(title="Distribusi Severity CVSS")
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        vc = df["vendorProject"].value_counts().head(10).sort_values()
        fig = px.bar(x=vc.values, y=vc.index, orientation="h", text=vc.values)
        fig.update_traces(marker_color="#4c79bd")
        fig.update_traces(textposition="outside")
        base_layout(fig, 390)
        fig.update_layout(title="Top 10 Vendor")
        st.plotly_chart(fig, use_container_width=True)

    st.markdown('<div class="section-title">Business questions</div>', unsafe_allow_html=True)
    questions = pd.DataFrame(
        [
            ["Q1", "Vendor & Product", "Teknologi apa yang paling dominan di KEV?"],
            ["Q2", "CVSS vs EPSS", "Apakah severity teknis bergerak searah dengan EPSS?"],
            ["Q3", "Attack Pattern", "Seberapa sering eksploitasi membutuhkan interaksi pengguna?"],
            ["Q4", "Vulnerability Profiles", "Apakah KEV memiliki beberapa profil karakteristik?"],
        ],
        columns=["", "Pertanyaan", "Fokus"],
    )
    st.dataframe(questions, use_container_width=True, hide_index=True)

    st.markdown(
        '<div class="insight">'
        '<strong>Inti project:</strong> seluruh CVE pada populasi ini sudah diketahui dieksploitasi. '
        'Karena itu dashboard tidak memprediksi “apakah akan dieksploitasi”, tetapi membantu membaca '
        'tingkat severity, probabilitas eksploitasi, karakteristik serangan, dan profil vulnerability.'
        '</div>',
        unsafe_allow_html=True,
    )

# ============================================================
# Q1
# ============================================================
elif page == "Q1 · Vendor & Product":
    st.markdown('<div class="section-title">Q1 · Vendor dan Product Dominan</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-note">Komposisi teknologi yang paling sering muncul dalam katalog CISA KEV.</div>',
        unsafe_allow_html=True,
    )

    c1, c2 = st.columns(2)
    with c1:
        vendor = filtered["vendorProject"].dropna().astype(str).value_counts().head(10).sort_values()
        fig = px.bar(x=vendor.values, y=vendor.index, orientation="h", text=vendor.values)
        fig.update_traces(marker_color="#087fa7", textposition="outside")
        base_layout(fig, 500)
        fig.update_layout(title="Top 10 Vendor", xaxis_title="Jumlah CVE", yaxis_title="Vendor")
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        product = filtered["product"].dropna().astype(str).value_counts().head(10).sort_values()
        fig = px.bar(x=product.values, y=product.index, orientation="h", text=product.values)
        fig.update_traces(marker_color="#4c79bd", textposition="outside")
        base_layout(fig, 500)
        fig.update_layout(title="Top 10 Product", xaxis_title="Jumlah CVE", yaxis_title="Product")
        st.plotly_chart(fig, use_container_width=True)

    st.markdown(
        f'<div class="insight"><strong>Temuan saat ini:</strong> Microsoft merupakan vendor '
        f'terbanyak dengan 389 CVE, sedangkan Windows merupakan product terbanyak dengan 174 CVE. '
        f'Filter aktif menampilkan {len(filtered):,} CVE.</div>',
        unsafe_allow_html=True,
    )

# ============================================================
# Q2
# ============================================================
elif page == "Q2 · CVSS vs EPSS":
    st.markdown('<div class="section-title">Q2 · CVSS vs EPSS</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-note">CVSS menggambarkan severity teknis; EPSS adalah probabilitas eksploitasi menurut model EPSS untuk 30 hari berikutnya.</div>',
        unsafe_allow_html=True,
    )

    q2 = filtered[["cvssScore", "epssScore", "cvssSeverity"]].dropna().copy()
    if len(q2) < 3:
        st.warning("Data terlalu sedikit setelah filter untuk menghitung hubungan.")
    else:
        # Spearman dihitung dari ranking agar dashboard tidak membutuhkan SciPy.
        spearman = spearman_corr(q2["cvssScore"], q2["epssScore"])
        pearson = q2["cvssScore"].corr(q2["epssScore"], method="pearson")
        cols = st.columns(3)
        for col, label, value, note in [
            (cols[0], "Spearman", f"{spearman:.2f}", "Hubungan monotonic"),
            (cols[1], "Pearson", f"{pearson:.2f}", "Hubungan linear"),
            (cols[2], "Observasi", f"{len(q2):,}", "CVE lengkap"),
        ]:
            col.markdown(
                f'<div class="metric-card"><div class="metric-label">{label}</div>'
                f'<div class="metric-value">{value}</div><div class="metric-note">{note}</div></div>',
                unsafe_allow_html=True,
            )

        fig = px.density_heatmap(
            q2,
            x="cvssScore",
            y="epssScore",
            nbinsx=18,
            nbinsy=18,
            color_continuous_scale=["#edf7fb", "#82cfe1", "#087fa7"],
        )
        base_layout(fig, 500)
        fig.update_layout(title="Kepadatan CVE: CVSS vs EPSS", xaxis_title="CVSS Score", yaxis_title="EPSS Score")
        st.plotly_chart(fig, use_container_width=True)

        sev = (
            q2.groupby("cvssSeverity", observed=False)["epssScore"]
            .agg(n="count", median="median", mean="mean")
            .reindex(SEVERITY_ORDER)
            .reset_index()
        )
        c1, c2 = st.columns([1.05, 1.0])
        with c1:
            fig = px.box(q2, x="cvssSeverity", y="epssScore", category_orders={"cvssSeverity": SEVERITY_ORDER})
            fig.update_traces(marker_color="#087fa7", line_color="#087fa7")
            base_layout(fig, 420)
            fig.update_layout(title="EPSS menurut Severity", xaxis_title="CVSS Severity", yaxis_title="EPSS Score")
            st.plotly_chart(fig, use_container_width=True)
        with c2:
            st.dataframe(sev.round(3), use_container_width=True, hide_index=True)

        st.markdown(
            '<div class="insight"><strong>Inti temuan:</strong> hubungan positif ada tetapi lemah-sedang. '
            'Artinya severity teknis yang tinggi tidak selalu diikuti EPSS yang sama tinggi.</div>',
            unsafe_allow_html=True,
        )

# ============================================================
# Q3
# ============================================================
elif page == "Q3 · Attack Pattern":
    st.markdown('<div class="section-title">Q3 · Attack Vector × User Interaction</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-note">Persentase dihitung di dalam masing-masing Attack Vector sehingga mudah dibaca sebagai komposisi.</div>',
        unsafe_allow_html=True,
    )

    q3 = filtered[["attackVector", "userInteraction"]].dropna().copy()
    q3["attackVector"] = q3["attackVector"].astype(str).str.upper()
    q3["userInteraction"] = q3["userInteraction"].astype(str).str.upper()
    q3_ct = pd.crosstab(q3["attackVector"], q3["userInteraction"])
    q3_pct = pd.crosstab(q3["attackVector"], q3["userInteraction"], normalize="index") * 100
    q3_pct = q3_pct.reindex([x for x in ATTACK_ORDER if x in q3_pct.index])

    fig = go.Figure()
    for interaction in ["NONE", "REQUIRED"]:
        if interaction in q3_pct.columns:
            fig.add_bar(
                x=q3_pct.index,
                y=q3_pct[interaction],
                name="Tidak membutuhkan interaksi" if interaction == "NONE" else "Membutuhkan interaksi",
                marker_color="#13877e" if interaction == "NONE" else "#d49a35",
                hovertemplate="%{x}<br>%{y:.1f}%<extra></extra>",
            )
    fig.update_layout(barmode="stack")
    base_layout(fig, 480)
    fig.update_layout(title="User Interaction dalam Setiap Attack Vector", yaxis_title="Persentase (%)")
    st.plotly_chart(fig, use_container_width=True)

    c1, c2 = st.columns(2)
    with c1:
        heat = px.imshow(
            q3_pct.round(2),
            text_auto=".1f",
            aspect="auto",
            color_continuous_scale=["#edf7fb", "#8bd2e3", "#087fa7"],
        )
        base_layout(heat, 400)
        heat.update_layout(title="Heatmap Persentase")
        st.plotly_chart(heat, use_container_width=True)
    with c2:
        st.dataframe(q3_ct, use_container_width=True)

    st.markdown(
        '<div class="insight"><strong>Temuan utama:</strong> pada Network, sekitar 77% CVE tidak membutuhkan interaksi pengguna; '
        'pada Local, proporsi yang membutuhkan interaksi lebih tinggi (sekitar 36%).</div>',
        unsafe_allow_html=True,
    )

# ============================================================
# Q4
# ============================================================
elif page == "Q4 · Vulnerability Profiles":
    st.markdown('<div class="section-title">Q4 · Vulnerability Profiles</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-note">EDA Q4 menjadi dasar clustering. Profil dan jumlah tiap cluster tetap berasal dari snapshot pelatihan di notebook; data katalog/vendor/EPSS dan CVE Explorer di halaman lain diambil langsung dari API. Model tidak dilatih ulang di Streamlit.</div>',
        unsafe_allow_html=True,
    )

    c1, c2 = st.columns([1.15, 1])
    with c1:
        plot_profiles = CLUSTER_PROFILES.copy()
        plot_profiles["label"] = "C" + plot_profiles["cluster"].astype(str)
        plot_profiles["display_order"] = plot_profiles["cluster"].map({k: i for i, k in enumerate(CLUSTER_ORDER)})
        plot_profiles = plot_profiles.sort_values("display_order")

        fig = px.bar(
            plot_profiles,
            x="label",
            y="jumlah_CVE",
            text="jumlah_CVE",
            category_orders={"label": [f"C{k}" for k in CLUSTER_ORDER]},
        )
        fig.update_traces(marker_color="#087fa7", textposition="outside")
        base_layout(fig, 430)
        fig.update_layout(title="Ukuran 6 Cluster", xaxis_title="Cluster", yaxis_title="Jumlah CVE")
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        st.markdown("#### Cara membaca cluster")
        st.write(
            "Nomor cluster adalah label hasil algoritma, bukan ranking risiko. "
            "Urutan risiko di bawah ditentukan setelah profiling."
        )
        order_df = CLUSTER_PROFILES.set_index("cluster").loc[CLUSTER_ORDER].reset_index()
        order_df["Cluster"] = "C" + order_df["cluster"].astype(str)
        order_df["Proporsi"] = (order_df["proporsi"] * 100).round(1).astype(str) + "%"
        st.dataframe(
            order_df[["Cluster", "jumlah_CVE", "Proporsi", "cvss_median", "epss_median", "ransomware_pct"]]
            .rename(columns={
                "jumlah_CVE": "Jumlah CVE",
                "cvss_median": "CVSS med.",
                "epss_median": "EPSS med.",
                "ransomware_pct": "Ransomware %",
            }),
            use_container_width=True,
            hide_index=True,
        )

    chosen_cluster = st.selectbox(
        "Pilih cluster untuk melihat profil",
        CLUSTER_ORDER,
        format_func=lambda x: f"C{x} · {CLUSTER_PROFILES.loc[CLUSTER_PROFILES['cluster']==x, 'ciri_utama'].iloc[0]}",
    )

    row = CLUSTER_PROFILES[CLUSTER_PROFILES["cluster"] == chosen_cluster].iloc[0]
    cols = st.columns(4)
    for col, label, value in [
        (cols[0], "CVSS Median", f"{row['cvss_median']:.1f}"),
        (cols[1], "EPSS Median", f"{row['epss_median']:.2f}"),
        (cols[2], "Jumlah CVE", f"{int(row['jumlah_CVE']):,}"),
        (cols[3], "Ransomware", f"{int(row['ransomware_pct'])}%"),
    ]:
        col.markdown(
            f'<div class="metric-card"><div class="metric-label">{label}</div>'
            f'<div class="metric-value">{value}</div></div>',
            unsafe_allow_html=True,
        )

    if chosen_cluster == 2:
        style = "insight risk-high"
    else:
        style = "insight"
    st.markdown(
        f'<div class="{style}"><span class="cluster-pill">C{chosen_cluster}</span> '
        f'<strong>{row["ciri_utama"]}</strong><br>'
        f'Profil ini mencakup {int(row["jumlah_CVE"]):,} CVE ({row["proporsi"]*100:.1f}% dari populasi) dengan '
        f'median CVSS {row["cvss_median"]:.1f} dan median EPSS {row["epss_median"]:.2f}.'
        f'</div>',
        unsafe_allow_html=True,
    )

    st.markdown('<div class="section-title">Profil risiko</div>', unsafe_allow_html=True)
    profile_chart = CLUSTER_PROFILES.copy()
    profile_chart["Cluster"] = "C" + profile_chart["cluster"].astype(str)
    profile_chart["Urutan"] = profile_chart["cluster"].map({k: i for i, k in enumerate(CLUSTER_ORDER)})
    profile_chart = profile_chart.sort_values("Urutan")

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=profile_chart["cvss_median"],
        y=profile_chart["epss_median"],
        mode="markers+text",
        text=profile_chart["Cluster"],
        textposition="top center",
        marker=dict(size=np.sqrt(profile_chart["jumlah_CVE"]) * 2.0, color=profile_chart["ransomware_pct"], colorscale="Tealgrn", showscale=True, colorbar=dict(title=dict(text="Ransomware %", font=dict(color="#34566d")), tickfont=dict(color="#60798d"))),
    ))
    fig.update_layout(title="Posisi Profil Cluster: CVSS vs EPSS", xaxis_title="Median CVSS", yaxis_title="Median EPSS")
    base_layout(fig, 460)
    st.plotly_chart(fig, use_container_width=True)

    st.markdown(
        '<div class="small">Catatan: hasil cluster berasal dari Model AI pada notebook. Streamlit hanya menyajikan hasil yang sudah dihitung dan memprofilkannya; tidak ada inference model baru.</div>',
        unsafe_allow_html=True,
    )

# ============================================================
# CVE EXPLORER
# ============================================================
else:
    st.markdown('<div class="section-title">CVE Explorer</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-note">Telusuri data gabungan KEV + NVD + EPSS. Gunakan filter di sidebar untuk mempersempit hasil.</div>',
        unsafe_allow_html=True,
    )

    search = st.text_input("Cari CVE, vendor, atau product")
    view = filtered.copy()
    if search:
        pattern = search.strip()
        mask = (
            view["cveID"].astype(str).str.contains(pattern, case=False, na=False)
            | view["vendorProject"].astype(str).str.contains(pattern, case=False, na=False)
            | view["product"].astype(str).str.contains(pattern, case=False, na=False)
        )
        view = view[mask]

    st.caption(f"Menampilkan {len(view):,} dari {len(df):,} CVE")

    cols = [
        "cveID",
        "vendorProject",
        "product",
        "cvssScore",
        "cvssSeverity",
        "epssScore",
        "attackVector",
        "privilegesRequired",
        "userInteraction",
        "knownRansomwareCampaignUse",
    ]
    cols = [c for c in cols if c in view.columns]
    explorer = view[cols].copy()
    explorer = explorer.sort_values(["epssScore", "cvssScore"], ascending=[False, False])
    st.dataframe(explorer, use_container_width=True, hide_index=True, height=620)

    csv = explorer.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download filtered data (CSV)",
        data=csv,
        file_name="kev_filtered.csv",
        mime="text/csv",
    )

# ============================================================
# FOOTER
# ============================================================
st.markdown("---")
st.caption(
    "CISA KEV × NVD × EPSS · Direct API dashboard · "
    f"Catalog version {API_META.get('catalogVersion', 'unknown')} · "
    f"Loaded {datetime.now().strftime('%Y-%m-%d %H:%M')} · API cache up to 6 hours"
)
