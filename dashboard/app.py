"""
CyberSight DW — Streamlit Dashboard
Sidebar-driven analytics UI with global filters and backend comparison.
"""

import os
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from connectors.postgres import PostgreSQLConnector
from connectors.mongodb import MongoDBConnector
from connectors.neo4j import Neo4jConnector
from connectors.ksqldb import KsqlDBConnector

from logging_config import setup_logging

setup_logging("dashboard")
logger = logging.getLogger(__name__)

st.set_page_config(
    page_title="CyberSight DW",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

API_URL = os.environ.get("API_URL", "http://api:8000")

NAV_PAGES = [
    "Overview",
    "Threat Profiling",
    "Time Analysis",
    "Geo Analysis",
    "Network Graph",
    "Backend Comparison",
    "Backend Logs",
    "Dead Letter Queue",
]

# Branding: Streamlit has no API for toolbar/sidebar chrome. Header uses a flex-flowing
# ::before so the label sits before stDecoration (the chevron). Sidebar repeats the same
# text in an absolutely positioned block aligned with the native collapse control.
BRAND_TITLE = "CyberSight DW"
BRAND_TAGLINE = "Network Intrusion Intelligence"

st.markdown(
    f"""
    <style>
    [data-testid="stSidebar"] .stButton > button {{
        justify-content: flex-start;
        text-align: left;
        width: 100%;
    }}

    /* Top header: [title][chevron area …][toolbar → Deploy] */
    [data-testid="stHeader"] {{
        display: flex;
        flex-direction: row;
        align-items: center;
        flex-wrap: nowrap;
        column-gap: 0.15rem;
    }}
    [data-testid="stHeader"]::before {{
        content: "{BRAND_TITLE}\\A{BRAND_TAGLINE}";
        white-space: pre-line;
        position: relative;
        inset: auto;
        display: block;
        margin: 0 0 0 0.5rem;
        flex: 0 0 auto;
        align-self: center;
        font-family: "Source Sans Pro", sans-serif;
        font-size: 0.78rem;
        font-weight: 400;
        line-height: 1.25;
        color: var(--text-color);
        opacity: 0.72;
        pointer-events: none;
    }}
    
    [data-testid="stDecoration"] {{
        flex: 0 0 auto;
        align-self: center;
        margin-left: -0.35rem;
        padding-left: 0;
    }}
    /* Chevron often lives inside stToolbar; pull that cluster toward the title */
    [data-testid="stToolbar"] > div:first-child {{
        margin-left: -0.65rem;
    }}
    [data-testid="stToolbar"] {{
        flex: 1 1 auto;
        display: flex;
        justify-content: flex-end;
        align-items: center;
        min-width: 0;
    }}

    @media (max-width: 640px) {{
        [data-testid="stHeader"]::before {{
            content: "{BRAND_TITLE}";
            white-space: normal;
            opacity: 1;
        }}
    }}

    /* Sidebar: brand sits in the SAME row as << (Streamlit header sits above our content;
 negative top pulls this block into that header strip). Tune -2.75rem if your build differs. */
    [data-testid="stSidebar"] {{
        position: relative;
    }}
    [data-testid="stSidebar"] [data-testid="stVerticalBlock"] {{
        position: relative;
        overflow: visible;
    }}
    .cybersight-sidebar-brand-wrap {{
        position: absolute;
        top: -2.85rem;
        left: 0.85rem;
        right: 2.6rem;
        z-index: 1001;
        pointer-events: none;
        font-family: "Source Sans Pro", sans-serif;
    }}
    .cybersight-sidebar-brand-title {{
        font-weight: 700;
        font-size: 1.08rem;
        line-height: 1.2;
        color: var(--text-color);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }}
    .cybersight-sidebar-brand-sub {{
        font-size: 0.78rem;
        line-height: 1.25;
        color: var(--text-color);
        opacity: 0.72;
        margin-top: 0.05rem;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }}
    .cybersight-sidebar-brand-spacer {{
        width: 100%;
        height: 2.25rem;
        margin: 0;
        padding: 0;
    }}
    @media (max-width: 640px) {{
        .cybersight-sidebar-brand-sub {{ display: none; }}
    }}
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Cached resources
# ---------------------------------------------------------------------------

@st.cache_resource
def get_pg():
    return PostgreSQLConnector()

@st.cache_resource
def get_mongo():
    return MongoDBConnector()

@st.cache_resource
def get_neo4j():
    return Neo4jConnector()

@st.cache_resource
def get_ksqldb():
    return KsqlDBConnector()

# ---------------------------------------------------------------------------
# Query catalog
# ---------------------------------------------------------------------------

QUERY_CATALOG = {
    'Q1: Attack count by category':          {'pg': True,  'mongo': True,  'neo4j': True},
    'Q2: Hourly attack trend':               {'pg': True,  'mongo': True,  'neo4j': True},
    'Q3: Top 10 source IPs':                 {'pg': True,  'mongo': True,  'neo4j': True},
    'Q4: Attack type distribution':           {'pg': True,  'mongo': True,  'neo4j': True},
    'Q5: Protocol usage breakdown':           {'pg': True,  'mongo': True,  'neo4j': True},
    'Q6: Most targeted dest ports':           {'pg': True,  'mongo': True,  'neo4j': True},
    'Q7: Avg flow duration by attack type':   {'pg': True,  'mongo': True,  'neo4j': True},
    'Q8: Co-attacking IPs':                   {'pg': False, 'mongo': False, 'neo4j': True},
    'Q9: Country-level threat summary':       {'pg': True,  'mongo': True,  'neo4j': True},
    'Q10: Severity distribution over time':   {'pg': True,  'mongo': True,  'neo4j': True},
    'Q11: Weekend vs weekday comparison':     {'pg': True,  'mongo': True,  'neo4j': True},
    'Q12: Botnet activity timeline':          {'pg': True,  'mongo': True,  'neo4j': True},
}


def run_query_on_backend(query_name: str, backend: str):
    """Execute a named query on the specified backend, return (df, elapsed_ms)."""
    pg = get_pg()
    mongo = get_mongo()
    neo = get_neo4j()

    dispatch = {
        'Q1':  {'pg': pg.q1_attack_counts,     'mongo': mongo.q1_attack_counts,     'neo4j': neo.q1_attack_counts},
        'Q2':  {'pg': pg.q2_hourly_trend,       'mongo': mongo.q2_hourly_trend,       'neo4j': neo.q2_hourly_trend},
        'Q3':  {'pg': pg.q3_top_sources,        'mongo': mongo.q3_top_sources,        'neo4j': neo.q3_top_sources},
        'Q4':  {'pg': pg.q4_attack_distribution,'mongo': mongo.q4_attack_distribution,'neo4j': neo.q4_attack_distribution},
        'Q5':  {'pg': pg.q5_protocol_breakdown, 'mongo': mongo.q5_protocol_breakdown, 'neo4j': neo.q5_protocol_breakdown},
        'Q6':  {'pg': pg.q6_targeted_ports,     'mongo': mongo.q6_targeted_ports,     'neo4j': neo.q6_targeted_ports},
        'Q7':  {'pg': pg.q7_avg_duration,       'mongo': mongo.q7_avg_duration,       'neo4j': neo.q7_avg_duration},
        'Q8':  {'neo4j': neo.q8_co_attackers},
        'Q9':  {'pg': pg.get_country_summary,   'mongo': mongo.q9_country_summary,    'neo4j': neo.q9_country_summary},
        'Q10': {'pg': pg.q10_severity_over_time,'mongo': mongo.q10_severity_over_time,'neo4j': neo.q10_severity_over_time},
        'Q11': {'pg': pg.q11_weekend_weekday,   'mongo': mongo.q11_weekend_weekday,   'neo4j': neo.q11_weekend_weekday},
        'Q12': {'pg': pg.q12_botnet_timeline,   'mongo': mongo.q12_botnet_timeline,   'neo4j': neo.q12_botnet_timeline},
    }

    qkey = query_name.split(':')[0]
    start = time.time()
    df = pd.DataFrame()
    try:
        fn = dispatch.get(qkey, {}).get(backend)
        if fn:
            df = fn()
    except Exception as e:
        logger.error("Query %s on %s failed: %s", query_name, backend, e)
        st.error(f"Query failed: {e}")

    elapsed = (time.time() - start) * 1000
    return df, elapsed


ALL_BACKENDS = [
    ('pg', 'PostgreSQL'),
    ('mongo', 'MongoDB'),
    ('neo4j', 'Neo4j'),
]


def run_query_all_backends(query_name: str) -> dict:
    """Run a named query on every supported backend in parallel.

    Returns dict keyed by backend label, each value is
    {'df': DataFrame, 'elapsed_ms': float} or
    {'df': empty DataFrame, 'elapsed_ms': None, 'error': str} on failure.
    """
    support = QUERY_CATALOG[query_name]
    results = {}

    def _run(backend_key, label):
        try:
            df, elapsed = run_query_on_backend(query_name, backend_key)
            return label, {'df': df, 'elapsed_ms': elapsed}
        except Exception as exc:
            logger.error("Parallel query %s on %s failed: %s", query_name, label, exc)
            return label, {'df': pd.DataFrame(), 'elapsed_ms': None, 'error': str(exc)}

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {
            pool.submit(_run, bk, lbl): lbl
            for bk, lbl in ALL_BACKENDS if support.get(bk)
        }
        for fut in as_completed(futures):
            label, payload = fut.result()
            results[label] = payload

    return results


# ===================================================================
# SIDEBAR
# ===================================================================

def render_sidebar():
    if "nav_page" not in st.session_state:
        st.session_state.nav_page = NAV_PAGES[0]

    with st.sidebar:
        st.markdown(
            f'<div class="cybersight-sidebar-brand-wrap">'
            f'<div class="cybersight-sidebar-brand-title">{BRAND_TITLE}</div>'
            f'<div class="cybersight-sidebar-brand-sub">{BRAND_TAGLINE}</div>'
            f"</div><div class='cybersight-sidebar-brand-spacer'></div>",
            unsafe_allow_html=True,
        )
        for label in NAV_PAGES:
            active = st.session_state.nav_page == label
            if st.button(
                label,
                key=f"nav_btn_{label.replace(' ', '_')}",
                use_container_width=True,
                type="primary" if active else "tertiary",
            ):
                if st.session_state.nav_page != label:
                    st.session_state.nav_page = label
                    st.rerun()

    return st.session_state.nav_page



# ===================================================================
# PAGE: Overview
# ===================================================================

def page_overview():
    st.header("Overview")
    pg = get_pg()

    try:
        kpis = pg.get_kpis()
    except Exception as e:
        st.error(f"Cannot connect to PostgreSQL: {e}")
        return

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Events", f"{kpis.get('total_events', 0):,}")
    c2.metric("Attack Events", f"{kpis.get('attack_events', 0):,}")
    c3.metric("Attack Rate", f"{kpis.get('attack_rate', 0)}%")
    c4.metric("Unique Sources", f"{kpis.get('unique_sources', 0):,}")

    left, right = st.columns(2)

    with left:
        st.subheader("Attack Count by Category")
        df = pg.q1_attack_counts()
        if not df.empty:
            fig = px.bar(df, x='attack_category', y='total_events',
                         color='attack_category', text_auto=True)
            fig.update_layout(showlegend=False, xaxis_title="Category", yaxis_title="Events")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attack data available yet.")

    with right:
        st.subheader("Attack Category Distribution")
        if not df.empty:
            fig = px.pie(df, names='attack_category', values='total_events', hole=0.4)
            st.plotly_chart(fig, use_container_width=True)

    st.subheader("Hourly Attack Timeline")
    trend = pg.q2_hourly_trend()
    if not trend.empty:
        fig = px.area(trend, x='hour_bucket', y='event_count',
                      color='attack_category')
        fig.update_layout(xaxis_title="Time", yaxis_title="Events")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No hourly trend data available yet.")

    st.subheader("Protocol Breakdown")
    proto = pg.q5_protocol_breakdown()
    if not proto.empty:
        left2, right2 = st.columns(2)
        with left2:
            fig = px.pie(proto, names='protocol_name', values='total_events',
                         hole=0.45, title='Protocol Usage')
            st.plotly_chart(fig, use_container_width=True)
        with right2:
            fig = px.bar(proto, x='protocol_name', y='attack_pct',
                         color='protocol_name', text_auto='.1f',
                         title='Attack % per Protocol')
            fig.update_layout(showlegend=False, yaxis_title="Attack %")
            st.plotly_chart(fig, use_container_width=True)

    _ksqldb_overview_section()


@st.fragment(run_every=5)
def _ksqldb_overview_section():
    """Real-time metrics from ksqlDB materialized views."""
    ksql = get_ksqldb()
    if not ksql.is_available():
        return

    st.subheader("ksqlDB Real-Time Analytics")

    left, right = st.columns(2)

    with left:
        st.markdown("**Attack Rate (1-min window)**")
        df = ksql.get_attack_rate_1min()
        if not df.empty:
            st.dataframe(df, use_container_width=True, height=250)
        else:
            st.caption("No data yet")

    with right:
        st.markdown("**Protocol Rate (1-min window)**")
        df = ksql.get_protocol_rate_1min()
        if not df.empty:
            st.dataframe(df, use_container_width=True, height=250)
        else:
            st.caption("No data yet")

    st.markdown("**High-Volume Attack Sources (5-min window)**")
    df = ksql.get_high_volume_sources()
    if not df.empty:
        st.dataframe(df, use_container_width=True, height=200)
    else:
        st.caption("No high-volume alerts")


# ===================================================================
# PAGE: Threat Profiling
# ===================================================================

def page_threat_profiling():
    st.header("Threat Profiling")
    pg = get_pg()

    st.subheader("Top 10 Attacking Source IPs")
    sources = pg.q3_top_sources()
    if not sources.empty:
        st.dataframe(sources, use_container_width=True)
    else:
        st.info("No source data available yet.")

    left, right = st.columns(2)

    with left:
        st.subheader("Severity Breakdown")
        sev = pg.q10_severity_over_time()
        if sev.empty or "severity" not in sev.columns or "event_count" not in sev.columns:
            st.info("No severity data available yet.")
        else:
            sev_totals = (
                sev.groupby("severity", dropna=False)["event_count"]
                .sum()
                .reset_index()
                .rename(columns={"event_count": "events"})
            )
            sev_totals["severity"] = sev_totals["severity"].fillna("Unknown").astype(str).str.strip()
            sev_totals["events"] = pd.to_numeric(sev_totals["events"], errors="coerce").fillna(0)

            if sev_totals.empty or sev_totals["events"].sum() <= 0:
                st.info("No severity data available yet.")
            else:
                severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "Unknown"]
                existing_order = [s for s in severity_order if s in set(sev_totals["severity"])]
                remainder = sorted(set(sev_totals["severity"]) - set(existing_order))
                category_orders = {"severity": existing_order + remainder}

                severity_colors = {
                    "CRITICAL": "#8B0000",
                    "HIGH": "#C0392B",
                    "MEDIUM": "#E67E22",
                    "LOW": "#F1C40F",
                    "INFO": "#2E86C1",
                    "Unknown": "#7F8C8D",
                }

                fig = px.bar(
                    sev_totals,
                    x="severity",
                    y="events",
                    color="severity",
                    text_auto=True,
                    category_orders=category_orders,
                    color_discrete_map=severity_colors,
                    title="Events by Severity",
                )
                fig.update_layout(showlegend=False, xaxis_title="Severity", yaxis_title="Events")
                st.plotly_chart(fig, use_container_width=True)

    with right:
        st.subheader("Attack Duration Profile")
        dur = pg.q7_avg_duration()
        if not dur.empty:
            fig = px.bar(dur, x='attack_label', y='avg_duration_ms',
                         color='attack_category', text_auto='.0f',
                         title='Avg Duration (ms) by Attack Type')
            fig.update_layout(xaxis_tickangle=-45, xaxis_title="Attack Type",
                              yaxis_title="Avg Duration (ms)")
            st.plotly_chart(fig, use_container_width=True)

    st.subheader("Most Targeted Destination Ports")
    ports = pg.q6_targeted_ports()
    if not ports.empty:
        fig = px.bar(ports, x='dest_port', y='attack_count',
                     text='service_name', color='service_name')
        fig.update_layout(xaxis_title="Destination Port", yaxis_title="Attack Count",
                          xaxis_type='category')
        st.plotly_chart(fig, use_container_width=True)


# ===================================================================
# PAGE: Time Analysis
# ===================================================================

def page_time_analysis():
    st.header("Time Analysis")
    pg = get_pg()

    st.subheader("Day-of-Week Attack Heatmap")
    dow = pg.get_day_of_week_heatmap()
    if not dow.empty:
        day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        dow['day_of_week'] = dow['day_of_week'].str.strip()
        pivot = dow.pivot_table(index='day_of_week', columns='hour', values='event_count',
                                fill_value=0, aggfunc='sum')
        ordered = [d for d in day_order if d in pivot.index]
        pivot = pivot.reindex(ordered)
        fig = px.imshow(pivot, aspect='auto', color_continuous_scale='YlOrRd',
                        labels={'x': 'Hour of Day', 'y': 'Day of Week', 'color': 'Attacks'})
        st.plotly_chart(fig, use_container_width=True)

    left, right = st.columns(2)
    with left:
        st.subheader("Time-of-Day Distribution")
        tod = pg.get_time_of_day_distribution()
        if not tod.empty:
            fig = px.bar(tod, x='time_of_day', y='event_count', color='attack_category',
                         barmode='group')
            fig.update_layout(xaxis_title="Time of Day", yaxis_title="Attack Events")
            st.plotly_chart(fig, use_container_width=True)

    with right:
        st.subheader("Weekly Attack Trend")
        weekly = pg.get_weekly_trend()
        if not weekly.empty:
            weekly['week_label'] = weekly['year'].astype(str) + '-W' + weekly['week'].astype(str).str.zfill(2)
            fig = px.line(weekly, x='week_label', y='event_count', color='attack_category',
                          markers=True)
            fig.update_layout(xaxis_title="Week", yaxis_title="Attack Events")
            st.plotly_chart(fig, use_container_width=True)

    st.subheader("Weekend vs Weekday Comparison")
    ww = pg.q11_weekend_weekday()
    if not ww.empty:
        ww['period'] = ww['is_weekend'].map({True: 'Weekend', False: 'Weekday'})
        fig = px.bar(ww, x='attack_category', y='attack_events', color='period',
                     barmode='group', text_auto=True)
        fig.update_layout(xaxis_title="Attack Category", yaxis_title="Attack Events")
        st.plotly_chart(fig, use_container_width=True)


# ===================================================================
# PAGE: Geo Analysis
# ===================================================================

def page_geo_analysis():
    st.header("Geographic Analysis")
    pg = get_pg()

    country_data = pg.get_country_summary()
    if not country_data.empty:
        st.subheader("Attack Events by Country")
        fig = px.choropleth(
            country_data, locations='country', locationmode='country names',
            color='attack_events', hover_name='country',
            color_continuous_scale='Reds',
            title='Global Attack Distribution',
        )
        fig.update_layout(geo=dict(showframe=False, showcoastlines=True), height=500)
        st.plotly_chart(fig, use_container_width=True)

        left, right = st.columns(2)
        with left:
            st.subheader("Top Countries by Attack Volume")
            top = country_data.head(10)
            fig = px.bar(top, x='country', y='attack_events', color='country',
                         text_auto=True)
            fig.update_layout(showlegend=False, xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)

        with right:
            st.subheader("Unique IPs per Country")
            fig = px.bar(country_data.head(10), x='country', y='unique_ips',
                         color='country', text_auto=True)
            fig.update_layout(showlegend=False, xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)

        st.subheader("Country Details")
        st.dataframe(country_data, use_container_width=True)
    else:
        st.info("No geographic data available yet.")


# ===================================================================
# PAGE: Network Graph
# ===================================================================

def page_network_graph():
    st.header("Network Graph Analysis (Neo4j)")
    neo = get_neo4j()

    left, right = st.columns(2)
    with left:
        st.metric("Total Nodes", f"{neo.get_node_count():,}")
    with right:
        st.metric("Total Relationships", f"{neo.get_relationship_count():,}")

    st.subheader("Co-Attacker Relationships")
    co = neo.q8_co_attackers()
    if not co.empty:
        st.dataframe(co, use_container_width=True)

        st.subheader("Co-Attacker Network")
        try:
            edges = []
            nodes_set = set()
            for _, row in co.iterrows():
                ip1 = str(row.get('ip1', ''))
                ip2 = str(row.get('ip2', ''))
                shared = int(row.get('shared_count', 1))
                edges.append((ip1, ip2, shared))
                nodes_set.add(ip1)
                nodes_set.add(ip2)

            if edges:
                node_list = list(nodes_set)
                node_x = {n: i for i, n in enumerate(node_list)}
                import math
                positions = {}
                for i, n in enumerate(node_list):
                    angle = 2 * math.pi * i / len(node_list)
                    positions[n] = (math.cos(angle), math.sin(angle))

                edge_x, edge_y = [], []
                for ip1, ip2, _ in edges:
                    x0, y0 = positions[ip1]
                    x1, y1 = positions[ip2]
                    edge_x.extend([x0, x1, None])
                    edge_y.extend([y0, y1, None])

                fig = go.Figure()
                fig.add_trace(go.Scatter(x=edge_x, y=edge_y, mode='lines',
                                         line=dict(width=0.5, color='#888'),
                                         hoverinfo='none'))
                node_xs = [positions[n][0] for n in node_list]
                node_ys = [positions[n][1] for n in node_list]
                fig.add_trace(go.Scatter(x=node_xs, y=node_ys, mode='markers+text',
                                         marker=dict(size=10, color='#EF553B'),
                                         text=node_list, textposition='top center',
                                         textfont=dict(size=8),
                                         hoverinfo='text'))
                fig.update_layout(showlegend=False, height=500,
                                  xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                                  yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                st.plotly_chart(fig, use_container_width=True)
        except Exception as e:
            st.warning(f"Could not render network graph: {e}")
    else:
        st.info("No co-attacker data available yet. Run the full pipeline first.")

    st.subheader("Top Attacked Destinations")
    dests = neo.get_top_attacked_destinations()
    if not dests.empty:
        st.dataframe(dests, use_container_width=True)


# ===================================================================
# PAGE: Backend Comparison
# ===================================================================

def _render_single_query_comparison():
    """Single-query mode: run one query across all supported backends."""
    query_name = st.selectbox("Select Query", list(QUERY_CATALOG.keys()), key="cmp_query")
    support = QUERY_CATALOG[query_name]

    supported_labels = [lbl for bk, lbl in ALL_BACKENDS if support.get(bk)]
    unsupported_labels = [lbl for bk, lbl in ALL_BACKENDS if not support.get(bk)]

    if unsupported_labels:
        st.caption(f"Not available on: {', '.join(unsupported_labels)}")

    if st.button("Run Comparison", key="btn_run_comparison", type="primary"):
        with st.spinner("Running query on all supported backends..."):
            st.session_state['comparison_results'] = run_query_all_backends(query_name)
            st.session_state['comparison_query'] = query_name

    results = st.session_state.get('comparison_results')
    last_query = st.session_state.get('comparison_query')

    if not results or last_query != query_name:
        st.info("Select a query and click **Run Comparison** to benchmark backends side-by-side.")
        return

    cols = st.columns(len(supported_labels))
    timings = {}

    for i, label in enumerate(supported_labels):
        with cols[i]:
            entry = results.get(label, {})
            error = entry.get('error')
            if error:
                st.subheader(label)
                st.error(f"Failed: {error}")
                continue

            elapsed = entry.get('elapsed_ms', 0)
            df = entry.get('df', pd.DataFrame())
            timings[label] = elapsed

            st.subheader(label)
            st.metric("Time", f"{elapsed:.1f} ms", label_visibility="collapsed")
            st.caption(f"{elapsed:.1f} ms  ·  {len(df)} rows")
            if not df.empty:
                st.dataframe(df, use_container_width=True, height=300)
            else:
                st.info("No results returned.")

    if timings:
        st.subheader("Execution Time Comparison")
        timing_df = pd.DataFrame([
            {'Backend': k, 'Time (ms)': v} for k, v in timings.items()
        ])
        fastest = timing_df.loc[timing_df['Time (ms)'].idxmin(), 'Backend']

        colors = {k: ('#2ecc71' if k == fastest else '#3498db') for k in timings}
        fig = px.bar(timing_df, x='Backend', y='Time (ms)', color='Backend',
                     text_auto='.1f', color_discrete_map=colors)
        fig.update_layout(showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
        st.success(f"Fastest: **{fastest}** ({timings[fastest]:.1f} ms)")


def _render_full_benchmark():
    """All-queries benchmark mode: run every catalog query across backends."""
    if st.button("Run Full Benchmark", key="btn_full_benchmark", type="primary"):
        progress_bar = st.progress(0, text="Starting benchmark...")
        benchmark = {}
        catalog_items = list(QUERY_CATALOG.items())

        for idx, (qname, _support) in enumerate(catalog_items):
            progress_bar.progress(
                (idx + 1) / len(catalog_items),
                text=f"Running {qname}..."
            )
            all_results = run_query_all_backends(qname)
            benchmark[qname] = {
                label: entry.get('elapsed_ms')
                for label, entry in all_results.items()
                if entry.get('error') is None
            }

        progress_bar.empty()
        st.session_state['benchmark_results'] = benchmark

    benchmark = st.session_state.get('benchmark_results')
    if not benchmark:
        st.info("Click **Run Full Benchmark** to execute all queries across every supported backend.")
        return

    rows = []
    for qname, timings in benchmark.items():
        row = {'Query': qname.split(': ', 1)[-1]}
        for _bk, lbl in ALL_BACKENDS:
            row[lbl] = timings.get(lbl)
        valid = {k: v for k, v in timings.items() if v is not None}
        row['Fastest'] = min(valid, key=valid.get) if valid else 'N/A'
        rows.append(row)

    summary_df = pd.DataFrame(rows)

    st.subheader("Timing Comparison")
    chart_rows = []
    for qname, timings in benchmark.items():
        short = qname.split(':')[0]
        for label, ms in timings.items():
            if ms is not None:
                chart_rows.append({'Query': short, 'Backend': label, 'Time (ms)': ms})

    if chart_rows:
        chart_df = pd.DataFrame(chart_rows)
        fig = px.bar(chart_df, x='Query', y='Time (ms)', color='Backend',
                     barmode='group', text_auto='.1f')
        fig.update_layout(xaxis_tickangle=-45, xaxis_title="Query", yaxis_title="Time (ms)")
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Summary Table")
    backend_labels = [lbl for _, lbl in ALL_BACKENDS]

    def _fmt_ms(val):
        if val is None:
            return "N/A"
        return f"{val:.1f} ms"

    display_df = summary_df.copy()
    for lbl in backend_labels:
        if lbl in display_df.columns:
            display_df[lbl] = display_df[lbl].apply(_fmt_ms)

    st.dataframe(display_df, use_container_width=True, hide_index=True)

    wins = {lbl: 0 for lbl in backend_labels}
    for row in rows:
        f = row.get('Fastest', 'N/A')
        if f in wins:
            wins[f] += 1
    winner = max(wins, key=wins.get)
    st.success(f"Overall fastest backend: **{winner}** (won {wins[winner]} of {len(rows)} queries)")


def page_backend_comparison():
    st.header("Backend Comparison")

    mode = st.radio(
        "Mode",
        ["Single Query", "Full Benchmark"],
        horizontal=True,
        key="cmp_mode",
    )

    st.divider()

    if mode == "Single Query":
        _render_single_query_comparison()
    else:
        _render_full_benchmark()


# ===================================================================
# Backend Logs
# ===================================================================

LEVEL_COLORS = {
    "ERROR": "background-color: #5c2020; color: #f8b4b4",
    "WARNING": "background-color: #5c4b1f; color: #fbd38d",
    "CRITICAL": "background-color: #6b1c1c; color: #feb2b2",
}


def _style_log_level(row):
    color = LEVEL_COLORS.get(row.get("level", ""), "")
    return [color] * len(row)


def page_backend_logs():
    st.header("Backend Logs")

    col1, col2 = st.columns([3, 1])
    with col1:
        service = st.selectbox(
            "Service",
            ["All", "producer", "consumer", "dashboard"],
            key="log_service_filter",
        )
    with col2:
        st.markdown("<div style='margin-top: 1.6rem'></div>", unsafe_allow_html=True)
        refresh = st.button("Refresh", key="log_refresh", use_container_width=True)

    if refresh or "log_data" not in st.session_state:
        params: dict = {"lines": 200}
        if service != "All":
            params["service"] = service
        try:
            resp = requests.get(f"{API_URL}/logs", params=params, timeout=5)
            resp.raise_for_status()
            st.session_state.log_data = resp.json()
        except Exception as exc:
            st.error(f"Failed to fetch logs: {exc}")
            st.session_state.log_data = []

    data = st.session_state.get("log_data", [])
    if data:
        df = pd.DataFrame(data)
        st.dataframe(
            df.style.apply(_style_log_level, axis=1),
            use_container_width=True,
            height=600,
        )
    else:
        st.info("No log entries found. Services may not have produced logs yet.")


# ===================================================================
# Dead Letter Queue
# ===================================================================

def page_dlq():
    st.header("Dead Letter Queue")

    refresh = st.button("Refresh", key="dlq_refresh")

    if refresh or "dlq_data" not in st.session_state:
        try:
            resp = requests.get(f"{API_URL}/dlq", params={"limit": 200}, timeout=10)
            resp.raise_for_status()
            st.session_state.dlq_data = resp.json()
        except Exception as exc:
            st.error(f"Failed to fetch DLQ messages: {exc}")
            st.session_state.dlq_data = []

    data = st.session_state.get("dlq_data", [])
    st.metric("DLQ Messages", len(data))

    if data:
        df = pd.DataFrame(data)
        display_cols = [c for c in df.columns if c != "_error"]
        st.dataframe(df[display_cols], use_container_width=True, height=400)

        st.subheader("Error Details")
        for i, msg in enumerate(data):
            error_text = msg.get("_error", "N/A")
            src = msg.get("source_ip", "unknown")
            label = msg.get("label", "unknown")
            with st.expander(f"Message {i + 1} — {src} / {label}"):
                st.code(error_text, language="text")
                st.json(msg)
    else:
        st.info("No dead-letter messages found.")


# ===================================================================
# Main
# ===================================================================

def main():
    page = render_sidebar()

    if page == "Overview":
        page_overview()
    elif page == "Threat Profiling":
        page_threat_profiling()
    elif page == "Time Analysis":
        page_time_analysis()
    elif page == "Geo Analysis":
        page_geo_analysis()
    elif page == "Network Graph":
        page_network_graph()
    elif page == "Backend Comparison":
        page_backend_comparison()
    elif page == "Backend Logs":
        page_backend_logs()
    elif page == "Dead Letter Queue":
        page_dlq()


if __name__ == '__main__':
    main()
