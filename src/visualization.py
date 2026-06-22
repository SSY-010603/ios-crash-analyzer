"""
Visualization module
Generates charts for crash trends, severity distribution, and clustering
"""

import logging
import io
import base64
from collections import Counter, defaultdict
from datetime import datetime

import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
import plotly.graph_objects as go
import plotly.express as px
import plotly.io as pio
import pandas as pd

from .crash_parser import CrashReport
from .clustering import CrashCluster

logger = logging.getLogger(__name__)

# Color palette
COLORS = {
    "critical": "#e74c3c",
    "high": "#e67e22",
    "medium": "#f39c12",
    "low": "#27ae60",
    "primary": "#2980b9",
    "secondary": "#8e44ad",
    "accent": "#16a085",
    "bg": "#1a1a2e",
    "card": "#16213e",
    "text": "#eaeaea",
}

sns.set_theme(style="darkgrid", palette="muted")


def fig_to_base64(fig) -> str:
    """Convert a matplotlib figure to base64-encoded PNG"""
    buf = io.BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight', dpi=100,
                facecolor='#1a1a2e', edgecolor='none')
    buf.seek(0)
    data = base64.b64encode(buf.read()).decode('utf-8')
    plt.close(fig)
    return data


def plotly_to_html(fig) -> str:
    """Convert a Plotly figure to HTML div string"""
    return pio.to_html(fig, full_html=False, include_plotlyjs='cdn')


def generate_exception_distribution_chart(reports: list[CrashReport]) -> str:
    """Pie chart of exception type distribution"""
    types = [r.exception_type or "Unknown" for r in reports]
    counter = Counter(types)

    labels = list(counter.keys())
    values = list(counter.values())

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.4,
        marker=dict(
            colors=px.colors.qualitative.Set3,
            line=dict(color='#1a1a2e', width=2)
        ),
        textinfo='label+percent',
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>',
    )])
    fig.update_layout(
        title=dict(text="Exception Type Distribution", font=dict(size=18, color='white')),
        paper_bgcolor='#1a1a2e',
        plot_bgcolor='#16213e',
        font=dict(color='white'),
        showlegend=True,
        legend=dict(bgcolor='#16213e', bordercolor='#2d2d5e'),
        height=380,
    )
    return plotly_to_html(fig)


def generate_severity_bar_chart(analyses: list[dict]) -> str:
    """Bar chart of severity distribution"""
    severity_order = ['critical', 'high', 'medium', 'low']
    color_map = {
        'critical': COLORS['critical'],
        'high': COLORS['high'],
        'medium': COLORS['medium'],
        'low': COLORS['low'],
    }
    severities = [a.get('severity', 'unknown').lower() for a in analyses]
    counter = Counter(severities)

    labels = [s for s in severity_order if s in counter]
    values = [counter[s] for s in labels]
    bar_colors = [color_map.get(s, '#888') for s in labels]

    fig = go.Figure(data=[go.Bar(
        x=labels,
        y=values,
        marker_color=bar_colors,
        text=values,
        textposition='auto',
        hovertemplate='<b>%{x}</b><br>Count: %{y}<extra></extra>',
    )])
    fig.update_layout(
        title=dict(text="Crash Severity Distribution", font=dict(size=18, color='white')),
        paper_bgcolor='#1a1a2e',
        plot_bgcolor='#16213e',
        font=dict(color='white'),
        xaxis=dict(gridcolor='#2d2d5e', title='Severity'),
        yaxis=dict(gridcolor='#2d2d5e', title='Count'),
        height=350,
    )
    return plotly_to_html(fig)


def generate_cluster_chart(clusters: list[CrashCluster]) -> str:
    """Horizontal bar chart of cluster sizes"""
    if not clusters:
        return ""

    labels = [f"Cluster {c.cluster_id}<br>({c.get_common_exception_type()})" for c in clusters[:12]]
    sizes = [c.size for c in clusters[:12]]
    unique = [c.unique_count for c in clusters[:12]]

    fig = go.Figure()
    fig.add_trace(go.Bar(
        y=labels, x=sizes,
        orientation='h',
        name='Total Crashes',
        marker_color=COLORS['primary'],
        text=sizes,
        textposition='auto',
    ))
    fig.add_trace(go.Bar(
        y=labels, x=unique,
        orientation='h',
        name='Unique Fingerprints',
        marker_color=COLORS['accent'],
        text=unique,
        textposition='auto',
    ))
    fig.update_layout(
        title=dict(text="Crash Cluster Analysis", font=dict(size=18, color='white')),
        paper_bgcolor='#1a1a2e',
        plot_bgcolor='#16213e',
        font=dict(color='white'),
        xaxis=dict(gridcolor='#2d2d5e', title='Count'),
        yaxis=dict(gridcolor='#2d2d5e'),
        barmode='overlay',
        height=max(300, 60 * len(clusters[:12])),
        legend=dict(bgcolor='#16213e'),
    )
    return plotly_to_html(fig)


def generate_root_cause_chart(analyses: list[dict]) -> str:
    """Treemap of root cause categories"""
    categories = [a.get('root_cause_category', 'other') for a in analyses]
    counter = Counter(categories)
    if not counter:
        return ""

    labels = list(counter.keys())
    values = list(counter.values())
    parents = [''] * len(labels)

    fig = go.Figure(go.Treemap(
        labels=labels,
        values=values,
        parents=parents,
        textinfo='label+value+percent root',
        marker=dict(
            colorscale='Viridis',
            showscale=True,
        ),
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>%{percentRoot:.1%}<extra></extra>',
    ))
    fig.update_layout(
        title=dict(text="Root Cause Categories", font=dict(size=18, color='white')),
        paper_bgcolor='#1a1a2e',
        font=dict(color='white'),
        height=380,
    )
    return plotly_to_html(fig)


def generate_affected_components_chart(analyses: list[dict]) -> str:
    """Bubble/scatter chart of affected components"""
    components = [a.get('affected_component', 'Unknown') for a in analyses]
    counter = Counter(components)

    if not counter:
        return ""

    df = pd.DataFrame({
        'component': list(counter.keys()),
        'count': list(counter.values()),
    }).sort_values('count', ascending=False).head(15)

    fig = px.bar(
        df, x='count', y='component',
        orientation='h',
        color='count',
        color_continuous_scale='Viridis',
        labels={'count': 'Crash Count', 'component': 'Component'},
        title='Most Affected Components',
    )
    fig.update_layout(
        paper_bgcolor='#1a1a2e',
        plot_bgcolor='#16213e',
        font=dict(color='white'),
        xaxis=dict(gridcolor='#2d2d5e'),
        yaxis=dict(gridcolor='#2d2d5e'),
        height=max(300, 40 * min(len(df), 15)),
        coloraxis_colorbar=dict(tickfont=dict(color='white'), title=dict(font=dict(color='white'))),
    )
    return plotly_to_html(fig)


def generate_tag_cloud_data(analyses: list[dict]) -> list[dict]:
    """Generate tag frequency data for a word cloud / tag display"""
    all_tags: list[str] = []
    for a in analyses:
        all_tags.extend(a.get('tags', []))
    counter = Counter(all_tags)
    max_count = max(counter.values()) if counter else 1
    result = []
    for tag, count in counter.most_common(30):
        result.append({
            "text": tag,
            "count": count,
            "weight": round(count / max_count, 2),
        })
    return result


def generate_dashboard_charts(
    reports: list[CrashReport],
    analyses: list[dict],
    clusters: list[CrashCluster],
) -> dict[str, str]:
    """Generate all dashboard charts, return as dict of HTML strings"""
    charts = {}

    if reports:
        try:
            charts['exception_distribution'] = generate_exception_distribution_chart(reports)
        except Exception as e:
            logger.error(f"Exception distribution chart failed: {e}")

    if analyses:
        try:
            charts['severity_distribution'] = generate_severity_bar_chart(analyses)
        except Exception as e:
            logger.error(f"Severity chart failed: {e}")

        try:
            charts['root_cause_distribution'] = generate_root_cause_chart(analyses)
        except Exception as e:
            logger.error(f"Root cause chart failed: {e}")

        try:
            charts['affected_components'] = generate_affected_components_chart(analyses)
        except Exception as e:
            logger.error(f"Components chart failed: {e}")

    if clusters:
        try:
            charts['cluster_analysis'] = generate_cluster_chart(clusters)
        except Exception as e:
            logger.error(f"Cluster chart failed: {e}")

    return charts
