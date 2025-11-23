from __future__ import annotations

from typing import Any, Dict, List

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


def plot_world_map(ip_data: List[Dict[str, Any]]) -> go.Figure:
    """
    Plots a world map with markers for IP locations.
    ip_data should be a list of dicts with keys: ip, country, city, lat, lon, count (optional)
    """
    if not ip_data:
        return go.Figure()

    df = pd.DataFrame(ip_data)
    if "count" not in df.columns:
        df["count"] = 1

    # Aggregate by location to size markers
    df_agg = df.groupby(["lat", "lon", "city", "country"]).size().reset_index(name="count")

    fig = px.scatter_geo(
        df_agg,
        lat="lat",
        lon="lon",
        hover_name="city",
        hover_data={"country": True, "count": True, "lat": False, "lon": False},
        size="count",
        projection="natural earth",
        title="Global Traffic Origins",
        template="plotly_dark",
    )
    fig.update_geos(
        showcountries=True,
        countrycolor="#444",
        showocean=True,
        oceancolor="#111",
        showland=True,
        landcolor="#222",
        bgcolor="#000",
    )
    fig.update_layout(margin={"r": 0, "t": 30, "l": 0, "b": 0})
    return fig


def plot_protocol_distribution(protocol_counts: Dict[str, int]) -> go.Figure:
    """
    Plots a donut chart of protocol distribution.
    """
    if not protocol_counts:
        return go.Figure()

    labels = list(protocol_counts.keys())
    values = list(protocol_counts.values())

    fig = px.pie(
        names=labels,
        values=values,
        hole=0.4,
        title="Protocol Distribution",
        template="plotly_dark",
        color_discrete_sequence=px.colors.qualitative.Pastel,
    )
    fig.update_traces(textposition="inside", textinfo="percent+label")
    fig.update_layout(margin={"r": 0, "t": 30, "l": 0, "b": 0})
    return fig


def plot_flow_timeline(flows: List[Dict[str, Any]]) -> go.Figure:
    """
    Plots a scatter plot of flows over time.
    flows is a list of dicts from pyshark_pass.
    """
    if not flows:
        return go.Figure()

    # Extract start times and durations (if available, else just points)
    data = []
    for f in flows:
        if not f.get("pkt_times"):
            continue
        start_ts = min(f["pkt_times"])
        duration = max(f["pkt_times"]) - start_ts
        proto = f.get("proto", "Unknown")
        size = f.get("count", 1)

        data.append(
            {
                "Start Time": pd.to_datetime(start_ts, unit="s"),
                "Duration (s)": duration,
                "Protocol": proto,
                "Packets": size,
                "Src": f.get("src"),
                "Dst": f.get("dst"),
            }
        )

    if not data:
        return go.Figure()

    df = pd.DataFrame(data)

    fig = px.scatter(
        df,
        x="Start Time",
        y="Duration (s)",
        color="Protocol",
        size="Packets",
        hover_data=["Src", "Dst", "Packets"],
        title="Flow Timeline & Duration",
        template="plotly_dark",
    )
    fig.update_layout(xaxis_title="Time", yaxis_title="Duration (seconds)")
    return fig
