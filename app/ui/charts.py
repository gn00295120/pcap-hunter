from __future__ import annotations

from typing import Any, Dict, List

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


def plot_world_map(ip_data: List[Dict[str, Any]], flows: List[Dict[str, Any]] = None) -> go.Figure:
    """
    Plots a world map with markers for IP locations and connectivity lines.
    ip_data: list of dicts with keys: ip, country, city, lat, lon
    flows: list of dicts with keys: src, dst (optional, for drawing lines)
    """
    if not ip_data:
        return go.Figure()

    df = pd.DataFrame(ip_data)
    if "count" not in df.columns:
        df["count"] = 1

    # Aggregate by location to size markers
    df_agg = df.groupby(["lat", "lon", "city", "country"]).size().reset_index(name="count")

    fig = go.Figure()

    # 1. Markers
    fig.add_trace(
        go.Scattergeo(
            lat=df_agg["lat"],
            lon=df_agg["lon"],
            text=df_agg["city"] + ", " + df_agg["country"] + " (" + df_agg["count"].astype(str) + ")",
            marker=dict(
                size=df_agg["count"] * 5,
                sizemode="area",
                sizemin=5,
                color="cyan",
                line=dict(width=1, color="#333"),
            ),
            name="Locations",
            hoverinfo="text",
        )
    )

    # 2. Connectivity Lines (Arcs)
    if flows:
        # Create a lookup for lat/lon by IP
        loc_map = {d["ip"]: (d["lat"], d["lon"]) for d in ip_data}

        # Limit lines to avoid clutter (e.g., top 100 unique connections)
        unique_conns = set()
        for f in flows:
            src, dst = f.get("src"), f.get("dst")
            if src in loc_map and dst in loc_map and src != dst:
                # Sort to treat A->B same as B->A for visualization
                pair = tuple(sorted((src, dst)))
                unique_conns.add(pair)

        # Draw lines
        lats, lons = [], []
        for src, dst in list(unique_conns)[:100]:
            slat, slon = loc_map[src]
            dlat, dlon = loc_map[dst]
            lats.extend([slat, dlat, None])
            lons.extend([slon, dlon, None])

        if lats:
            fig.add_trace(
                go.Scattergeo(
                    lat=lats,
                    lon=lons,
                    mode="lines",
                    line=dict(width=1, color="rgba(255, 100, 100, 0.5)"),
                    name="Connectivity",
                    hoverinfo="skip",
                )
            )

    fig.update_geos(
        showcountries=True,
        countrycolor="#444",
        showocean=True,
        oceancolor="#111",
        showland=True,
        landcolor="#222",
        bgcolor="#000",
        projection_type="natural earth",
    )
    fig.update_layout(
        title="Global Traffic Origins & Connectivity",
        template="plotly_dark",
        margin={"r": 0, "t": 30, "l": 0, "b": 0},
        height=400,  # Fixed height
    )
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
    fig.update_layout(
        margin={"r": 0, "t": 30, "l": 0, "b": 0},
        height=400,  # Fixed height
    )
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
    fig.update_layout(
        xaxis_title="Time",
        yaxis_title="Duration (seconds)",
        height=400,  # Fixed height
    )
    return fig
