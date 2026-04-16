"""
CyberSight DW — Shared Cleaning Functions
Implements all 8 cleaning steps from PRD §6.2 for CICIDS 2017 data.
Supports both original UNB format and vishwa132/HF format (decimal IPs).
"""

import logging
import struct
import socket

import numpy as np
import pandas as pd

from geo_lookup import get_geo
from mappings import (
    PROTOCOL_MAP, LABEL_NORMALISATION, ATTACK_CATEGORY_MAP,
    SEVERITY_MAP, SERVICE_MAP,
    categorize_label, get_service, get_label_severity,
)

logger = logging.getLogger(__name__)


DAY_BASE_DATES = {
    'monday':    '2017-07-03',
    'tuesday':   '2017-07-04',
    'wednesday': '2017-07-05',
    'thursday':  '2017-07-06',
    'friday':    '2017-07-07',
}


def decimal_to_ip(val) -> str:
    """Convert a decimal IP (uint32) to dotted-quad string."""
    try:
        n = int(float(val))
        if n <= 0 or n > 0xFFFFFFFF:
            return '0.0.0.0'
        return socket.inet_ntoa(struct.pack('>I', n))
    except (ValueError, TypeError, struct.error):
        return '0.0.0.0'


def normalise_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Map vishwa132/HF column names to the standard names used by the ETL."""
    df.columns = df.columns.str.strip()

    rename_map = {
        'Src IP dec': 'Source IP',
        'Dst IP dec': 'Destination IP',
        'Src Port': 'Source Port',
        'Dst Port': 'Destination Port',
        'Total Fwd Packet': 'Total Fwd Packets',
        'Total Bwd packets': 'Total Backward Packets',
        'Total Length of Fwd Packet': 'Total Length of Fwd Packets',
        'Total Length of Bwd Packet': 'Total Length of Bwd Packets',
        'FWD Init Win Bytes': 'Init_Win_bytes_forward',
        'Bwd Init Win Bytes': 'Init_Win_bytes_backward',
        'Fwd Act Data Pkts': 'act_data_pkt_fwd',
        'Fwd Seg Size Min': 'min_seg_size_forward',
        'Flow Bytes/s': 'Flow Bytes/s',
        'Flow Packets/s': 'Flow Packets/s',
        'Attempted Category': 'Attempted Category',
    }
    existing = {k: v for k, v in rename_map.items() if k in df.columns}
    df.rename(columns=existing, inplace=True)
    return df


def reconstruct_timestamps(df: pd.DataFrame, filename: str) -> pd.Series:
    """
    Reconstruct proper timestamps from truncated MM:SS.S format.
    Uses the filename to determine the base date and distributes
    rows across working hours (08:00-17:00).
    """
    base_key = filename.lower().replace('.csv', '').split('-')[0].split('_')[0]
    base_date = DAY_BASE_DATES.get(base_key, '2017-07-03')

    n = len(df)
    start = pd.Timestamp(f'{base_date} 08:00:00')
    end = pd.Timestamp(f'{base_date} 17:00:00')
    return pd.date_range(start=start, end=end, periods=n)


def clean_dataframe(df: pd.DataFrame, filename: str = '') -> pd.DataFrame:
    """Apply all 8 cleaning steps to a raw CICIDS DataFrame."""
    original_len = len(df)

    # Step 1: Normalise column names (strip + rename)
    df = normalise_columns(df)

    # Step 1b: Convert decimal IPs to dotted-quad
    if 'Source IP' in df.columns:
        sample = str(df['Source IP'].iloc[0]) if len(df) > 0 else ''
        if sample.isdigit() or (sample.replace('.', '', 1).isdigit() and '.' not in sample[:5]):
            df['Source IP'] = df['Source IP'].apply(decimal_to_ip)
            df['Destination IP'] = df['Destination IP'].apply(decimal_to_ip)

    # Step 2: Replace Infinity values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Step 3: Drop rows with NaN in critical fields
    critical = ['Source IP', 'Destination IP', 'Label', 'Timestamp']
    existing_critical = [c for c in critical if c in df.columns]
    df.dropna(subset=existing_critical, inplace=True)

    # Step 4: Fill remaining NaN numerics with 0
    df.fillna(0, inplace=True)

    # Step 5: Parse and normalize timestamps
    if 'Timestamp' in df.columns:
        sample_ts = str(df['Timestamp'].iloc[0]).strip() if len(df) > 0 else ''
        is_truncated = len(sample_ts) < 12 and ':' in sample_ts
        if is_truncated and filename:
            df['Timestamp'] = reconstruct_timestamps(df, filename)
        else:
            df['Timestamp'] = pd.to_datetime(df['Timestamp'], dayfirst=True, errors='coerce')
            df.dropna(subset=['Timestamp'], inplace=True)

    # Step 6: Decode protocol number
    if 'Protocol' in df.columns:
        try:
            df['Protocol'] = pd.to_numeric(df['Protocol'], errors='coerce').fillna(-1).astype(int)
            df['Protocol'] = df['Protocol'].map(PROTOCOL_MAP).fillna('OTHER')
        except (ValueError, TypeError):
            pass

    # Step 7: Normalize attack labels
    if 'Label' in df.columns:
        df['Label'] = df['Label'].astype(str).str.strip()
        df['Label'] = df['Label'].replace(LABEL_NORMALISATION)
        df['attack_category'] = df['Label'].apply(categorize_label)
        df['severity'] = df.apply(
            lambda r: get_label_severity(r['Label'], r['attack_category']), axis=1
        )

    # Step 8: Assign simulated geolocation
    if 'Source IP' in df.columns:
        geo = df['Source IP'].apply(lambda ip: get_geo(str(ip)))
        df['source_country'] = geo.apply(lambda g: g[0])
        df['source_region'] = geo.apply(lambda g: g[1])

    logger.info("Cleaned %d -> %d rows (dropped %d)",
                original_len, len(df), original_len - len(df))
    return df
