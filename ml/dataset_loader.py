"""
Dataset Loader for CICIDS2017 Dataset
Handles loading and combining multiple CSV files from the dataset
"""

import os
import pandas as pd
import numpy as np
from typing import Tuple, List, Optional
import warnings
warnings.filterwarnings('ignore')


# Column names for CICIDS2017 dataset (cleaned)
FEATURE_COLUMNS = [
    'destination_port', 'flow_duration', 'total_fwd_packets', 'total_bwd_packets',
    'total_length_fwd_packets', 'total_length_bwd_packets', 'fwd_packet_length_max',
    'fwd_packet_length_min', 'fwd_packet_length_mean', 'fwd_packet_length_std',
    'bwd_packet_length_max', 'bwd_packet_length_min', 'bwd_packet_length_mean',
    'bwd_packet_length_std', 'flow_bytes_per_s', 'flow_packets_per_s', 'flow_iat_mean',
    'flow_iat_std', 'flow_iat_max', 'flow_iat_min', 'fwd_iat_total', 'fwd_iat_mean',
    'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min', 'bwd_iat_total', 'bwd_iat_mean',
    'bwd_iat_std', 'bwd_iat_max', 'bwd_iat_min', 'fwd_psh_flags', 'bwd_psh_flags',
    'fwd_urg_flags', 'bwd_urg_flags', 'fwd_header_length', 'bwd_header_length',
    'fwd_packets_per_s', 'bwd_packets_per_s', 'min_packet_length', 'max_packet_length',
    'packet_length_mean', 'packet_length_std', 'packet_length_variance', 'fin_flag_count',
    'syn_flag_count', 'rst_flag_count', 'psh_flag_count', 'ack_flag_count', 'urg_flag_count',
    'cwe_flag_count', 'ece_flag_count', 'down_up_ratio', 'average_packet_size',
    'avg_fwd_segment_size', 'avg_bwd_segment_size', 'fwd_header_length_2',
    'fwd_avg_bytes_bulk', 'fwd_avg_packets_bulk', 'fwd_avg_bulk_rate', 'bwd_avg_bytes_bulk',
    'bwd_avg_packets_bulk', 'bwd_avg_bulk_rate', 'subflow_fwd_packets', 'subflow_fwd_bytes',
    'subflow_bwd_packets', 'subflow_bwd_bytes', 'init_win_bytes_forward',
    'init_win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'active_mean',
    'active_std', 'active_max', 'active_min', 'idle_mean', 'idle_std', 'idle_max',
    'idle_min', 'label'
]

# Attack type mappings to broader categories
ATTACK_CATEGORY_MAP = {
    'BENIGN': 'Normal',
    'DDoS': 'DDoS',
    'DoS Hulk': 'DoS',
    'DoS GoldenEye': 'DoS',
    'DoS slowloris': 'DoS',
    'DoS Slowhttptest': 'DoS',
    'PortScan': 'PortScan',
    'FTP-Patator': 'BruteForce',
    'SSH-Patator': 'BruteForce',
    'Web Attack � Brute Force': 'BruteForce',
    'Web Attack � XSS': 'WebAttack',
    'Web Attack � Sql Injection': 'WebAttack',
    'Bot': 'Botnet',
    'Infiltration': 'Infiltration',
    'Heartbleed': 'Heartbleed'
}


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean and standardize column names
    """
    # Strip whitespace from column names
    df.columns = df.columns.str.strip()
    
    # Create a mapping from original to cleaned names
    column_mapping = {}
    for col in df.columns:
        # Convert to lowercase, replace spaces with underscores
        clean_name = col.lower().replace(' ', '_').replace('/', '_per_')
        column_mapping[col] = clean_name
    
    df = df.rename(columns=column_mapping)
    return df


def load_single_csv(filepath: str, sample_size: Optional[int] = None) -> pd.DataFrame:
    """
    Load a single CSV file from the dataset
    
    Args:
        filepath: Path to the CSV file
        sample_size: Optional number of rows to sample (for faster processing)
    
    Returns:
        DataFrame with cleaned data
    """
    print(f"Loading: {os.path.basename(filepath)}")
    
    try:
        # Read CSV with error handling
        df = pd.read_csv(filepath, encoding='utf-8', low_memory=False)
    except UnicodeDecodeError:
        df = pd.read_csv(filepath, encoding='latin-1', low_memory=False)
    
    # Clean column names
    df = clean_column_names(df)
    
    # Sample if requested
    if sample_size and len(df) > sample_size:
        df = df.sample(n=sample_size, random_state=42)
    
    print(f"  Loaded {len(df)} rows")
    return df


def load_all_datasets(data_dir: str, sample_per_file: Optional[int] = None) -> pd.DataFrame:
    """
    Load and combine all CSV files from the CICIDS2017 dataset
    
    Args:
        data_dir: Directory containing the CSV files
        sample_per_file: Optional max rows to sample per file
    
    Returns:
        Combined DataFrame with all data
    """
    csv_files = [f for f in os.listdir(data_dir) if f.endswith('.csv')]
    
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")
    
    print(f"Found {len(csv_files)} CSV files")
    
    dataframes = []
    for csv_file in csv_files:
        filepath = os.path.join(data_dir, csv_file)
        df = load_single_csv(filepath, sample_per_file)
        dataframes.append(df)
    
    # Combine all dataframes
    print("\nCombining datasets...")
    combined_df = pd.concat(dataframes, ignore_index=True)
    print(f"Total combined rows: {len(combined_df)}")
    
    return combined_df


def map_to_categories(df: pd.DataFrame, label_col: str = 'label') -> pd.DataFrame:
    """
    Map detailed attack labels to broader categories
    
    Args:
        df: DataFrame with label column
        label_col: Name of the label column
    
    Returns:
        DataFrame with 'attack_category' column added
    """
    df = df.copy()
    
    # Handle encoding issues in labels
    df[label_col] = df[label_col].astype(str).str.strip()
    
    # Map to categories
    df['attack_category'] = df[label_col].map(
        lambda x: next((v for k, v in ATTACK_CATEGORY_MAP.items() if k in x), 'Other')
    )
    
    return df


def get_label_distribution(df: pd.DataFrame, label_col: str = 'label') -> pd.DataFrame:
    """
    Get distribution of labels in the dataset
    """
    distribution = df[label_col].value_counts().reset_index()
    distribution.columns = ['Label', 'Count']
    distribution['Percentage'] = (distribution['Count'] / len(df) * 100).round(2)
    return distribution


def get_category_distribution(df: pd.DataFrame) -> pd.DataFrame:
    """
    Get distribution of attack categories
    """
    if 'attack_category' not in df.columns:
        df = map_to_categories(df)
    
    distribution = df['attack_category'].value_counts().reset_index()
    distribution.columns = ['Category', 'Count']
    distribution['Percentage'] = (distribution['Count'] / len(df) * 100).round(2)
    return distribution


if __name__ == "__main__":
    # Test the loader
    import sys
    
    # Default path
    data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'MachineLearningCVE')
    
    if len(sys.argv) > 1:
        data_dir = sys.argv[1]
    
    print(f"Loading data from: {data_dir}\n")
    
    # Load with sampling for quick test
    df = load_all_datasets(data_dir, sample_per_file=10000)
    
    # Map to categories
    df = map_to_categories(df)
    
    print("\n--- Label Distribution ---")
    print(get_label_distribution(df))
    
    print("\n--- Category Distribution ---")
    print(get_category_distribution(df))
    
    print(f"\nDataset shape: {df.shape}")
    print(f"Columns: {list(df.columns[:10])}...")
