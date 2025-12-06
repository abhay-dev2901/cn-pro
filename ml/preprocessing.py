"""
Preprocessing Module for Network Traffic Data
Handles cleaning, normalization, and feature engineering
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from typing import Tuple, Dict, List, Optional
import joblib
import os
import warnings
warnings.filterwarnings('ignore')


# Features to exclude from training (identifiers, redundant)
EXCLUDE_FEATURES = [
    'label', 'attack_category', 'fwd_header_length_2'  # duplicate column
]

# Important features for threat detection (based on domain knowledge)
IMPORTANT_FEATURES = [
    'destination_port', 'flow_duration', 'total_fwd_packets', 'total_bwd_packets',
    'total_length_fwd_packets', 'total_length_bwd_packets', 'fwd_packet_length_max',
    'fwd_packet_length_mean', 'bwd_packet_length_max', 'bwd_packet_length_mean',
    'flow_bytes_per_s', 'flow_packets_per_s', 'flow_iat_mean', 'flow_iat_std',
    'fwd_iat_total', 'fwd_iat_mean', 'bwd_iat_total', 'bwd_iat_mean',
    'fwd_psh_flags', 'bwd_psh_flags', 'fwd_header_length', 'bwd_header_length',
    'fwd_packets_per_s', 'bwd_packets_per_s', 'min_packet_length', 'max_packet_length',
    'packet_length_mean', 'packet_length_std', 'fin_flag_count', 'syn_flag_count',
    'rst_flag_count', 'psh_flag_count', 'ack_flag_count', 'urg_flag_count',
    'down_up_ratio', 'average_packet_size', 'init_win_bytes_forward',
    'init_win_bytes_backward', 'act_data_pkt_fwd', 'active_mean', 'idle_mean'
]


class DataPreprocessor:
    """
    Preprocessor for network traffic data
    Handles cleaning, normalization, and feature encoding
    """
    
    def __init__(self, use_important_features_only: bool = False):
        """
        Initialize the preprocessor
        
        Args:
            use_important_features_only: If True, only use the most important features
        """
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns: List[str] = []
        self.use_important_features_only = use_important_features_only
        self.is_fitted = False
        
    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean the dataset by handling missing values and infinities
        
        Args:
            df: Raw DataFrame
            
        Returns:
            Cleaned DataFrame
        """
        df = df.copy()
        
        # Replace infinity values with NaN
        df = df.replace([np.inf, -np.inf], np.nan)
        
        # Get numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        # Fill NaN with median for numeric columns
        for col in numeric_cols:
            if df[col].isna().any():
                median_val = df[col].median()
                if pd.isna(median_val):
                    median_val = 0
                df[col] = df[col].fillna(median_val)
        
        # Remove rows with any remaining NaN in label
        if 'label' in df.columns:
            df = df.dropna(subset=['label'])
        
        # Remove duplicate rows
        initial_len = len(df)
        df = df.drop_duplicates()
        if len(df) < initial_len:
            print(f"  Removed {initial_len - len(df)} duplicate rows")
        
        return df
    
    def get_feature_columns(self, df: pd.DataFrame) -> List[str]:
        """
        Get the list of feature columns to use for training
        
        Args:
            df: DataFrame
            
        Returns:
            List of feature column names
        """
        # Get numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        
        # Remove excluded columns
        feature_cols = [col for col in numeric_cols if col not in EXCLUDE_FEATURES]
        
        # Use important features only if specified
        if self.use_important_features_only:
            feature_cols = [col for col in feature_cols if col in IMPORTANT_FEATURES]
        
        return feature_cols
    
    def fit_transform(self, df: pd.DataFrame, label_col: str = 'attack_category') -> Tuple[np.ndarray, np.ndarray]:
        """
        Fit the preprocessor and transform the data
        
        Args:
            df: DataFrame with features and labels
            label_col: Name of the label column
            
        Returns:
            Tuple of (X_scaled, y_encoded)
        """
        print("Preprocessing data...")
        
        # Clean data
        df = self.clean_data(df)
        
        # Get feature columns
        self.feature_columns = self.get_feature_columns(df)
        print(f"  Using {len(self.feature_columns)} features")
        
        # Extract features
        X = df[self.feature_columns].values
        
        # Handle any remaining NaN or inf
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        
        # Fit and transform features
        X_scaled = self.scaler.fit_transform(X)
        
        # Encode labels
        y = df[label_col].values
        y_encoded = self.label_encoder.fit_transform(y)
        
        self.is_fitted = True
        
        print(f"  Classes: {list(self.label_encoder.classes_)}")
        print(f"  X shape: {X_scaled.shape}, y shape: {y_encoded.shape}")
        
        return X_scaled, y_encoded
    
    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """
        Transform new data using fitted preprocessor
        
        Args:
            df: DataFrame with features
            
        Returns:
            Scaled feature array
        """
        if not self.is_fitted:
            raise ValueError("Preprocessor not fitted. Call fit_transform first.")
        
        # Clean data
        df = self.clean_data(df)
        
        # Ensure all required columns exist
        missing_cols = [col for col in self.feature_columns if col not in df.columns]
        if missing_cols:
            # Add missing columns with 0 values
            for col in missing_cols:
                df[col] = 0
        
        # Extract features in the same order
        X = df[self.feature_columns].values
        
        # Handle NaN and inf
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        
        # Transform
        X_scaled = self.scaler.transform(X)
        
        return X_scaled
    
    def inverse_transform_labels(self, y_encoded: np.ndarray) -> np.ndarray:
        """
        Convert encoded labels back to original labels
        """
        return self.label_encoder.inverse_transform(y_encoded)
    
    def get_class_labels(self) -> List[str]:
        """
        Get the list of class labels
        """
        return list(self.label_encoder.classes_)
    
    def save(self, filepath: str):
        """
        Save the preprocessor to a file
        
        Args:
            filepath: Path to save the preprocessor
        """
        state = {
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'feature_columns': self.feature_columns,
            'use_important_features_only': self.use_important_features_only,
            'is_fitted': self.is_fitted
        }
        joblib.dump(state, filepath)
        print(f"Preprocessor saved to {filepath}")
    
    @classmethod
    def load(cls, filepath: str) -> 'DataPreprocessor':
        """
        Load a preprocessor from a file
        
        Args:
            filepath: Path to the saved preprocessor
            
        Returns:
            Loaded DataPreprocessor instance
        """
        state = joblib.load(filepath)
        
        preprocessor = cls(use_important_features_only=state['use_important_features_only'])
        preprocessor.scaler = state['scaler']
        preprocessor.label_encoder = state['label_encoder']
        preprocessor.feature_columns = state['feature_columns']
        preprocessor.is_fitted = state['is_fitted']
        
        return preprocessor


def prepare_train_test_split(
    X: np.ndarray, 
    y: np.ndarray, 
    test_size: float = 0.2,
    val_size: float = 0.1,
    random_state: int = 42
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """
    Split data into train, validation, and test sets
    
    Args:
        X: Feature array
        y: Label array
        test_size: Proportion for test set
        val_size: Proportion for validation set (from remaining after test)
        random_state: Random seed
        
    Returns:
        Tuple of (X_train, X_val, X_test, y_train, y_val, y_test)
    """
    # First split: separate test set
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    
    # Second split: separate validation from training
    val_ratio = val_size / (1 - test_size)
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=val_ratio, random_state=random_state, stratify=y_temp
    )
    
    print(f"\nData Split:")
    print(f"  Training:   {len(X_train)} samples ({len(X_train)/(len(X_train)+len(X_val)+len(X_test))*100:.1f}%)")
    print(f"  Validation: {len(X_val)} samples ({len(X_val)/(len(X_train)+len(X_val)+len(X_test))*100:.1f}%)")
    print(f"  Test:       {len(X_test)} samples ({len(X_test)/(len(X_train)+len(X_val)+len(X_test))*100:.1f}%)")
    
    return X_train, X_val, X_test, y_train, y_val, y_test


def create_features_from_packet(packet_data: Dict) -> pd.DataFrame:
    """
    Create feature DataFrame from a single packet/flow data
    This is used during prediction time
    
    Args:
        packet_data: Dictionary with packet/flow information
        
    Returns:
        DataFrame with features ready for prediction
    """
    # Default values for all features
    default_features = {
        'destination_port': 0,
        'flow_duration': 0,
        'total_fwd_packets': 1,
        'total_bwd_packets': 0,
        'total_length_fwd_packets': 0,
        'total_length_bwd_packets': 0,
        'fwd_packet_length_max': 0,
        'fwd_packet_length_min': 0,
        'fwd_packet_length_mean': 0,
        'fwd_packet_length_std': 0,
        'bwd_packet_length_max': 0,
        'bwd_packet_length_min': 0,
        'bwd_packet_length_mean': 0,
        'bwd_packet_length_std': 0,
        'flow_bytes_per_s': 0,
        'flow_packets_per_s': 0,
        'flow_iat_mean': 0,
        'flow_iat_std': 0,
        'flow_iat_max': 0,
        'flow_iat_min': 0,
        'fwd_iat_total': 0,
        'fwd_iat_mean': 0,
        'fwd_iat_std': 0,
        'fwd_iat_max': 0,
        'fwd_iat_min': 0,
        'bwd_iat_total': 0,
        'bwd_iat_mean': 0,
        'bwd_iat_std': 0,
        'bwd_iat_max': 0,
        'bwd_iat_min': 0,
        'fwd_psh_flags': 0,
        'bwd_psh_flags': 0,
        'fwd_urg_flags': 0,
        'bwd_urg_flags': 0,
        'fwd_header_length': 20,
        'bwd_header_length': 0,
        'fwd_packets_per_s': 0,
        'bwd_packets_per_s': 0,
        'min_packet_length': 0,
        'max_packet_length': 0,
        'packet_length_mean': 0,
        'packet_length_std': 0,
        'packet_length_variance': 0,
        'fin_flag_count': 0,
        'syn_flag_count': 0,
        'rst_flag_count': 0,
        'psh_flag_count': 0,
        'ack_flag_count': 0,
        'urg_flag_count': 0,
        'cwe_flag_count': 0,
        'ece_flag_count': 0,
        'down_up_ratio': 0,
        'average_packet_size': 0,
        'avg_fwd_segment_size': 0,
        'avg_bwd_segment_size': 0,
        'fwd_avg_bytes_bulk': 0,
        'fwd_avg_packets_bulk': 0,
        'fwd_avg_bulk_rate': 0,
        'bwd_avg_bytes_bulk': 0,
        'bwd_avg_packets_bulk': 0,
        'bwd_avg_bulk_rate': 0,
        'subflow_fwd_packets': 1,
        'subflow_fwd_bytes': 0,
        'subflow_bwd_packets': 0,
        'subflow_bwd_bytes': 0,
        'init_win_bytes_forward': 0,
        'init_win_bytes_backward': 0,
        'act_data_pkt_fwd': 0,
        'min_seg_size_forward': 20,
        'active_mean': 0,
        'active_std': 0,
        'active_max': 0,
        'active_min': 0,
        'idle_mean': 0,
        'idle_std': 0,
        'idle_max': 0,
        'idle_min': 0
    }
    
    # Update with provided values
    for key, value in packet_data.items():
        key_normalized = key.lower().replace(' ', '_').replace('/', '_per_')
        if key_normalized in default_features:
            default_features[key_normalized] = value
    
    return pd.DataFrame([default_features])


if __name__ == "__main__":
    # Test preprocessing
    from dataset_loader import load_all_datasets, map_to_categories
    import os
    
    data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'MachineLearningCVE')
    
    # Load sample data
    df = load_all_datasets(data_dir, sample_per_file=5000)
    df = map_to_categories(df)
    
    # Preprocess
    preprocessor = DataPreprocessor(use_important_features_only=True)
    X, y = preprocessor.fit_transform(df)
    
    # Split
    X_train, X_val, X_test, y_train, y_val, y_test = prepare_train_test_split(X, y)
    
    print("\nPreprocessing complete!")
    print(f"Feature columns: {preprocessor.feature_columns[:5]}...")
