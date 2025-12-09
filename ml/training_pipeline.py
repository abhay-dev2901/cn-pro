"""
Training Pipeline for Network Threat Detection
Trains and evaluates multiple ML models, selects the best one
"""

import os
import sys
import time
import numpy as np
import pandas as pd
from typing import Dict, Tuple, Any
import joblib
import warnings
warnings.filterwarnings('ignore')

# ML Libraries
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)

# Local imports - handle both direct run and module run
try:
    from .dataset_loader import load_all_datasets, map_to_categories, get_category_distribution
    from .preprocessing import DataPreprocessor, prepare_train_test_split
except ImportError:
    from dataset_loader import load_all_datasets, map_to_categories, get_category_distribution
    from preprocessing import DataPreprocessor, prepare_train_test_split


class ModelTrainer:
    """
    Trains Random Forest model for threat detection
    """
    
    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.models: Dict[str, Any] = {}
        self.results: Dict[str, Dict] = {}
        self.best_model_name: str = "RandomForest"
        self.best_model: Any = None
        
    def initialize_models(self):
        """
        Initialize Random Forest model
        """
        self.models = {
            'RandomForest': RandomForestClassifier(
                n_estimators=150,
                max_depth=25,
                min_samples_split=5,
                min_samples_leaf=2,
                n_jobs=-1,
                random_state=self.random_state,
                class_weight='balanced',
                verbose=1
            )
        }
        
        print(f"Initialized model: RandomForest")
    
    def train_model(
        self, 
        name: str, 
        model: Any, 
        X_train: np.ndarray, 
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray
    ) -> Dict:
        """
        Train a single model and evaluate on validation set
        """
        print(f"\n{'='*50}")
        print(f"Training: {name}")
        print(f"{'='*50}")
        
        start_time = time.time()
        
        # Train
        model.fit(X_train, y_train)
        
        train_time = time.time() - start_time
        print(f"Training time: {train_time:.2f}s")
        
        # Predict on validation set
        y_pred = model.predict(X_val)
        
        # Calculate metrics
        metrics = {
            'accuracy': accuracy_score(y_val, y_pred),
            'precision': precision_score(y_val, y_pred, average='weighted', zero_division=0),
            'recall': recall_score(y_val, y_pred, average='weighted', zero_division=0),
            'f1': f1_score(y_val, y_pred, average='weighted', zero_division=0),
            'train_time': train_time
        }
        
        print(f"\nValidation Metrics:")
        print(f"  Accuracy:  {metrics['accuracy']:.4f}")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall:    {metrics['recall']:.4f}")
        print(f"  F1 Score:  {metrics['f1']:.4f}")
        
        return metrics
    
    def train_all_models(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray
    ):
        """
        Train all initialized models
        """
        self.initialize_models()
        
        for name, model in self.models.items():
            metrics = self.train_model(name, model, X_train, y_train, X_val, y_val)
            self.results[name] = metrics
    
    def select_best_model(self) -> Tuple[str, Any]:
        """
        Select Random Forest as the model
        """
        print("\n" + "="*60)
        print("RANDOM FOREST MODEL RESULTS")
        print("="*60)
        
        metrics = self.results['RandomForest']
        print(f"{'Metric':<20} {'Value':<12}")
        print("-"*32)
        print(f"{'Accuracy':<20} {metrics['accuracy']:<12.4f}")
        print(f"{'Precision':<20} {metrics['precision']:<12.4f}")
        print(f"{'Recall':<20} {metrics['recall']:<12.4f}")
        print(f"{'F1 Score':<20} {metrics['f1']:<12.4f}")
        print(f"{'Training Time':<20} {metrics['train_time']:<12.2f}s")
        print("-"*32)
        
        print(f"\nUsing Random Forest Model (F1 Score: {metrics['f1']:.4f})")
        
        self.best_model_name = "RandomForest"
        self.best_model = self.models['RandomForest']
        
        return self.best_model_name, self.best_model
    
    def evaluate_on_test(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
        class_labels: list
    ) -> Dict:
        """
        Evaluate the best model on test set
        """
        print("\n" + "="*60)
        print(f"FINAL EVALUATION: {self.best_model_name} on Test Set")
        print("="*60)
        
        y_pred = self.best_model.predict(X_test)
        
        # Overall metrics
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, average='weighted', zero_division=0),
            'recall': recall_score(y_test, y_pred, average='weighted', zero_division=0),
            'f1': f1_score(y_test, y_pred, average='weighted', zero_division=0)
        }
        
        print(f"\nOverall Metrics:")
        print(f"  Accuracy:  {metrics['accuracy']:.4f}")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall:    {metrics['recall']:.4f}")
        print(f"  F1 Score:  {metrics['f1']:.4f}")
        
        # Classification report
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=class_labels, zero_division=0))
        
        return metrics
    
    def save_model(self, filepath: str):
        """
        Save the best model to a file
        """
        if self.best_model is None:
            raise ValueError("No best model selected. Run train_all_models and select_best_model first.")
        
        model_data = {
            'model': self.best_model,
            'model_name': self.best_model_name,
            'metrics': self.results[self.best_model_name]
        }
        
        joblib.dump(model_data, filepath)
        print(f"\nModel saved to: {filepath}")


def run_training_pipeline(
    data_dir: str,
    output_dir: str,
    sample_per_file: int = None,
    use_important_features: bool = True
):
    """
    Run the complete training pipeline
    
    Args:
        data_dir: Directory containing CICIDS2017 CSV files
        output_dir: Directory to save model and preprocessor
        sample_per_file: Optional max samples per file (for faster training)
        use_important_features: Whether to use only important features
    """
    print("\n" + "="*70)
    print("  NETWORK THREAT DETECTION - TRAINING PIPELINE")
    print("="*70)
    
    # Step 1: Load data
    print("\nSTEP 1: Loading Dataset")
    print("-"*40)
    df = load_all_datasets(data_dir, sample_per_file=sample_per_file)
    
    # Step 2: Map to categories
    print("\nSTEP 2: Mapping Labels to Categories")
    print("-"*40)
    df = map_to_categories(df)
    print("\nCategory Distribution:")
    print(get_category_distribution(df).to_string(index=False))
    
    # Step 3: Preprocess
    print("\nSTEP 3: Preprocessing Data")
    print("-"*40)
    preprocessor = DataPreprocessor(use_important_features_only=use_important_features)
    X, y = preprocessor.fit_transform(df)
    
    # Step 4: Split data
    print("\nSTEP 4: Splitting Data")
    print("-"*40)
    X_train, X_val, X_test, y_train, y_val, y_test = prepare_train_test_split(X, y)
    
    # Step 5: Train models
    print("\nSTEP 5: Training Models")
    print("-"*40)
    trainer = ModelTrainer()
    trainer.train_all_models(X_train, y_train, X_val, y_val)
    
    # Step 6: Select best model
    print("\nSTEP 6: Selecting Best Model")
    print("-"*40)
    trainer.select_best_model()
    
    # Step 7: Final evaluation
    print("\nSTEP 7: Final Evaluation")
    print("-"*40)
    class_labels = preprocessor.get_class_labels()
    trainer.evaluate_on_test(X_test, y_test, class_labels)
    
    # Step 8: Save model and preprocessor
    print("\nSTEP 8: Saving Model and Preprocessor")
    print("-"*40)
    os.makedirs(output_dir, exist_ok=True)
    
    model_path = os.path.join(output_dir, 'model.pkl')
    preprocessor_path = os.path.join(output_dir, 'preprocessor.pkl')
    
    trainer.save_model(model_path)
    preprocessor.save(preprocessor_path)
    
    print("\n" + "="*70)
    print("  TRAINING COMPLETE")
    print("="*70)
    print(f"\nModel saved to: {model_path}")
    print(f"Preprocessor saved to: {preprocessor_path}")
    print(f"\nTo use the model:")
    print(f"  from ml.predict import ThreatPredictor")
    print(f"  predictor = ThreatPredictor('{output_dir}')")
    print(f"  result = predictor.predict(packet_features)")
    
    return trainer, preprocessor


if __name__ == "__main__":
    # Default paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    
    data_dir = os.path.join(project_dir, 'MachineLearningCVE')
    output_dir = script_dir  # Save in ml/ folder
    
    # Parse command line arguments
    sample_size = None  # Use None for full dataset
    
    if len(sys.argv) > 1:
        if sys.argv[1] == '--quick':
            sample_size = 10000  # Quick training with sample
            print("Running quick training with 10,000 samples per file...")
        elif sys.argv[1] == '--medium':
            sample_size = 50000
            print("Running medium training with 50,000 samples per file...")
        elif sys.argv[1].isdigit():
            sample_size = int(sys.argv[1])
            print(f"Running training with {sample_size} samples per file...")
    
    if len(sys.argv) > 2:
        data_dir = sys.argv[2]
    
    # Run pipeline
    run_training_pipeline(
        data_dir=data_dir,
        output_dir=output_dir,
        sample_per_file=sample_size,
        use_important_features=True
    )
