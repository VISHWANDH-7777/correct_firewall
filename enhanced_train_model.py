import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os
import seaborn as sns
import matplotlib.pyplot as plt

class EnhancedFirewallTrainer:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = None
        
    def load_data(self, file_path):
        """Load and preprocess dataset"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Dataset not found at {file_path}")
        
        df = pd.read_csv(file_path)
        df = df.dropna()
        df = df.replace([float('inf'), -float('inf')], 0)
        
        # Remove any duplicate rows
        df = df.drop_duplicates()
        
        print(f"Loaded dataset: {file_path}")
        print(f"Shape: {df.shape}")
        print(f"Classes: {df[' Label'].value_counts()}")
        
        return df
    
    def prepare_features(self, df):
        """Prepare features for training"""
        # Get all columns except the label
        feature_columns = [col for col in df.columns if col != ' Label']
        
        # Encode categorical features
        self.label_encoder = LabelEncoder()
        
        # Handle Protocol column if it exists
        if 'Protocol' in df.columns:
            df['Protocol'] = self.label_encoder.fit_transform(df['Protocol'])
        
        X = df[feature_columns]
        y = df[' Label']
        
        self.feature_names = feature_columns
        
        return X, y
    
    def train_model(self, X_train, y_train):
        """Train the Random Forest model"""
        # Scale features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        
        # Train model with optimized parameters
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train_scaled, y_train)
        
        return X_train_scaled
    
    def evaluate_model(self, X_test, y_test):
        """Evaluate model performance"""
        X_test_scaled = self.scaler.transform(X_test)
        predictions = self.model.predict(X_test_scaled)
        
        accuracy = accuracy_score(y_test, predictions)
        report = classification_report(y_test, predictions)
        
        print(f"Model Accuracy: {accuracy:.4f}")
        print("\nClassification Report:")
        print(report)
        
        # Confusion Matrix
        cm = confusion_matrix(y_test, predictions)
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=self.model.classes_, 
                   yticklabels=self.model.classes_)
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()
        plt.savefig('confusion_matrix.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        return accuracy, predictions
    
    def feature_importance_analysis(self):
        """Analyze feature importance"""
        if self.model is None:
            print("Model not trained yet!")
            return
        
        importances = self.model.feature_importances_
        feature_importance_df = pd.DataFrame({
            'feature': self.feature_names,
            'importance': importances
        }).sort_values('importance', ascending=False)
        
        print("\nTop 20 Most Important Features:")
        print(feature_importance_df.head(20))
        
        # Plot feature importance
        plt.figure(figsize=(12, 8))
        top_features = feature_importance_df.head(20)
        plt.barh(range(len(top_features)), top_features['importance'])
        plt.yticks(range(len(top_features)), top_features['feature'])
        plt.xlabel('Feature Importance')
        plt.title('Top 20 Feature Importances')
        plt.gca().invert_yaxis()
        plt.tight_layout()
        plt.savefig('feature_importance.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        return feature_importance_df
    
    def save_model(self, model_prefix='enhanced'):
        """Save trained model and preprocessors"""
        if self.model is None:
            print("No model to save!")
            return
        
        joblib.dump(self.model, f'{model_prefix}_model.pkl')
        joblib.dump(self.scaler, f'{model_prefix}_scaler.pkl')
        joblib.dump(self.label_encoder, f'{model_prefix}_label_encoder.pkl')
        
        # Save feature names
        with open(f'{model_prefix}_features.txt', 'w') as f:
            for feature in self.feature_names:
                f.write(f"{feature}\n")
        
        print(f"Model saved with prefix: {model_prefix}")
    
    def train_on_dataset(self, dataset_path, model_prefix='enhanced'):
        """Complete training pipeline"""
        print(f"Training model on: {dataset_path}")
        
        # Load data
        df = self.load_data(dataset_path)
        
        # Prepare features
        X, y = self.prepare_features(df)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"Training set size: {X_train.shape}")
        print(f"Test set size: {X_test.shape}")
        
        # Train model
        print("Training model...")
        self.train_model(X_train, y_train)
        
        # Evaluate model
        print("Evaluating model...")
        accuracy, predictions = self.evaluate_model(X_test, y_test)
        
        # Feature importance analysis
        self.feature_importance_analysis()
        
        # Save model
        self.save_model(model_prefix)
        
        return accuracy

def main():
    trainer = EnhancedFirewallTrainer()
    
    # Check if datasets exist
    data_dir = 'data'
    if not os.path.exists(data_dir):
        print("Data directory not found. Please run generate_multiple_datasets.py first.")
        return
    
    # Train on combined dataset
    combined_dataset = 'data/combined_attacks_dataset.csv'
    if os.path.exists(combined_dataset):
        print("Training on combined dataset...")
        accuracy = trainer.train_on_dataset(combined_dataset, 'combined')
        print(f"Combined model accuracy: {accuracy:.4f}")
    else:
        print("Combined dataset not found. Please run generate_multiple_datasets.py first.")
        return
    
    # Train individual models for each attack type
    attack_types = ['ddos', 'port_scan', 'brute_force', 'web_attack', 'infiltration']
    
    for attack_type in attack_types:
        dataset_path = f'data/{attack_type}_dataset.csv'
        if os.path.exists(dataset_path):
            print(f"\nTraining {attack_type} specific model...")
            trainer_individual = EnhancedFirewallTrainer()
            accuracy = trainer_individual.train_on_dataset(dataset_path, attack_type)
            print(f"{attack_type} model accuracy: {accuracy:.4f}")
        else:
            print(f"Dataset not found: {dataset_path}")

if __name__ == "__main__":
    main()