import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import joblib
import os
import json

DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'nsl_kdd_preprocessed.csv')
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'rf_model.joblib')
PROTO_ENCODER_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'proto_encoder.joblib')
LABEL_ENCODER_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'label_encoder.joblib')
FEATURES_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'model_features.json')

FEATURES = ['protocol_type', 'src_bytes', 'dst_bytes']


def train_model(df):
	"""Train the real-time IDS model from a dataframe with the required columns."""
	if 'label' not in df.columns:
		raise ValueError('The dataset must contain a label column.')
	if df.empty:
		raise ValueError('The uploaded dataset is empty.')
	if df['label'].nunique() < 2:
		raise ValueError('The label column must contain at least two classes.')

	custom_features = [
		column for column in df.columns
		if column != 'label' and pd.api.types.is_numeric_dtype(df[column])
	]
	if set(FEATURES).issubset(df.columns):
		feature_columns = FEATURES
		df = df[feature_columns + ['label']].copy()
		le_proto = LabelEncoder()
		if pd.api.types.is_numeric_dtype(df['protocol_type']):
			le_proto.fit(['tcp', 'udp', 'icmp', 'other'])
		else:
			df['protocol_type'] = df['protocol_type'].astype(str).str.lower()
			df['protocol_type'] = le_proto.fit_transform(df['protocol_type'])
	elif custom_features:
		feature_columns = custom_features
		df = df[feature_columns + ['label']].copy()
		le_proto = LabelEncoder()
		le_proto.fit(['tcp', 'udp', 'icmp', 'other'])
	else:
		raise ValueError('The dataset needs numeric feature columns besides label.')

	for column in feature_columns:
		df[column] = pd.to_numeric(df[column], errors='coerce').fillna(0)

	label_le = LabelEncoder()
	df['label'] = label_le.fit_transform(df['label'].astype(str))

	X = df[feature_columns]
	y = df['label']
	stratify = y if y.value_counts().min() >= 2 else None
	X_train, X_test, y_train, y_test = train_test_split(
		X, y, test_size=0.2, random_state=42, stratify=stratify
	)

	clf = RandomForestClassifier(n_estimators=100, random_state=42)
	clf.fit(X_train, y_train)
	report = classification_report(y_test, clf.predict(X_test), zero_division=0)

	os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
	joblib.dump(clf, MODEL_PATH)
	joblib.dump(le_proto, PROTO_ENCODER_PATH)
	joblib.dump(label_le, LABEL_ENCODER_PATH)
	with open(FEATURES_PATH, 'w') as stream:
		json.dump(feature_columns, stream, indent=2)
	return report, len(df), list(label_le.classes_)

if __name__ == '__main__':
	report, row_count, classes = train_model(pd.read_csv(DATA_PATH))
	print(f'Training complete on {row_count} rows. Classes: {classes}')
	print(report)