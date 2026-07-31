import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

print("Loading dataset...")

df = pd.read_csv("phishing.csv")
df = df.dropna()

print("Rows:", len(df))

# Standardize label column to 0/1 integers
df["label"] = df["label"].apply(lambda x: 1 if str(x).lower() in ["1", "bad", "phishing"] else 0)

X = df["url"]
y = df["label"]

print("Creating TF-IDF...")

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(3, 5),
    max_features=50000
)

X = vectorizer.fit_transform(X)

print("Splitting data...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

print("Training Logistic Regression...")

model = LogisticRegression(
    max_iter=1000
)

model.fit(X_train, y_train)

pred = model.predict(X_test)

print("Accuracy:", accuracy_score(y_test, pred))

joblib.dump(model, "model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("Training Complete!")
