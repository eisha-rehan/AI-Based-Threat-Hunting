from flask import Flask, render_template, request
import pandas as pd
import pickle
from werkzeug.utils import secure_filename
from sklearn.preprocessing import MinMaxScaler
import os

app = Flask(__name__)

# Set up directory for file uploads
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Function to load the trained model
def load_model(model_path):
    with open(model_path, 'rb') as file:
        model = pickle.load(file)
    return model

# Function to preprocess data for malware detection
def preprocess_malware_data(input_file):
    data = pd.read_csv(input_file)
    features = data.drop(['Name', 'Machine','TimeDateStamp','Malware'], axis=1, errors='ignore')
    return features

def preprocess_network_data(input_file):
    df = pd.read_csv(input_file)

    # Print columns for debugging
    print("Columns in the loaded DataFrame:", df.columns)

    # Check and handle missing data
    df.dropna(subset=['Flow Bytes/s'], inplace=True)

    # Encoding categorical variables
    df_encoded = pd.get_dummies(df)

    # Print columns after encoding
    print("Columns in the DataFrame after encoding:", df_encoded.columns)

    # Specify the numerical columns you expect to scale
    numerical_columns = ['Destination Port', 'Flow Duration', 'Total Fwd Packets', ...]  # List all expected numerical columns

    # Check if these columns exist in the DataFrame
    existing_columns = df_encoded.columns.intersection(numerical_columns)
    print("Columns available for scaling:", existing_columns)

    # Apply scaling only to existing columns
    if len(existing_columns) > 0:
        scaler = MinMaxScaler()
        df_encoded[existing_columns] = scaler.fit_transform(df_encoded[existing_columns])
    else:
        print("Expected numerical columns not found in DataFrame")

    return df_encoded


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # File upload handling
        file = request.files['fileUpload']
        filename = secure_filename(file.filename)
        file_path = os.path.join('uploads', filename)
        file.save(file_path)

        # Load models
        intrusion_model_path = '/Users/fatimaanwar/Documents/Semester 7/Info Sec/Project/AI-Based-Threat-Hunting/KNN_Model.pkl'
        malware_model_path = '/Users/fatimaanwar/Documents/Semester 7/Info Sec/Project/AI-Based-Threat-Hunting/rf_model.pkl'
        intrusion_model = load_model(intrusion_model_path)
        malware_model = load_model(malware_model_path)

        # Process the file based on the selected attack type
        attack_type = request.form['attackType']
        if attack_type == 'network':
            # Load the model to get the feature names it was trained on
            intrusion_model = load_model(intrusion_model_path)
            model_columns = list(intrusion_model.feature_names_in_)  # Get feature names from the model

            # Preprocess the data with respect to model's features
            preprocessed_data = preprocess_network_data(file_path, model_columns)

            # Predict using the model
            intrusion_predictions = intrusion_model.predict(preprocessed_data)
        elif attack_type == 'malware':
            # Preprocess and predict malware
            preprocessed_data = preprocess_malware_data(file_path)
            malware_predictions = malware_model.predict(preprocessed_data)
            num_malicious = sum(malware_predictions)
            num_benign = len(malware_predictions) - num_malicious
            malware_result = {
                'total': len(malware_predictions),
                'malicious': num_malicious,
                'benign': num_benign
            }
            return render_template('results.html', malware_result=malware_result)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
