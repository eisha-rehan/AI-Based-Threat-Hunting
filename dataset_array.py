import pandas as pd

def extract_file_names(file_path):
    """Extracts file names from the given CSV file."""
    data = pd.read_csv(file_path)
    file_names = data['Name'].tolist()  # Assuming 'Name' is the column with file names
    return file_names

def main():
    file_path = '/Users/fatimaanwar/Documents/Semester 7/Info Sec/Project/archive/dataset_test.csv'  # Replace with the path to your dataset_test.csv
    file_names = extract_file_names(file_path)
    print("Extracted File Names:", file_names)

if __name__ == "__main__":
    main()
