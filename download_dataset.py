import os
import requests
import zipfile
import io

def download_and_extract_dataset():
    url = "http://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/CSVs/MachineLearningCSV.zip"
    target_dir = "MachineLearningCVE"
    zip_path = "MachineLearningCSV.zip"

    # Ensure directory exists
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
        print(f"Created directory: {target_dir}")

    # Check if dataset already extracted
    extracted_files = [f for f in os.listdir(target_dir) if f.endswith(".csv")]
    if extracted_files:
        print("Dataset already extracted. Skipping download.")
        return

    # Check if ZIP already downloaded
    if os.path.exists(zip_path):
        print(f"ZIP already exists: {zip_path}. Extracting...")
        try:
            with zipfile.ZipFile(zip_path, 'r') as z:
                z.extractall(target_dir)
            print(f"Dataset extracted to {target_dir}")
        except zipfile.BadZipFile:
            print("Corrupted ZIP file. Redownloading...")
            os.remove(zip_path)
        else:
            return

    # Download ZIP if not present
    print(f"Downloading dataset from {url}...")
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()

        with open(zip_path, "wb") as f:
            f.write(response.content)
        print("Download complete. Extracting...")

        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(target_dir)

        print(f"Dataset extracted to {target_dir}")

    except requests.exceptions.RequestException as e:
        print(f"Error downloading dataset: {e}")
    except zipfile.BadZipFile:
        print("Error: Downloaded file is not a valid ZIP.")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    download_and_extract_dataset()
