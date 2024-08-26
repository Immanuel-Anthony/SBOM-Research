import joblib
import pandas as pd
import json
import os

#Read file and extract vulnerabilities and id
def extract_cve_ids(file_path):
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
        vulnerabilities = data.get('vulnerabilities', [])
        cve_ids = [vuln.get('id') for vuln in vulnerabilities if 'id' in vuln]
        return cve_ids

#Load data from pickle file
def load_data(file_path):
    return joblib.load(file_path)

#Convert dataframe into a dictionary for faster process times
def prepare_lookup_dict(df):
    lookup_dict = df.set_index('cveId').to_dict(orient='index')
    return lookup_dict

#Retrieve information of cveId
def predict_cve_info(cve_id, lookup_dict):
    record = lookup_dict.get(cve_id, None)
    if record:
        return {
            'description': record['description'],
            'metrics': record['metrics'],
            'cveMetadata': record['cveMetadata']
        }   
    else:
        return None

#Get information for each cveId from an array
def process_cve_files(cve_files, lookup_dict):
    cve_info = {}
    for cve_id in cve_files:
        info = predict_cve_info(cve_id, lookup_dict)
        if info:
            cve_info[cve_id] = info
        else:
            cve_info[cve_id] = "No information available"
    return cve_info

#Save information to a JSON file
def save_to_json(data, output_file):
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=4)

#Making the JSON file readable
def fix_metrics_field(metrics_str):
    try:
        fixed_metrics_str = metrics_str.replace('\\n', '\n').replace('\\"', '"')
        return json.loads(fixed_metrics_str)
    except json.JSONDecodeError as e:
        print(f"Error decoding metrics: {e}")
        return None

#Fixes 'metrics' fields in CVE data JSON and saves it.
def process_cve_data(input_file, output_file):
    with open(input_file, 'r') as file:
        raw_data = file.read()

    try:
        data = json.loads(raw_data)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return

    for cve_id, cve_info in data.items():
        if 'metrics' in cve_info:
            cve_info['metrics'] = fix_metrics_field(cve_info['metrics'])

    with open(output_file, 'w') as file:
        json.dump(data, file, indent=4, sort_keys=True)
        

file_path = input("Enter the file path of the SBOM File : ")

cve_ids = extract_cve_ids(file_path)

#Remark if no cveIds were found in the given SBOM file
if not cve_ids :
    print("No CVE Ids found in the following SBOM file")


print("Creating file...\nThe file creation process should take less than a minute, or almost a minute at most, depending on your system's performance.")

# Load the pre-processed data
data_file = 'CVEmodel.pkl'
data = load_data(data_file)

# Convert the dictionary back to a DataFrame
df = pd.DataFrame(data['data'])

# Prepare lookup dictionary
lookup_dict = prepare_lookup_dict(df)

# Process CVE files and get their information
cve_info = process_cve_files(cve_ids, lookup_dict)

# Save the results to a JSON file
cveSavedFile = 'cveFinal.json'
save_to_json(cve_info, cveSavedFile)

#Create output file
output_file = 'cveData.json'
process_cve_data(cveSavedFile , output_file)

#Delete initial JSON file for cleaner execution
os.remove(cveSavedFile)
print("\n\nFile created at ",os.path.abspath(output_file))