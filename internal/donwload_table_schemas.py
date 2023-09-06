import requests
import json

def download_and_parse_json(url):
    # Download the JSON data from the provided URL
    response = requests.get(url)
    response.raise_for_status()  # Raise an exception for HTTP errors

    # Parse the JSON data
    data = response.json()

    # Extract the 'name', 'description', and 'examples' of each table
    filtered_data = [
        {
            "name": table["name"],
            "description": table["description"],
            "examples": table["examples"]
        } 
        for table in data
    ]

    return filtered_data

def main():
    # URL of the JSON file to download
    url = input("Enter the URL of the current osquery table schema json: ")

    # Get the filtered data
    filtered_data = download_and_parse_json(url)

    # Write the filtered data to a new JSON file
    with open("osquery/osquery_schemas.json", "w") as outfile:
        json.dump(filtered_data, outfile, indent=4)

    print("Filtered data has been saved to 'osquery_schemas.json'.")

if __name__ == "__main__":
    main()
