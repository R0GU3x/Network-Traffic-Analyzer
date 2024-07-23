import requests

class Geo:

    def __init__(self, token:str):
        self.token = token

    def fetch_json_data(self, ip:str):
        url = f"https://ipinfo.io/{ip}?token={self.token}"
        try:
            response = requests.get(url)
            response.raise_for_status()  # Check for HTTP errors
            data = response.json()  # Parse JSON data
            return data
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            return None

    

    # if data:
    #     print("Fetched JSON data:")
    #     print(data)
    # else:
    #     print("Failed to fetch JSON data.")
