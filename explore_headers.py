import requests

# The authorized local lab target 
url = "http://localhost:3000"

# Send a normal GET request — just like a browser would
response = requests.get(url)

# Print the status code (e.g. 200 = success)
print("Status Code:", response.status_code)

print("\n--- Response Headers ---")
for header_name, header_value in response.headers.items():
    print(f"{header_name}: {header_value}")