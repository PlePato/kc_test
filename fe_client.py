import requests,json

# The URL of your FastAPI application
base_url = 'http://127.0.0.1:8000'

# Login credentials
login_data = {
    'username': 'fero',
    'password': 'heslo'
}

# Start a session to maintain cookies
with requests.Session() as session:
    # Send login request
    login_response = session.post(f'{base_url}/login', data=json.dumps(login_data))

    # Check if login was successful
    if login_response.status_code == 200:
        print("Login successful.")

        # Extract CSRF token from cookies
        csrf_token = session.cookies.get('csrf_token')
        print(f"Received CSRF token: {csrf_token}")

        # Use the CSRF token in a subsequent request
        # Example of a protected endpoint that requires CSRF token
        protected_url = f'{base_url}/process1'
        response = session.get(protected_url, data={'csrf_token': 'aa'}, headers = {"X-CSRF-TOKEN": csrf_token})
        print(f"Response from protected endpoint: {response.status_code}, {response.text}")
    else:
        print(f"Login failed: {login_response.status_code}   {login_response.content}")