### Django Authentication API


# Django Project Setup

## 1. Prerequisites

Ensure Python is installed on your system. If not, download and install it from [python.org](https://www.python.org/downloads/).

## 2. Clone the Git Repository

Clone the repository using the following command:

```sh
git clone <repository_url>


### 3. Create a Virtual Environment
Navigate to the project directory and create a virtual environment:

python3 -m venv venv

Activate the Virtual Environment

For Linux or macOS:

source venv/bin/activate

For Windows:

venv/Scripts/activate

4. Install Dependencies

Install the required packages from requirements.txt:

pip install -r requirements.txt

5. Create the .env File

Create a .env file in the root directory and add the following environment variables:

SECRET_KEY=YOUR_SECRET_KEY
EMAIL_HOST_USER=YOUR_EMAIL_HOST_USER (Your Email ID for sending Mail)
EMAIL_HOST_PASSWORD=YOUR_EMAIL_HOST_PASSWORD (Your Email ID Password)

Generate Django Secret Key

To generate a SECRET_KEY, open the Django shell:

python manage.py shell

Then use the following commands to generate the key:

from django.core.management.utils import get_random_secret_key
SECRET_KEY = get_random_secret_key()
print(SECRET_KEY)

Copy the generated key and paste it into the .env file without spaces between = and the key.

Configure Gmail for Sending Emails

1. Go to Google Account.

2. Search for App Passwords.

3. Create a new app password (e.g., Test), and copy the generated password.

4. Paste the password into .env for EMAIL_HOST_PASSWORD, and your email ID for EMAIL_HOST_USER.


6. Create Migrations

To create migrations for your app, use:

python manage.py makemigrations

Note: If no changes are detected, specify your app name:

python manage.py makemigrations app_name


7. Apply Migrations

Run the migrations to apply the changes to your database:

python manage.py migrate


8. Create a Superuser

Create a superuser to access the Django admin panel:

python manage.py createsuperuser

Enter your credentials for the superuser.


9. Run the Project

Finally, run the Django development server:

python manage.py runserver

Your project should now be running on http://127.0.0.1:8000/.


1. Swagger UI Page
http://127.0.0.1:8000/

    .  DRF UI Page
http://127.0.0.1:8000/auth/login/

.  Django Admin UI Page
http://127.0.0.1:8000/admin/

2. User Registration API

Endpoint: POST /api/register/

Accepts email and password, sends a one-time password (OTP) to email, and returns a success response.

3. OTP Verification API

Endpoint: POST /api/register/verify

Verifies the registration with OTP.

4. User Login API

Endpoint: POST /api/login/

Validates email and password. On success, sets auth_token in an HTTP-only cookie.

5. User Details API

Endpoint: GET /api/me/

Returns logged-in user details. Requires authentication using auth_token from cookies.

Swagger Authentication

To get user details in Swagger, you need an authentication token. After logging in, copy the token from the response and go to the Authorize tab in Swagger UI. Paste the token in the following format:

Token your_copied_token


6. Logout API

Endpoint: POST /api/logout/

Clears the auth_token cookie, logging out the user.

