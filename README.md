# Security-Project

Before starting the project:
        1. Download the file named key , in the SSP Folder
        2. Place it in your C drive , the path should be like this C:\key\...

Sherman:

    HTTPS:
        Step 1: Download Ngrok from www.ngrok.com and follow the installation steps to set up ngrok.exe.
        Step 2: Comment out lines 1824 to 1826.
        Step 3: Run the project.
        Step 4: In the Ngrok terminal, type ngrok http https://127.0.0.1:8443.
        Step 5: Click on the link provided by Ngrok under "Forwarding." This will create a secure channel between the local server and the provided link.
        Step 6: Don't forget to uncomment the lines you commented out earlier before proceeding with anything else.

    OAUTH:
        Step 1: Navigate to the Login Page.
        Step 2: Press the OAUTH button located next to the "Forgot Password?" link.
        Step 3: Test the OAUTH functionalities.
        Functionalities:
            1. If you don't exist in the database, you'll be prompted to register an account.
            2. If you do exist, you'll be redirected to the 2FA page to authenticate yourself.
            3. You can log in using your account credentials directly on the login page, not just through the OAUTH button.

    Secure File Upload:
        Step 1: Ensure that you are logged in.
        Step 2: Navigate to the Profile Page.
        Step 3: On the Profile Page, locate the section labeled "Submit your face for Facial Recognition login:" and press the "Choose File" button.
        Step 4: Test the upload by either selecting a file larger than 16 MB (which will crash the system, requiring you to press the back button) or by selecting a non-image file.

    Encryption:
        Step 1: Run the SQL Script.
        Step 2: Create an account.
        Step 3: Verify the email field to ensure it is encrypted and not displayed in plain text
        A snippet of the code responsible for the encryption is:
            key = Fernet.generate_key()
            f = Fernet(key)
            email_bytes = email.encode()
            encrypted_email = f.encrypt(email_bytes).decode()

Tim Feng:

    OTP phone
        1. Login to any account
        2. In the choice page, chose the phone method to verify.
        3. OTP would be sent to your phone number.
        4. OTP would expire if not done in time.
        5. There is a resend feature if user did not do it in time.
        6. User logged in if successfully verified

    OTP Authenticator:
        1. Login to any account
        2. In the choice page, chose the Authenticator method to verify.
        3. User logged in if successfully verified
        4. If you logged in once with authenticator, you would not see the qr code again

    JWT:
        1. Login to any account
        2. The data stored in the cookie would be the user information but encoded using asymmetric jwt

    Email Notifications:
        1. Enabled it in the profile page.
        2. When you login again to the account, You will be prompt the email for suspicious login.
        3. Disabled it in the profile page, if you don't want the email prompts .

    Captcha:
        1. Before loging in to any account
        2. You will need to check if you are a bot, by doing the captcha.

Shu Jie:

    OTP Email:
        Step 1: The user begins by signing in to their account.
        Step 2: On the choice page, the user selects the email OTP option.
        Step 3: An OTP is sent to the user's registered email address. The user retrieves the OTP from their email
                and enters it into the application.
        Step 4: If the OTP is verified successfully, the user is logged in.

    Forgot Password:
        Step 1: The user clicks on the "forgot password" link located at the bottom left corner of the login page.
        Step 2: The user is prompted to enter their username and email.
        Step 3: An OTP is sent to the user's email for verification.
        Step 4: Upon successful verification of the OTP, the user is allowed to reset their password.
        Step 5: After resetting the password, the user is required to log in again.

    Admin authority access:
        Step 1: Log in as the superAdmin with the credentials (account: "root", password: "Root@123").
        Step 2: Choose an OTP medium (e.g., email) to complete the login. (Note: The email must be updated in the
                database to match your own to receive the OTP for the "root" account.)
        Step 3: After a successful login, navigate to the Super Admin section to view the user list.
        Step 4: By default, all accounts are set as "user." You can update an account to "admin" by selecting the
                desired admin authority from a dropdown list and clicking "update."
        Step 5: Log out of the root account, then log in with the account you just elevated to Sub Admin.
        Step 6: After logging in, the account will now have the admin authorities you assigned.
        *** The URL link will not be working if you logout the account *** (It will show Invalid token!)

    Password expired reminder:
        Step 1: When an account is created, password_create_date, password_expiry_days, and password_expiry are automatically inserted into the database.
        Step 2: To simulate password expiration, manually update the password_expiry field in the accounts table to a date within 24 hours or a past date.
        Step 3: Restart the Python project, and the user will receive a password expiry reminder email with a link to reset their password.
        Step 4: The user clicks on the provided link (valid for 1 hour) and resets their password, after which they are redirected to the login page.
        Step 5: If the user attempts to log in with an expired password, they will be forced to reset it using an email OTP.

Jun Quan:

    Face Recognition:
        1. Login to any account
        2. Go to profile
        3. Add a photo of your face
        4. logout
        5. Make sure that Sherman's HTTPS application is not running
        6. In the login Page, press the Face button
        
    Input Validation:
        Sanitising: Remove any none related characters
        Validation:
            Password: min 1 uppercase letter, 1 lowercase letter, 1 number, 1 special character. min 8 characters, max 20 characters
            OTP: only numbers and 6 digits
            Email: Must have @ and .com
            Phone Number: Must have +65 and 8 digits
        Encoding: Encode all special characters
        Testing:
            Type anything you want in any text field
            
    Logging & Monitoring:
        1. Login through any account
        2. Go to logs
        3. Login to root account
        4. Go to admin level <level>
        5. Click on the view
        6. The individual logs for the user will show.
