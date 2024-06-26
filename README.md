# ELEC0138 Group L
# Online Learning Forum Project Overview

This project simulates an online learning forum and aims to analyze and defend against two major security threats: Brute Force Attacks and Cross-Site Request Forgery (CSRF). The project not only implements the basic functionalities of the forum but also incorporates corresponding security measures.

## Installation of Dependencies

Before running the project, please ensure that the necessary libraries are installed. Depending on your version of Python, you may need to install the following libraries:

```bash
pip install cryptography
```

If you are using Python version 3.6 or above, you will also need to install an additional dependency:
```bash
pip install idna
```

Other required libraries can be installed via the requirements file:
```bash
pip install -r requirements.txt
```
## Project Structure and Execution
The project contains two main application versions, located in the **`mainapp`** folder:

- **`app_w`**: This version has no defensive measures and is used to demonstrate the potential effects of attacks.
- **`app_s`**: This version includes security measures.

After running the respective application, access the webpage by following the address displayed in the terminal.

## Security Measures
### Multi-Factor Authentication (MFA)
This forum supports multi-factor authentication to enhance account security. After activating MFA, the login process is as follows:
1. **Enter your username and password.**
2. **Enter the verification code received in your email.**
3. **open a new web tab and visit the URL provided in the email.**
4. **On this page, enter your username and the random code from the email.**
5. **Decide whether to authorize the login.**
6. **If you agree, the login process will be completed.**

### CSRF Tokens
To prevent cross-site request forgery, the enhanced application app_s uses CSRF token protection.

## Note
Due to AWS requirements, keys and access keys cannot be uploaded to a public GitHub repository. Therefore, we have included these keys in ELEC0138Coursework_23104401 report. Replacing the content in the code's placeholders with the values from the report will enable the code to run successfully. The variables that need to be replaced are aws_access_key_id, aws_secret_access_key and app.config['MAIL_PASSWORD']. To ensure successful execution, please replace these variables in the code with the values from ELEC0138Coursework_23104401 report before running the code.

As the webpages use computer self-signed SSL/TLS certificates for HTTPS communication, the communication is encrypted, but browsers will warn that the certificate is not trusted because it is not issued by an authoritative CA.

## Feature overview
Users can normally browse and post(include reply) after creating an account. By clicking on the profile page, users can choose whether to activate MFA and change passoword.

The design of this project considers real security threats and enhances user safety on the forum through specific protective measures.

## Video Link
https://youtu.be/ngj7c_-N-Pg?si=zuZ-4qDZMw47Hhhf

## Brute attack
Link of the software:https://portswigger.net/burp/pro
The provided passwords.txt are just some weak passwords for demo purposes only, you can add more passwords in the future.
