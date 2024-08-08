# Weak Password Recovery

This vulnerability is related to password recovery mechanisms that are insecure or poorly implemented, allowing an attacker to access accounts without knowing the original password.

## Breach type

* A07:2021 Identification and Authentication Failures
    * CWE-640 Weak Password Recovery Mechanism for Forgotten Password.
* A05:2021 Security Misconfiguration 
    * CWE-16 Configuration (the feature doesn't work properly: `page=recover` for recover password)

## How to find the flag

* Go to the sign in page
* Click on `forgot password` link
* Inspect the page and discover a hidden field : `<input type="hidden" name="mail" value="webmaster@borntosec.com" maxlength="15">`
* Edit the html to display the field containing the webmaster email
* Send the password recovery demand to the email of your choice

## Risks

* Incorrect implementation permitting viewing or editing someone else's account, by providing its unique identifier.
* An attacker can enumerating which accounts exist, and increases the risk of targeted attacks
* Brute force attacks to access to the account
* Interception of communications, if the password reset link is sent via email or other unsecured means of communication, there is a risk that this email could be intercepted by an attacker, allowing them to access the account
* Phishing, attackers can exploit password reset mechanisms to send fraudulent emails containing fake reset links, aiming to trick users into disclosing their account information

## How to avoid

* Use good security practices for the password reset identifiers:
    * Use a side-channel to communicate the method to reset their password (ex: sms, other apps)
    * Use URL tokens like `Json Web Tokens`
    * Ensure that generated tokens or codes are:
        * Randomly generated using a cryptographically safe algorithm
        * Long enough to protect against brute-force attacks
        * Stored securely
        * Single use and expire after an appropriate time.
* To avoid attacker enumerating which accounts exist, return a consistent message for both existent and non-existent accounts.
* Remove or do not install unused features and frameworks.
* Ensure that the time taken for the user response message is uniform or fully randomized (to block script analyzing response time to deduce if a login was successful or not)

## Sources

* [CWE-640](https://cwe.mitre.org/data/definitions/640.html)
* [OWASP Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
