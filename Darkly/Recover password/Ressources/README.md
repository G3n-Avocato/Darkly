# Hidden field

## Breach type:
* A05:2021 Security Misconfiguration 
    * CWE-16 Configuration (the feature doesn't work properly: page=recover for recover password.)
A01:2021 Broken Access Control
    * CWE-200 Exposure of Sensitive Information to an Unauthorized Actor.

(A07:2021 Identification and Authentication Failures
    CWE-640 Weak Password Recovery Mechanism for Forgotten Password.)

## How to find the flag:
* Go to the sign in page
* Click on `forgot password` link
* Inspect the page and discover a hidden field : `<input type="hidden" name="mail" value="webmaster@borntosec.com" maxlength="15">`
* Edit the html to display the field containing the webmaster email
* Send the password recovery demand to the email of your choice

## Risks:
* Permitting viewing or editing someone else's account, by providing its unique identifier.

## How to avoid:
* Remove or do not install unused features and frameworks.
* Use a better security architecture


Sources:
* https://owasp.org/Top10/fr/A03_2021-Injection/
* https://www.vaadata.com/blog/fr/injections-sql-principes-impacts-exploitations-bonnes-pratiques-securite/
* https://www.sqlinjection.net/table-names/
* https://www.sqlinjection.net/column-names/