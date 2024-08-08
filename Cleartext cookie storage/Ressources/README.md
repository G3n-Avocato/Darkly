# Cleartext cookie storage

The product stores sensitive information in cleartext, or uses an algorithm that produces insufficient entropy, in a cookie. 

## Breach type

Cookies Storage:  
* A05_2021 Security Misconfiguration
    * CWE-315 : Cleartext Storage of Sensitive Information in a Cookie
    * CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag

Algorythm MD5:  
* A02:2021 – Cryptographic Failures
    * CWE-326: Inadequate Encryption Strength
    * CWE-331: Insufficient Entropy

## How to find the flag
* Open you browser and type `Inspect" -> "Applications`
* Go to the `Cookie` tab
* Copy-paste the value of the cookie and decode it with MD5 decryption (ex: https://dcode.fr)
* Discover that it is set to `false`
* Encode the string `true` in MD5 and modify the value of the cookie in the navigator to impersonate the admin

## Risks
* Data Exposure: Storing sensitive data in cookies can lead to data exposure if not encrypted, allowing attackers to read private information.
* Data Manipulation: Unsigned data in cookies can be modified by attackers, leading to potential security breaches.
* Cookie Theft: Attackers can steal cookies and use them to impersonate users, especially if cookies are used for authentication.
* Man-in-the-Middle Attacks: Without SSL, cookies can be intercepted and tampered with during transmission.

## How to avoid
* Encrypt Data: Encrypt the data before storing it in cookies to prevent attackers from reading the information.
* Sign Data: Sign the encrypted data to ensure it hasn't been modified, maintaining data integrity.
* Use SSL (HTTPS): Always use SSL to encrypt the data during transmission, preventing interception by attackers.
* Set Secure Flag: Set the HttpCookie. Secure property to true to ensure cookies are only sent over HTTPS connections.
* Include Expiration Time: Add an expiration time to the cookie to limit the duration it can be used, reducing the risk of misuse.
* Restrict Access: Use the HttpOnly flag to prevent client-side scripts from accessing the cookie, protecting against cross-site scripting (XSS) attacks.
* Authentication Best Practices: Do not rely solely on cookies for user authentication; combine them with secure sessions (2FA) and server-side checks (checking inputs without processing them).

## Sources
* [OWASP A05:2021](https://owasp.org/Top10/fr/A05_2021-Security_Misconfiguration/)
* [CWE-315](https://cwe.mitre.org/data/definitions/315.html)
* [Authenticate and Cookie Storage](https://stackoverflow.com/questions/3206622/is-putting-data-in-cookies-secure)
* [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html)