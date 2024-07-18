# Upload - Improper file type handling

The product allows the upload or transfer of dangerous file types that are automatically processed within its environment.

## Breach type

* A04:2021 - Insecure Design
    * CWE-434: Unrestricted Upload of File with Dangerous Type
    * CWE-351: Insufficient Type Distinction

* OWASP Top 10 2017: A5 - Security Misconfiguration (Unvalidated Redirects and Forwards).
* OWASP Top 10 2021: A8 - Security of APIs and Services (Injection).

## How to find the flag

* Go to the image upload page : `http://192.168.56.101/index.php?page=upload`

The goal is to upload a malicious .php script via the image upload form.

First method:
* Create a `coucou.php` file in your working directory.
* On Firefox, upload the script `coucou.php` in the form. You'll get an error prompt saying `Your image was not uploaded.`.
* Press `F12`, click on the Network tab, click on `Reload` to resend the file. 
* You'll see a `POST` request with the address `/?page=upload`, right click on it and select `edit and resend`
* In the body field, change the content type to `image/jpg` (instead of  `application/x-php`) then click on the `Send` at the bottom of the page
* Click on the `Response` tab, wait a few seconds and you'll get your flag !

Second method:

Now that we know that we just have to change the content type of the file to bypass the form security, we'll try a more scalable method using the terminal and Curl. Enter this command in your terminal: `curl 'http://192.168.56.101/index.php?page=upload#' -X POST -F "uploaded=@./coucou.php;type=image/jpeg" -F "Upload=Upload" | grep flag`

* `curl 'http://192.168.56.101/index.php?page=upload#'` -> This initiates a cURL command to send an HTTP POST request to the specified URL.
* `-F "uploaded=@./coucou.php;type=image/jpeg"` This specifies the file to be uploaded and falsely sets its MIME type to `image/jpeg`, indicating it is an image.
* `-F "Upload=Upload" | grep flag` This adds a form field named Upload with a value of Upload accordingly to the form present on the website to trigger the upload action and grep the flag in the http response

## Risks

* If the server accepts and processes the uploaded file `coucou.php` as an image `image/jpeg`, it enables an attacker to execute malicious code on the server.
* Remote Code Execution (RCE) allows attackers to run arbitrary commands on the server. They can steal sensitive data, modify files, or exploit other vulnerabilities to escalate privileges.

## How to avoid

* File format limitation: Limit allowed file types to only those necessary for the application.
* Strong protection: Do not rely only on the MIME type nor the file extension to validate the uploaded file, as it can be easily bypassed.
* Content Inspection: Thoroughly scan and validate the content of uploaded files, checking for malicious code or harmful content before making them accessible or processing them further.
* Execute Permission Control: Ensure that directories used for storing uploaded files do not have execute permissions, preventing any script execution from those directories.
* Sanitize Filenames: Remove all special, control, and Unicode characters from filenames and ensure filenames comply with strict regular expressions to prevent path traversal and injection attacks.

## Sources
* https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
* https://chocapikk.com/posts/2023/faille_upload/
* https://developer.mozilla.org/fr/docs/Web/HTTP/Basics_of_HTTP/MIME_types
* https://cwe.mitre.org/data/definitions/434.html