# SQL Injection - User Data

A SQL injection attack consists of insertion of a SQL query via the input data from the client to the application. By interfering with the requests that an application makes to it's database.

## Breach type

* A03:2021 Injection 
    * CWE-89: SQL Injection (In-band SQLi):
        * Error-based SQLi: exploit error messages thrown by the database server to obtain information about the structure of the database.
        * Union-based SQLi: exploit the UNION SQL operator to combine the result of two or more SELECT statements into a single result.
* A01:2021 Broken Access Control
    * CWE-200: Exposure of Sensitive Information to an Unauthorized Actor.

## How to find the flag

* Go to the `Members` page
* Do a regular text query and understand that it returns SQL MariaDB errors

Enter the following commands:

* `105 OR 1=1`
    * By injecting `105 OR 1=1` into a vulnerable SQL query, the attacker attempts to manipulate the logic of the query to always return true (1=1). 
    * This can bypass authentication or access control mechanisms if the application does not properly sanitize input. 
    * In this context the command displays the member list. The fourth one has the fields : `id (105 OR 1=1)`, `first name (Flag)`, `surname (GetThe)`.
    * We now need to find where these informations are stored in the database.

* `105 OR 1=1 UNION SELECT table_name, table_schema FROM information_schema.tables `
    * With this command we display all the schemas and their tables and discover that there's a table called 'users'.
    * This table is probably the best place to find the flag. 

* `105 OR 1=1 UNION SELECT table_name, column_name FROM information_schema.columns`
    * The intention behind this SQL line is to retrieve the names of tables and their respective columns from the information_schema.columns table.
    * We now have a list of all the columns of the 'users' table

* `105 OR 1=1 UNION SELECT countersign, 1 FROM users`
    * In the countersign field corresponding to the "GetThe Flag" user we find a hashed code in MD5 : 5ff9d0165b4f92b14994e5c685cdce28. 
    * When we decode it we find "FortyTwo".
    * We can't do anything with it yet.

* `105 OR 1=1 UNION SELECT Commentaire, 1 FROM users`
    * In the Commentaire field we find an explanation of how to retrieve the flag : decode `5ff9d0165b4f92b14994e5c685cdce28`, put the result in lowercase, encrypt it in SHA-256 and you'll get your flag. 

## Risks

* Sensitive informations data breaches such as logins, passwords, bank informations, etc.
* Then Attackers can impersonate users or impersonate database administrator and obtain all database privileges.
* They can alter data in database and add new database for example in a financial app : alter balance, transaction, transfer money.
* They can delete records from database, even if the admin makes database backups, this could affect application availability until the database is restored. 
* Attackers can also inject informations to bypass authentication pages to read and write files directly into the server such as backdoors, viruses.
* In some database servers we can access to the operating system from database server.

## How to avoid

* Use Parameterized Queries:
    * Don't trust any user input. Utilize prepared statements or parameterized queries with placeholders for user input. 
    This ensures that input values are not directly concatenated into the SQL query string and avoid SQL injection.
    * All input must be sanitize, to remove potential malicious code element such as special characters like single quotes. They're used in SQLi attacks.
    * Most languages and frameworks offer methods to escape special characters.

* Turn off the visibility of database errors on your production sites, they can be used to gain information about your database.

* Use `LIMIT` eveywhere in the Database to limit the data display in case of attack

* Use SQLi detection tools each time app is updated. If the vulnerability cannot be fixed immediately, using a firewall allows you to patch while the vulnerability is fixed.

## Sources
* [OWASP A03:2021](https://owasp.org/Top10/fr/A03_2021-Injection/)
* [SQL Injection impact and good practice](https://www.vaadata.com/blog/fr/injections-sql-principes-impacts-exploitations-bonnes-pratiques-securite/)
* [SQL Injection table name](https://www.sqlinjection.net/table-names/)
* [SQL Injection column name](https://www.sqlinjection.net/column-names/)
* [SQL Injection def](https://www.acunetix.com/websitesecurity/sql-injection/)
* [SQL Injection source](https://www.invicti.com/learn/in-band-sql-injection/)