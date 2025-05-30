# ***nmap***
```shell
sudo nmap -v -Pn -n -sCV -p5432,5433 --script "pgsql-*" -oN nmap_postgress_MACHINE
```
# ***Login***
***postgres:postgres***
```shell
# Local
psql -U user
```

```shell
# Remote
psql -h `tip` -U 'user' -d database [ -p port ]
```

# ***interact***
```shell
# List databases / Use database
\list
\c <database>

# List tables / Get user roles
\d
\du+

# Get current user / current database
SELECT user;
SELECT current_catalog;

# List schemas / databases
SELECT schema_name,schema_owner FROM information_schema.schemata;
\dn+

#List databases
SELECT datname FROM pg_database;

#Read credentials (usernames + pwd hash)
SELECT usename, passwd from pg_shadow;

# Get languages
SELECT lanname,lanacl FROM pg_language;

# Show installed extensions
SHOW rds.extensions;
SELECT * FROM pg_extension;

# Get history of commands executed
\s
```

# Defau
# ***resources***
```
https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql
```