# ***nmap***
```shell
sudo nmap -sCV -p3306 --script "mysql-*" `tip` -oN nmap_mysql_MACHINE
```
# ***Attempt Login***
***Port forward if service only accessible from localhost***
***root:***
```shell
mysql -h `tip` -u root
mysql -h `tip` -u root -p'pass'
mysql -h `tip` -u 'user '-p'pass'
```

```shell
# Port Forward from Kali
ssh -N -L 127.0.0.1:3306:127.0.0.1:PORT user@`tip`
mysql -h 127.0.0.1 -u root
mysql -h 127.0.0.1 -u 'user '-p'pass'
```
# ***interact***
```shell
# Version
select version(); #version
select @@version(); #version

# DBs
show databases;
use <database>;
connect <database>;
select database(); #database name

# Tables
show tables;
describe <table_name>;
show columns from <table>;

# User
select user();
select system_user();
SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec'; # show encrypted  password for user

# Get a shell with the mysql client user
\! sh


#https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql
```

# *Default pass*
```
root:
```