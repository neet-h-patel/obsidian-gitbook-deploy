# ***Scanning***

## *UDP scan*
## *Add Domains/Hosts to /etc/hosts asap!*

## *Google everything unknown (source code/git etc)*




# ***Services***
## ***CVE/RCE search in Google***

## ***USE BURP for  anything HTTP (File Disclosure/LFI/SQLi on parameters etc )***
## *Try user:user for password*

## *Recursively do subdir enum using ffuf*
## *ftp -A for active session always*

## *nmap scan services i.e can discover things like .git*

## *Re-Enumerate services when you find creds i.e ftp, smb, ldap etc* 

## *Try ssh login w/ found creds*

## ***Enum databases w/ found creds to find more creds***
## ***Can change password etc in database if privileged***


# ***Windows***

## *IIS web form, can try RELAY w/ UNC (can get service cred)*

## *IIS runs as Local Service, Network Service or ApplicationPoolIdentity which often have SeImpersonate*

## *If not Sweet try Sigma (or others even)*

## *CHECK for service logs, .bak, .old*

## *CHECK Downloads, Documents, Desktop*

## *DOUBLE REVERSE shell* 

## *Mimi oneliner*

## *RE-ENUMERATE w/ Found Creds i.e Bloodhound*

## *Always DO C:\Users C:\Tasks (C:\Windows maybe) for manual enum*

## *Re-Enumerate the Administrator folder or when previously not held permission*


# ***AD***
## ***nmap MS02 and DC01!***

## ***IP == NTLM auth so be mindful of not just using IP (add to domain to /etc/hosts)***

## ***nxc spray creds to check for acccess***


# ***Bruteforce***

## *Try default credentials prior to brute-force*
## *Try brute-force with default names like admin*
## *Try username/username combos*

## *Try hashcat, john, and crackstation*