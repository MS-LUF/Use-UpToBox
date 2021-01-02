# Use-Uptobox - HOW TO

## version 1.0.0
- first document version

## install module
`Install-Module -Name Use-UptoBox`

## import module in your powershell environment
`Import-Module Use-UptoBox`
### when installed out of default PowerShell modules path
`Import-Module c:\mypath\Use-UptoBox\Use-UptoBox.psd1`

## Manage your UpToBox access
### set your API Key
`Set-UptoboxAPIKey -APIKey xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
- note : 
  - the api Key is loaded the global variables `$uptoboxAPIKey`
### set your api key and export it in an encrypted file
`Set-UptoboxAPIKey -APIKey xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -MasterPassword (ConvertTo-SecureString -String "YourP@ssw0rd" -AsPlainText -Force) -EncryptKeyInLocalFile`
- note :
  - the generated file is **$home/Use-Uptobox/Use-Uptobox-Config.xml**
### import your api key from an exported file
`Import-uptoboxEncryptedIKey -MasterPassword (ConvertTo-SecureString -String "YourP@ssw0rd" -AsPlainText -Force)`

## Get information about your UpToBox account
`Get-UptoboxUserInfo`

## download a file
### common options
- the following options work with both synchronous / asynchronous cmdlets
#### download using a file code
`Get-UptoboxFileAsync -filecode yyyyyyyyyyyy`
`Get-UptoboxFile -filecode yyyyyyyyyyyy`
#### download using an url
`Get-UptoboxFileAsync -url https://uptobox.com/yyyyyyyyyyyy`
`Get-UptoboxFile -url https://uptobox.com/yyyyyyyyyyyy`
#### set a custom output directory
`Get-UptoboxFileAsync -filecode yyyyyyyyyyyy -outputfolder "c:\myfolder"`
`Get-UptoboxFile -filecode yyyyyyyyyyyy -outputfolder "c:\myfolder"`
### synchronous download
`Get-UptoboxFile -url https://uptobox.com/yyyyyyyyyyyy`
### asynchronous download
`Get-UptoboxFileAsync -url https://uptobox.com/yyyyyyyyyyyy`
#### notes
- this cmdlet require **PowerShell host in version > 5.1**
- this cmdlet use the module **threadjob**
- you can run the cmdlet `Get-UptoboxFileAsync` multiple times and a PowerShell job (thread) will be created for each file. you can follow the download status using `get-job` cmdlet. All jobs created have a name starting with **UptoBox**
