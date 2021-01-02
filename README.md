![image](http://www.lucas-cueff.com/files/gallery.png)

# Use-UpToBox
a few cmdlets to download file hosted on uptobox.com file hosting service using uptobox API (uptobox account and API key is required)

(c) 2020 lucas-cueff.com Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).

## Note
- this module requires an uptobox account and an api key.
  - [uptobox registration form](https://uptobox.com/register)

## Notes version :
### 1.0.1 first public release
 - cmdlets to manage your API key (set, import) : *Set-UptoboxAPIKey*, *Import-uptoboxEncryptedIKey*
 - cmdlet to get information about your UpToBox account : *Get-UptoboxUserInfo*
 - cmdlet to dowload a file in a synchronous way (single thread, synchronous) : *Get-UptoboxFile*
 - cmdlet to dowload a file in a asynchronous way (multi threads, asynchronous) : *Get-UptoboxFileAsync*
   - this cmdlet require **PowerShell host in version > 5.1**
   - this cmdlet use the module **threadjob**
 - cmdlet to manage internet connection context (set your proxy) : *Set-uptoboxProxy*

## How To
[Simple How TO](https://github.com/MS-LUF/Use-UpToBox/blob/main/HOWTO.md)

## install Use-UpToBox from PowerShell Gallery repository
You can easily install it from [powershell gallery repository](https://www.powershellgallery.com/packages/Use-UpToBox/) using a simple powershell command and an internet access :-) 
```
	Install-Module -Name Use-UpToBox
```

## import module from PowerShell 
```
	C:\PS> import-module Use-UpToBox
```

## module content
### function
- Get-UptoboxUserInfo
- Get-UptoboxFile
- Get-UptoboxFileAsync
- Import-uptoboxEncryptedIKey
- Invoke-APIuptoboxLink
- Invoke-APIuptoboxLinkInfo
- Invoke-APIuptoboxUser
- Invoke-uptoboxAPIV2
- Set-UptoboxAPIKey
- Set-uptoboxProxy
### alias
- Get-UptoboxUserInfo
