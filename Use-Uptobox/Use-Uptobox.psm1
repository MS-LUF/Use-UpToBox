
Function Get-UptoboxFileAsync {
    <#
	  .SYNOPSIS 
	  main function used to download a file from UpToBox online file hosting service using multi threading and asynchronous capabilities
  
	  .DESCRIPTION
      main function used to download a file from UpToBox online file hosting service using multi threading and asynchronous capabilities
      this function requires the Microsoft PowerShell Module 'threadjob'
      To use this function you must have an account and a valid API key
	  	  
	  .PARAMETER filecode
	  -filecode string
      use an uptobox filecode to target a file to download
      
      .PARAMETER url
      -url string
      use an uptobox file url to download a file

      .PARAMETER outputfolder
      -outputfolder string
      path to a target folder where the file will be downloaded. if no target folder is set, a default value is used ($home\downloads)

      .PARAMETER APIKEY
	  -APIKey string{APIKEY}
	   Set APIKEY as global variable.
			  
	  .OUTPUTS
		 TypeName: PSuptobox
  
	  .EXAMPLE
	  Get-UptoboxFileAsync -url https://uptobox.com/xxxxx11yyyy2 
      start a multi thread / asynchronous download for filecode xxxxx11yyyy2 and download it in default folder
      
      .EXAMPLE
	  Get-UptoboxFileAsync -filecode xxxxx11yyyy2 -outputfolder c:\MyFolder 
	  start a multi thread / asynchronous download for filecode xxxxx11yyyy2 and download it in c:\MyFolder
    #>
    [cmdletbinding()]
	Param ( 
        [parameter(Mandatory=$false)]
            [URI]$url,
        [parameter(Mandatory=$false)]
        [ValidateLength(12,12)]
            [string]$filecode,
        [parameter(Mandatory=$false)]
        [ValidateScript({(test-path $_)})]
            [string]$outputfolder
    )
    process {
        if ($Host.Version.Major -lt 6) {
            throw "please use PowerShell in last version to use the multithreading feature"
        }
        if (!(Get-Module -Name threadjob)) {
            try {
                import-module -Name threadjob -Force
            } catch {
                throw "please install PowerShell module threadjob first - 'Install-Module -Name threadjob'"
            }
        }
        if (!($global:uptoboxAPIKey)) {
            throw "please set an api key using 'Set-UptoboxAPIKey'"
        }
        $inputobject = [pscustomobject]@{
            APIKey = $global:uptoboxAPIKey.clone()
            url = $PSBoundParameters["url"]
            filecode = $PSBoundParameters["filecode"]
            outputfolder = $PSBoundParameters["outputfolder"]
            proxyparams = if ($global:uptoboxProxyParams) {$global:uptoboxProxyParams.clone()}
        }
        $actionblock = {
            $settings = $input | ConvertTo-Json | ConvertFrom-Json
            Set-UptoboxAPIKey -APIKey $settings.APIKey
            if ($settings.proxyparams) {
                $global:uptoboxProxyParams = $settings.proxyparams
            }
            if ($settings.url) {
                if ($settings.outputfolder) {
                    Get-UptoboxFile -url $settings.url -outputfolder $settings.outputfolder
                } else {
                    Get-UptoboxFile -url $settings.url
                }
            } elseif ($settings.filecode) {
                if ($settings.outputfolder) {
                    Get-UptoboxFile -filecode $settings.filecode -outputfolder $settings.outputfolder
                } else {
                    Get-UptoboxFile -filecode $settings.filecode
                }
            }
        }
        $intializationblock = {
            Import-Module Use-Uptobox
            import-module Microsoft.PowerShell.Management
            import-module Microsoft.PowerShell.Utility
        }
        Start-ThreadJob -ScriptBlock $actionblock -InputObject $inputobject -StreamingHost $Host -InitializationScript $intializationblock -Name "UptoBox $(new-guid)"
    }
}
Function Get-UptoboxFile {
    <#
	  .SYNOPSIS 
	  main function used to download a file from UpToBox online file hosting service.
  
	  .DESCRIPTION
	  main function used to download a file from UpToBox online file hosting service. To use this function you must have an account and a valid API key
	  	  
	  .PARAMETER filecode
	  -filecode string
      use an uptobox filecode to target a file to download
      
      .PARAMETER url
      -url string
      use an uptobox file url to download a file

      .PARAMETER outputfolder
      -outputfolder string
      path to a target folder where the file will be downloaded. if no target folder is set, a default value is used ($home\downloads)

      .PARAMETER APIKEY
	  -APIKey string{APIKEY}
	   Set APIKEY as global variable.
			  
	  .OUTPUTS
		 TypeName: PSuptobox
  
	  .EXAMPLE
	  Get-UptoboxFile -url https://uptobox.com/xxxxx11yyyy2 
      start a single thread / synchronous download for filecode xxxxx11yyyy2 and download it in default folder
      
      .EXAMPLE
	  Get-UptoboxFile -filecode xxxxx11yyyy2 -outputfolder c:\MyFolder 
	  start a single thread / synchronous download for filecode xxxxx11yyyy2 and download it in c:\MyFolder
    #>
    [cmdletbinding()]
	Param ( 
        [parameter(Mandatory=$false)]
            [URI]$url,
        [parameter(Mandatory=$false)]
        [ValidateLength(12,12)]
            [string]$filecode,
        [parameter(Mandatory=$false)]
        [ValidateScript({(test-path $_)})]
            [string]$outputfolder,
        [parameter(Mandatory=$false)]
        [ValidateLength(37,37)]
            [string]$APIKey
    )
    process {
        if ($APIKey) {Set-uptoboxAPIKey -APIKey $APIKey | out-null}
        if (!($outputfolder)) {
            if (!$home) {
                $global:home = $env:userprofile
            }
            $outputfolder = join-path $home "Downloads"
            if (!(test-path $outputfolder)) {
                new-item -Path $outputfolder -ItemType Directory -Force | Out-Null
            }
        }
        if ($url) {
            $filecode = $url.AbsolutePath.Substring(1,$url.AbsolutePath.Length-1)
        }
        $fileinfo = Invoke-APIuptoboxLinkInfo -filecodes $filecode
        if ($fileinfo.list.'file_name') {
            $filename = $fileinfo.list.'file_name'
            write-verbose "Filename is : $($filename)"
            $fullfilename = join-path $outputfolder $filename
            write-verbose "Output file generated : $($fullfilename)"
            $downloadlink = Invoke-APIuptoboxLink -filecode $filecode
            write-verbose "Download link generated : $($downloadlink.dlLink)"
            try {
                $tmpfile = join-path $outputfolder "$((new-guid).guid).tmp"
                Invoke-WebRequest -uri $downloadlink.dlLink -OutFile $tmpfile -UseBasicParsing | Out-Null
            } catch {
                write-verbose -message "Error when downloading filecode $($filecode) - file $($filename)"
                write-verbose -message "Error Type: $($_.Exception.GetType().FullName)"
                write-verbose -message "Error Message: $($_.Exception.Message)"
                write-verbose -message "HTTP error code:$($_.Exception.Response.StatusCode.Value__)"
                write-verbose -message "HTTP error message:$($_.Exception.Response.StatusDescription)"
                write-error "Error when downloading filecode $($filecode) - file $($filename)"
            }
            if (test-path $fullfilename) {
                write-error "Not able to save temporary file $($tmpfile) to $($filename). The file was alredy existing"
            } else {
                rename-item -Path $tmpfile -NewName $fileinfo.list.'file_name'
            }
        } else {
            write-error "Filecode $($filecode) not existing or with file status in error"
        }
    }
}
Function Invoke-APIuptoboxLink {
 	<#
	  .SYNOPSIS 
	  create several input for Invoke-uptoboxAPIV2 function and then call it to get the user account info from link API
  
	  .DESCRIPTION
	  create several input for Invoke-uptoboxAPIV2 function and then call it to get the user account info from link API
	  	  
	  .PARAMETER APIKEY
	  -APIKey string{APIKEY}
		Set APIKEY as global variable.
			  
	  .OUTPUTS
		 TypeName: PSuptobox
    #>
    [cmdletbinding()]
	Param ( 
		[parameter(Mandatory=$false)]
		[ValidateLength(37,37)]
            [string]$APIKey,
        [parameter(Mandatory=$true)]
        [ValidateLength(12,12)]
            [string]$filecode
	)  
	  Process {
		if ($APIKey) {Set-uptoboxAPIKey -APIKey $APIKey | out-null}
			$params = @{
                api = "link"
                apiparam = "file_code=$($filecode)"
			}
			Write-Verbose -message "URL Info : $($params.api)"  
			Invoke-uptoboxAPIV2 @params
		}
}
Function Invoke-APIuptoboxLinkInfo {
    <#
     .SYNOPSIS 
     create several input for Invoke-uptoboxAPIV2 function and then call it to get the user account info from link info API
 
     .DESCRIPTION
     create several input for Invoke-uptoboxAPIV2 function and then call it to get the user account info from link info API
           
     .PARAMETER APIKEY
     -APIKey string{APIKEY}
       Set APIKEY as global variable.
             
     .OUTPUTS
        TypeName: PSuptobox
   #>
   [cmdletbinding()]
   Param ( 
       [parameter(Mandatory=$false)]
       [ValidateLength(37,37)]
           [string]$APIKey,
       [parameter(Mandatory=$true)]
       [ValidateLength(12,12)]
           [string[]]$filecodes
   )  
     Process {
       if ($APIKey) {Set-uptoboxAPIKey -APIKey $APIKey | out-null}
        if ($filecodes.count -gt 1) {
            $filecodes = $filecodes -join ","
        }
           $params = @{
               api = "link/info"
               apiparam = "fileCodes=$($filecodes)"
           }
           Write-Verbose -message "URL Info : $($params.api)"  
           Invoke-uptoboxAPIV2 @params
       }
}
Function Invoke-APIuptoboxUser {
	<#
	  .SYNOPSIS 
	  create several input for Invoke-uptoboxAPIV2 function and then call it to get the user account info from user API
  
	  .DESCRIPTION
	  create several input for Invoke-uptoboxAPIV2 function and then call it to get the user account info from user API
	  	  
	  .PARAMETER APIKEY
	  -APIKey string{APIKEY}
		Set APIKEY as global variable.
			  
	  .OUTPUTS
		 TypeName: PSuptobox
  
	  .EXAMPLE
      Invoke-APIuptoboxUser -APIKey "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      get user account info for api key xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx and set the api key

	  .EXAMPLE
      Invoke-APIuptoboxUser
      get your user account info
	#>
	[cmdletbinding()]
	Param ( 
		[parameter(Mandatory=$false)]
		[ValidateLength(37,37)]
			[string]$APIKey
	)  
	  Process {
		if ($APIKey) {Set-uptoboxAPIKey -APIKey $APIKey | out-null}
			$params = @{
				api = "user/me"
			}
			Write-Verbose -message "URL Info : $($params.api)"  
			Invoke-uptoboxAPIV2 @params
		}
}
Function Set-UptoboxAPIKey {
    <#
          .SYNOPSIS 
          set and remove uptobox API key as global variable uptoboxAPIKey
  
          .DESCRIPTION
          set and remove uptobox API key as global variable uptoboxAPIKey
          
          .PARAMETER APIKEY
          -APIKey string{APIKEY}
          Set APIKEY as global variable.
  
          .PARAMETER MasterPassword
          -MasterPassword SecureString{Password}
          Use a passphrase for encryption purpose.
  
          .PARAMETER EncryptKeyInLocalFile
          -EncryptKeyInLocalFile
          Store APIKey in encrypted value on local drive
          
          .PARAMETER Remove
          -Remove
          Remove your current APIKEY from global variable.
          
          .OUTPUTS
          none
          
          .EXAMPLE
          Set-uptoboxAPIKey -apikey "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
          Set your API key as global variable so it will be used automatically by all use-uptobox functions
          
          .EXAMPLE
          Set-uptoboxAPIKey -remove
          Remove your API key set as global variable
  
          .EXAMPLE
          Set-uptoboxAPIKey -apikey "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" -MasterPassword (ConvertTo-SecureString -String "YourP@ssw0rd" -AsPlainText -Force) -EncryptKeyInLocalFile
          Store your API key on hard drive
    #>
    [cmdletbinding()]
    Param (
          [parameter(Mandatory=$false)]
          [ValidateLength(37,37)]
              [string]$APIKey,
          [parameter(Mandatory=$false)]
              [switch]$Remove,
          [parameter(Mandatory=$false)]
              [switch]$EncryptKeyInLocalFile,
          [parameter(Mandatory=$false)]
              [securestring]$MasterPassword
    )
    process {
      if ($Remove.IsPresent) {
          $global:uptoboxAPIKey = $Null
        } Else {
          $global:uptoboxAPIKey = $APIKey
          If ($EncryptKeyInLocalFile.IsPresent) {
              If (!$MasterPassword -or !$APIKey) {
                  Write-warning "Please provide a valid Master Password to protect the API Key storage on disk and a valid API Key"
                  throw 'no api key or master password'
              } Else {
                  [Security.SecureString]$SecureKeyString = ConvertTo-SecureString -String $APIKey -AsPlainText -Force
                  $SaltBytes = New-Object byte[] 32
                  $RNG = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
                  $RNG.GetBytes($SaltBytes)
                  $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList 'user', $MasterPassword
                  $Rfc2898Deriver = New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $Credentials.GetNetworkCredential().Password, $SaltBytes
                  $KeyBytes  = $Rfc2898Deriver.GetBytes(32)
                  $EncryptedString = $SecureKeyString | ConvertFrom-SecureString -key $KeyBytes
                  $ObjConfiguptobox = @{
                      Salt = $SaltBytes
                      EncryptedAPIKey = $EncryptedString
                  }
                  $FolderName = 'Use-Uptobox'
                  $ConfigName = 'Use-Uptobox-Config.xml'
                  if (!$home) {
                      $global:home = $env:userprofile
                  }
                  if (!(Test-Path -Path "$($home)\$FolderName")) {
                      New-Item -ItemType directory -Path "$($home)\$FolderName" | Out-Null
                  }
                  if (test-path "$($home)\$FolderName\$ConfigName") {
                      Remove-item -Path "$($home)\$FolderName\$ConfigName" -Force | out-null
                  }
                  $ObjConfiguptobox | Export-Clixml "$($home)\$FolderName\$ConfigName"
              }	
          }
        }
    }
}
Function Set-uptoboxProxy {
	<#
	  .SYNOPSIS 
	  Set an internet proxy to use uptobox web api
  
	  .DESCRIPTION
	  Set an internet proxy to use uptobox web api

	  .PARAMETER DirectNoProxy
	  -DirectNoProxy
	  Remove proxy and configure uptobox powershell functions to use a direct connection
	
	  .PARAMETER Proxy
	  -Proxy{Proxy}
	  Set the proxy URL

	  .PARAMETER ProxyCredential
	  -ProxyCredential{ProxyCredential}
	  Set the proxy credential to be authenticated with the internet proxy set

	  .PARAMETER ProxyUseDefaultCredentials
	  -ProxyUseDefaultCredentials
	  Use current security context to be authenticated with the internet proxy set

	  .PARAMETER AnonymousProxy
	  -AnonymousProxy
	  No authentication (open proxy) with the internet proxy set

	  .OUTPUTS
	  none
	  
      .EXAMPLE
      Set-uptoboxProxy -DirectNoProxy
	  Remove Internet Proxy and set a direct connection

	  .EXAMPLE
      Set-uptoboxProxy -Proxy "http://myproxy:8080" -ProxyCredential (get-credential)
      Set Internet Proxy and with manual authentication

	  .EXAMPLE
      Set-uptoboxProxy -Proxy "http://myproxy:8080" -ProxyUseDefaultCredentials
      Set Internet Proxy and with automatic authentication based on current security context

	  .EXAMPLE
      Set-uptoboxProxy -Proxy "http://myproxy:8080" -AnonymousProxy
      Set Internet Proxy and with no authentication
	#>
	[cmdletbinding()]
	Param (
	  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$false)]
		  [switch]$DirectNoProxy,
	  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
	    [string]$Proxy,
	  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$false)]
	    [Management.Automation.PSCredential]$ProxyCredential,
	  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$false)]
		  [Switch]$ProxyUseDefaultCredentials,
	  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$false)]
		  [Switch]$AnonymousProxy
	)
	if ($DirectNoProxy.IsPresent){
		$global:uptoboxProxyParams = $null
	} ElseIf ($Proxy) {
		$global:uptoboxProxyParams = @{}
		$uptoboxProxyParams.Add('Proxy', $Proxy)
		if ($ProxyCredential){
			$uptoboxProxyParams.Add('ProxyCredential', $ProxyCredential)
			If ($uptoboxProxyParams.ProxyUseDefaultCredentials) {$uptoboxProxyParams.Remove('ProxyUseDefaultCredentials')}
		} Elseif ($ProxyUseDefaultCredentials.IsPresent){
			$uptoboxProxyParams.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
			If ($uptoboxProxyParams.ProxyCredential) {$uptoboxProxyParams.Remove('ProxyCredential')}
		} ElseIf ($AnonymousProxy.IsPresent) {
			If ($uptoboxProxyParams.ProxyUseDefaultCredentials) {$uptoboxProxyParams.Remove('ProxyUseDefaultCredentials')}
			If ($uptoboxProxyParams.ProxyCredential) {$uptoboxProxyParams.Remove('ProxyCredential')}
		}
	}
}
Function Import-uptoboxEncryptedIKey {
    <#
          .SYNOPSIS 
          import uptobox API key as global variable from encrypted local config file
  
          .DESCRIPTION
          import uptobox API key as global variable from encrypted local config file
          
          .PARAMETER MasterPassword
          -MasterPassword SecureString{Password}
          Use a passphrase for encryption purpose.
          
          .OUTPUTS
          none
          
          .EXAMPLE
          Import-uptoboxEncryptedIKey -MasterPassword (ConvertTo-SecureString -String "YourP@ssw0rd" -AsPlainText -Force)
          set API Key as global variable using encrypted key hosted in local xml file previously generated with Set-uptoboxAPIKey
    #>
      [CmdletBinding()]
      Param(
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
          [securestring]$MasterPassword
      )
      process {
          $FolderName = 'Use-uptobox'
          $ConfigName = 'Use-uptobox-Config.xml'
          if (!$home) {
              $global:home = $env:userprofile
          }
          if (!(Test-Path "$($home)\$($FolderName)\$($ConfigName)")){
              throw 'Configuration file has not been set, Set-uptoboxAPIKey to configure the API Keys.'
          }
          $ObjConfiguptobox = Import-Clixml "$($home)\$($FolderName)\$($ConfigName)"
          $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList 'user', $MasterPassword
          try {
              $Rfc2898Deriver = New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $Credentials.GetNetworkCredential().Password, $ObjConfiguptobox.Salt
              $KeyBytes  = $Rfc2898Deriver.GetBytes(32)
              $SecString = ConvertTo-SecureString -Key $KeyBytes $ObjConfiguptobox.EncryptedAPIKey
              $SecureStringToBSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecString)
              $APIKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto($SecureStringToBSTR)
              $global:uptoboxAPIKey = $APIKey
          } catch {
              throw "Not able to set correctly your API Key, your passphrase my be incorrect"
              write-error -message "Error Type: $($_.Exception.GetType().FullName)"
              write-error -message "Error Message: $($_.Exception.Message)"
          }
      }
}
Function Invoke-uptoboxAPIV2 {
	[cmdletbinding()]
	Param (
		  [parameter(Mandatory=$true)]
		  [ValidateNotNullOrEmpty()]  
              [string]$api,
          [parameter(Mandatory=$false)]
          [ValidateNotNullOrEmpty()]  
              [string]$apiparam,
		  [parameter(Mandatory=$false)]
		  [Validateset("GET","PATCH")]
			  [string]$Method = "GET",
		  [parameter(Mandatory=$false)]
			  [switch]$Stream
	)
	Process {
    $script:uptoboxurl = "https://uptobox.com/api/"
    write-verbose -message "using production uptobox service - https://uptobox.com/"
	  if ((!$global:uptoboxAPIKey)) {
		  write-verbose -message "please set an api key using 'Set-UptoboxAPIKey'"
		  throw "please set an api key using 'Set-UptoboxAPIKey'"
	  }
	  try {
          $fulluptoboxurl = "$($uptoboxurl)$($api)?token=$($global:uptoboxAPIKey)"
          if ($apiparam) {
            $fulluptoboxurl = "$($fulluptoboxurl)&$($apiparam)"
          }
		  if ($global:uptoboxProxyParams) {
			  $params = $global:uptoboxProxyParams.clone()
			  If (!$params.UseBasicParsing){
				  $params.add('UseBasicParsing', $true)
			  }
			  If (!$params.URI) {
				  $params.add('URI', "$($fulluptoboxurl)")
			  } Else {
				  $params['URI'] = "$($fulluptoboxurl)"
			  }
		  } Else {
			  $params = @{}
			  $params.add('UseBasicParsing', $true)
			  $params.add('URI', "$($fulluptoboxurl)")
		  }
		  if (($Method -eq "PATCH") -and !$params.Method) {
			  $params.add('Method','PATCH') 
		  }
		  $uptoboxresult = invoke-webrequest @params
	  } catch {
			  write-verbose -message "Not able to use uptobox online service - KO"
			  write-verbose -message "Error Type: $($_.Exception.GetType().FullName)"
			  write-verbose -message "Error Message: $($_.Exception.Message)"
			  write-verbose -message "HTTP error code:$($_.Exception.Response.StatusCode.Value__)"
              write-verbose -message "HTTP error message:$($_.Exception.Response.StatusDescription)"
              throw "error with uptobox online service"
	  }
		write-verbose -message "Response Headers : $($uptoboxresult.Headers | out-string)"  
		write-verbose -message "Web Content : $($uptoboxresult.Content)"
		$temp = $uptoboxresult.Content
        if ($temp) {
			if ($stream) {
				$temp
			} else {
				$tempobj = $temp | Convertfrom-Json
				$tempobj.PSObject.TypeNames.Insert(0,"PSuptobox")
                if ($tempobj.data) {
                    $tempobj.data
                } else {
                    $tempobj
                }
			}
		}
	  }
}

New-Alias -name Get-UptoboxUserInfo -Value Invoke-APIuptoboxUser

Export-ModuleMember -Function  Invoke-uptoboxAPIV2, Import-uptoboxEncryptedIKey, Set-uptoboxProxy, Set-UptoboxAPIKey, Invoke-APIuptoboxUser, Invoke-APIuptoboxLink, Invoke-APIuptoboxLinkInfo, 
                                Get-UptoboxFile, Get-UptoboxFileAsync
Export-ModuleMember -Alias Get-UptoboxUserInfo
