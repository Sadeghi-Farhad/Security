@echo off
title This is your first batch script!
echo Welcome to batch scripting!


echo 1.2 Ensure 'host headers' are on all sites (Scored)
%systemroot%\system32\inetsrv\appcmd list sites

echo 1.3 Ensure 'directory browsing' is set to disabled
%systemroot%\system32\inetsrv\appcmd set config /section:directoryBrowse /enabled:false

echo 1.4 Ensure 'application pool identity' is configured for all application pools
%systemroot%\system32\inetsrv\appcmd set config /section:applicationPools /[name='<your 
apppool>'].processModel.identityType:ApplicationPoolIdentity

echo 1.5 Ensure 'unique application pools' is set for sites
echo 	1. Open IIS Manager
echo 	2. Open the Sites node underneath the machine node
echo 	3. Select the Site to be changed
echo 	4. In the Actions pane, select Basic Settings
echo 	5. Click the Select… box next to the Application Pool text box
echo 	6. Select the desired Application Pool
echo 	7. Once selected, click OK


echo 1.6 Ensure 'application pool identity' is configured for anonymous user identity 
%systemroot%\system32\inetsrv\appcmd set config -section:anonymousAuthentication /username:"" --password

echo  (L1) Ensure' WebDav' feature is disabled
Uninstall-WindowsFeature Web-DAV-Publishing


echo 2.1 (L1) Ensure 'global authorization rule' is set to restrict access
%systemroot%\system32\inetsrv\appcmd list config -section:system.webserver/security/authorization

echo 2.2 (L1)Ensure access to sensitive site features is restricted to authenticated principals only
%systemroot%\system32\inetsrv\appcmd list config -section:system.web/authentication

echo 2.3 (L1) Ensure 'forms authentication' require SSL
%systemroot%\system32\inetsrv\appcmd list config -section:system.web/authentication

echo 2.4 (L2) Ensure 'forms authentication' is set to use cookies
%systemroot%\system32\inetsrv\appcmd list config -section:system.web/authentication

echo 2.5 (L1) Ensure 'cookie protection mode' is configured for forms authentication
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter 'system.web/authentication/forms' -name 'protection'

echo 2.6 (L1) Ensure transport layer security for 'basic authentication' is configured
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location '<website name>' -filter 'system.webServer/security/access' -name 'sslFlags'

echo 2.7 (L1) Ensure 'passwordFormat' is not set to clear
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter 'system.web/authentication/forms/credentials' -name 'passwordFormat'

echo 3.2 (L2) Ensure 'debug' is turned off
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter "system.web/compilation" -name "debug" | format-list Name, Value

echo 3.3 (L2) Ensure custom error messages are not off
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter "system.web/customErrors" -name "mode"

echo 3.4 (L1) Ensure IIS HTTP detailed errors are hidden from displaying remotely
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter "system.webServer/httpErrors" -name "errorMode"

echo 3.5 (L2) Ensure ASP.NET stack tracing is not enabled
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter "system.web/trace" -name "enabled" | Format-List Name,Value

echo 3.6 (L2) Ensure 'httpcookie' mode is configured for session state
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter "system.web/sessionState" -name "mode"

echo 3.7 (L1) Ensure 'cookies' are set with HttpOnly attribute
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter "system.web/httpCookies" -name "httpOnlyCookies"

echo 3.9 (L1) Ensure 'MachineKey validation method - .Net 4.5' is configured
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' -filter "system.web/machineKey" -name "validation"

echo 3.10 (L1) Ensure global .NET trust level is configured 
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' -filter "system.web/trust" -name "level"

echo 3.11 (L2) Ensure X-Powered-By Header is removed 
%systemroot%\system32\inetsrv\appcmd.exe list config -section:system.webServer/httpProtocol

echo 3.12 (L2) Ensure Server Header is removed 
Get-WebConfigurationProperty -pspath machine/webroot/apphost -filter 'system.webserver/security/requestfiltering' -name 'removeServerHeader'

echo 4.1 (L2) Ensure 'maxAllowedContentLength' is configured 
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength"

echo 4.2 (L2) Ensure 'maxURL request filter' is configured
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl"

echo 4.3 (L2) Ensure 'MaxQueryString request filter' is configured
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString"

echo 4.4 (L2) Ensure non-ASCII characters in URLs are not allowed
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name 'allowHighBitCharacters'

echo 4.5 (L1) Ensure Double-Encoded requests will be rejected
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping"

echo 4.6 (L1) Ensure 'HTTP Trace Method' is disabled (Manual)
%systemroot%\system32\inetsrv\appcmd listconfig /section:requestfiltering

echo 4.7 (L1) Ensure Unlisted File Extensions are not allowed
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/fileExtensions" -name "allowUnlisted"

echo 4.8 (L1) Ensure Handler is not granted Write and Script/Execute
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/handlers" -name "accessPolicy"

echo 4.9 (L1) Ensure 'notListedIsapisAllowed' is set to false
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/isapiCgiRestriction" -name "notListedIsapisAllowed"

echo 4.10 (L1) Ensure 'notListedCgisAllowed' is set to false
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/isapiCgiRestriction" -name "notListedCgisAllowed"

echo 5.1 (L1) Ensure Default IIS web log location is moved
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/logFile" -name "directory"

echo 5.2 (L1) Ensure Advanced IIS logging is enabled (Automated)


echo 7.2 (L1) Ensure SSLv2 is Disabled (Automated)
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'Enabled'
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'Enabled'
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault'
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'DisabledByDefault'

echo 7.3 (L1) Ensure SSLv3 is Disabled (Automated)
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'Enabled'
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'Enabled'
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'DisabledByDefault'
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'DisabledByDefault'

echo 7.4 (L1) Ensure TLS 1.0 is Disabled (Automated)
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled'
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'Enabled'
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault'
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'DisabledByDefault'

echo 7.5 (L1) Ensure TLS 1.1 is Disabled (Automated)
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled'
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled'
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault'
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault'

echo 7.6 (L1) Ensure TLS 1.2 is Enabled (Automated)
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocol s\TLS 1.2\Server' -name 'Enabled'
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault'

echo 7.7 (L1) Ensure NULL Cipher Suites is Disabled (Automated)
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' -name 'Enabled'

echo 7.8 (L1) Ensure DES Cipher Suites is Disabled (Automated)
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56' -name 'Enabled'

echo 7.9 (L1) Ensure RC4 Cipher Suites is Disabled (Automated)
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128' -name 'Enabled'
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128' -name 'Enabled'
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128' -name 'Enabled'
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128' -name 'Enabled'

echo 7.10 (L1) Ensure AES 128/128 Cipher Suite is Disabled (Automated)
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128' -name 'Enabled'

echo 7.11 (L1) Ensure AES 256/256 Cipher Suite is Enabled (Automated)
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256' -name 'Enabled'

echo 7.12 (L2) Ensure TLS Cipher Suite ordering is Configured (Automated)
Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions'

pause