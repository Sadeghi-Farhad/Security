- Ensure web content is on non-system drive
- Ensure 'host headers' are on all sites
- Ensure 'directory browsing' is set to disabled
- Ensure 'application pool identity' is configured for all application pools
- Ensure 'unique application pools' is set for sites
- Ensure 'application pool identity' is configured for anonymous user identity

---
 - Ensure 'global authorization rule' is set to restrict access
- Ensure access to sensitive site features is restricted to authenticated principals only
- Ensure 'forms authentication' require SSL
- Ensure 'forms authentication' is set to use cookies
- Ensure transport layer security for 'basic authentication' is configured
- Ensure 'passwordFormat' is not set to clear 
- Ensure 'credentials' are not stored in configuration files

- Ensure 'deployment method retail' is set
- Ensure 'debug' is turned off
- Ensure custom error messages are not off
- Ensure IIS HTTP detailed errors are hidden from displaying remotely
- Ensure ASP.NET stack tracing is not enabled
- Ensure 'httpcookie' mode is configured for session state
- Ensure 'cookies' are set with HttpOnly attribute
- Ensure 'MachineKey validation method - .Net 3.5' is configured
- Ensure 'MachineKey validation method - .Net 4.5' is configured
- Ensure global .NET trust level is configured
- Ensure X-Powered-By Header is removed
- Ensure Server Header is removed

<div dir="rtl">
موارد ذیل درweb.config  اضافه شود :

1. تنظیمات مربوط به Ensure 'global authorization rule' is set to restrict access: 
<div dir="ltr">
  
```
  <configuration>
 <system.webServer>
        <security>
            <authorization>
                <remove users="*" roles="" verbs="" />
                <add accessType="Allow" roles="administrators" />
            </authorization>
        </security>
    </system.webServer>
</configuration>
```
</div>
2. تنظیمات مربوط به  Ensure 'forms authentication' is set to use cookies
<div dir="ltr">
  
  ```
<system.web> <authentication> <forms cookieless="UseCookies" requireSSL="true" timeout="30" /> </authentication> </system.web>
```
</div>

3. تنظیمات مربوط به  Ensure 'cookie protection mode' is configured for forms authentication
<div dir="ltr">

```
<system.web> <authentication> <forms cookieless="UseCookies" protection="All" /> </authentication> </system.web>
```
</div>

4. در تنظیمات مربوط به Ensure 'passwordFormat' is not set to clear  حتمن از مقدار <credentials passwordFormat="SHA1"> " استفاده شود
5. در تنظیمات مربوط به  Ensure 'deployment method retail' is set مقدار  <system.web> <deployment retail="true" /> </system.web> استفاده شود
6. در تنظیمات مربوط به   Ensure 'debug' is turned off  مقدار <system.web> <compilation debug="false" /> </system.web> استفاده شود
7. در تنظیمات مربوط به   Ensure IIS HTTP detailed errors are hidden from displaying remotely  مقدار <httpErrors errorMode="DetailedLocalOnly"> </httpErrors> استفاده شود 
8. در تنظیمات مربوط به  Ensure 'cookies' are set with HttpOnly attribute مقدار  <httpCookies httpOnlyCookies="true" /> استفاده شود
9. برای MachineKey validation method مقدار validation method برابرHMACSHA256  تنظیم شود (مربوط به تنظیمات IIS می باشد)
10. برای Ensure global .NET trust level is configured مقدارMedium  تنظیم شود (مربوط به تنظیمات IIS می باشد)
11. حذف Ensure X-Powered-By Header is removed
12. حذف Ensure Server Header is removed

</div>

---
- Ensure 'maxAllowedContentLength' is configured
- Ensure 'maxURL request filter' is configured
- Ensure 'MaxQueryString request filter' is configured
- Ensure non-ASCII characters in URLs are not allowed
- Ensure Double-Encoded requests will be rejected
- Ensure 'HTTP Trace Method' is disabled
- Ensure Unlisted File Extensions are not allowed
- Ensure Handler is not granted Write and Script/Execute
- Ensure 'notListedIsapisAllowed' is set to false
- Ensure 'notListedCgisAllowed' is set to false
- Ensure 'Dynamic IP Address Restrictions' is enabled

   موارد ذیل در web.config  اضافه شود
  <div dir="ltr">
1. محدود کردن 'maxAllowedContentLength'
```
<security>
<requestFiltering>
<requestLimits
maxAllowedContentLength="30000000" />
</requestFiltering>
</security>
```
2. محدود کردن 'maxURL request filter'
```
<configuration>
<system.webServer>
<security>
<requestFiltering>
<requestLimits
maxURL="4096" />
</requestFiltering>
</security>
</system.webServer>
</configuration>
```
3. محدود کردن 'MaxQueryString request filter'
```
<configuration>
<system.webServer>
<security>
<requestFiltering>
<requestLimits
maxQueryString="2048" />
</requestFiltering>
</security>
</system.webServer>
</configuration>
```
4. محدود کردن allowHighBitCharacters
```
<configuration>
<system.webServer>
<security>
<requestFiltering
allowHighBitCharacters="false">
</requestFiltering>
</security>
</system.webServer>
</configuration>
```
5. جلوگیری از DoubleEscaping
```
<configuration>
<system.webServer>
<security>
<requestFiltering
allowDoubleEscaping="false">
</requestFiltering>
</security>
</system.webServer>
</configuration>
```
6. جلوگیری از Trace
```
<configuration>
<system.webServer>
<security>
<requestFiltering>
<verbs>
<add verb="TRACE" allowed="false" />
</verbs>
</requestFiltering>
</security>
</system.webServer>
</configuration>
```
7. محدود کردن file extension
```
<configuration>
<system.webServer>
<security>
<requestFiltering>
<fileExtensions allowUnlisted="false">
<add fileExtension=".asp" allowed="true" />
<add fileExtension=".aspx" allowed="true" />
<add fileExtension=".html" allowed="true" />
</fileExtensions>
</requestFiltering>
</security>
</system.webServer>
</configuration>
```
8. تنظیم accessPolicy
```
<system.webserver>
<handlers accessPolicy="Read, Script">
</handlers>
</system.webserver>
```
9. غیر فعال کردن 'notListedIsapisAllowed'
```
<system.webServer>
<security>
<isapiCgiRestriction notListedIsapisAllowed="false">
</isapiCgiRestriction>
</security>
</system.webServer>
```
10. غیر فعال کردن notListedCgisAllowed
```
<system.webServer>
<security>
<isapiCgiRestriction notListedCgisAllowed="false">
</isapiCgiRestriction>
</security>
</system.webServer>
```

  </div>

  > اسکریپت موارد مطرح شده تا به اینجا، در فایل [IIS-Fixed.ba](IIS-Fixed.ba_) تهیه شده است.


  ---
  موارد ذیل مربوط به هاردنینگ وف و نرم افزار می باشد و آستانه پارامتر های درخواست های HTTP تنظیم می شود و این موارد در IIS نیز قابل تنظیم می باشند:
1. maxAllowedContentLength
2. maxURL request filter
3. MaxQueryString request filter
4. non-ASCII characters in URLs
5. Double-Encoded requests
6. allowUnlisted File Extensions

- Ensure Default IIS web log location is moved
- Ensure Advanced IIS logging is enabled
- Ensure 'ETW Logging' is enabled
- Ensure FTP requests are encrypted
- Ensure FTP Logon attempt restrictions is enabled

- Ensure HSTS Header is set
- Ensure SSLv2 is Disabled
- Ensure SSLv3 is Disabled
- Ensure TLS 1.0 is Disabled
- Ensure TLS 1.1 is Disabled
- Ensure TLS 1.2 is Enabled


موراد ذیل در تمامی web.config ها باید اعمال شود:
```
      <customHeaders>
        <remove name="X-Powered-By" />
        <add name="Header-Name" value="Header-Value" />
        <add name="Referrer-Policy" value="no-referrer" />
        <add name="X-Content-Type-Options" value="NOSNIFF" />
        <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
        <add name="X-Frame-Options" value="DENY" />
        <add name="X-Permitted-Cross-Domain-Policies" value="none" />
        <add name="Feature-Policy" value="vr:'none'" />
        <add name="X-XSS-Protection" value="1; mode=block" />
      </customHeaders>
```


