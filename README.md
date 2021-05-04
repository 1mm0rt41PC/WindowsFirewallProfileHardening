# WindowsFirewallProfileHardening
Script to detect fake DHCP that force the Windows Firewall to migrate as `domain` profile.

Exemple of return:
```
PS C:\WINDOWS\system32> checkDomainStatus
[!] Possible Attack !!! Invalid rootCA >D1C2373A92889FDFEA795EF9DE00BFE8650586B7<
[!] If your are sure of your network, add D1C2373A92889FDFEA795EF9DE00BFE8650586B7 into the variable $_CONF_ALLOWED_THUMBPRINT
[!] HACKED detected !!!! Fake connection to the internal network has been detected on the interface >Ethernet1<
[!] Suffix: lab.1mm0rt41.local
[!] Suffix-test: False
[!] Suffix-Expected: lab.1mm0rt41.local
[!] isValidDomainCertificate: False
```

```
PS C:\WINDOWS\system32> checkDomainStatus
[*] Valid connection to the internal network has been detected on the interface >Ethernet1<
```


If connection to a network with a profile `domain`:
1) Connect to the DC on LDAPS and grab the rootCA
2) If the rootCA is not valid => change the firewall profile to `public`

If the computer have two connections (wifi + ethernet) and if both interface use the profile `domain`:
1) Connect to the DC on LDAPS and grab the rootCA
2) If the rootCA is not valid => change the firewall profile to `public` for all interfaces
