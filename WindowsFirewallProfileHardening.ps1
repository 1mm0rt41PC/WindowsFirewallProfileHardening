# DHCP suffix. Normaly this value is the same has the domain name (see the value of %USERDNSDOMAIN%)
$_CONF_DNS_SUFFIX = '1mm0rt41.lab.local'

$_CONF_TIME_OUT = 2000# Milli-seconds
# List of thumprint or file to the list of thumprint
$_CONF_ALLOWED_THUMBPRINT = 'C:\Windows\AutoHarden\AD_THUMBPRINT.list'
# OR
#$_CONF_ALLOWED_THUMBPRINT = @(
#	'D1C2373A92889FDFEA795EF9DE00BFE8650586B5',
#	''# DO NOT REMOVE
#)

#############################################################################


function Get-RemoteSslCertificate
{
	# Author: jstangroome https://gist.github.com/jstangroome/5945820
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$true)]
		[string]
		$ComputerName,
		[int]
		$Port = 636
	)

	$Certificate = $null
	$TcpClient = New-Object -TypeName System.Net.Sockets.TcpClient;
	try {
		$async = $TcpClient.ConnectAsync($ComputerName, $Port)
		$async.Wait($_CONF_TIME_OUT) | out-null	
		if( $async.Status -ne 'RanToCompletion' ){
			$TcpClient.Dispose()
			return $null
		}
		$TcpStream = $TcpClient.GetStream()
		$Callback = { param($sender, $cert, $chain, $errors) return $true }
		$SslStream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList @($TcpStream, $true, $Callback)
		try {
			$SslStream.AuthenticateAsClient('')
			$Certificate = $SslStream.RemoteCertificate
		} finally {
			$SslStream.Dispose()
		}
	} finally {
		$TcpClient.Dispose()
	}

	if ($Certificate) {
		if ($Certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
			$Certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $Certificate
		}
		return $Certificate
	}
	return $null
}


function isValidDomainCertificate( $domainIP=$_CONF_DNS_SUFFIX )
{
	$cert = Get-RemoteSslCertificate $domainIP 636
	$chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
	$chain.Build($cert) | out-null
	$rootCA = $chain.ChainElements[$chain.ChainElements.Count-1]
	$rootCA = $rootCA.Certificate.Thumbprint.ToUpper()
	if( -not $_CONF_ALLOWED_THUMBPRINT.Contains($rootCA) ){
		Write-Host "[!] Possible Attack !!! Invalid rootCA >$rootCA<"
		Write-Host "[!] If your are sure of your network, add $rootCA into the variable `$_CONF_ALLOWED_THUMBPRINT"
		return $false
	}
	return $true
}


function checkDomainStatus {
	try {
		$_CONF_DNS_SUFFIX = $_CONF_DNS_SUFFIX.ToUpper()
		Get-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue | Set-NetConnectionProfile -NetworkCategory Public
		$cert = isValidDomainCertificate
		Get-NetConnectionProfile -NetworkCategory DomainAuthenticated -ErrorAction SilentlyContinue | foreach {
			$suffix = ($_ | Get-DnsClient).ConnectionSpecificSuffix.ToUpper()
			if( ($suffix -eq $_CONF_DNS_SUFFIX) -and $cert ){
				Write-Host ("[*] Valid connection to the internal network has been detected on the interface >"+($_.Name)+"<")
			}else{
				Get-NetConnectionProfile -NetworkCategory DomainAuthenticated -ErrorAction SilentlyContinue | Set-NetConnectionProfile -NetworkCategory Public
				Write-Host ("[!] HACKED detected !!!! Fake connection to the internal network has been detected on the interface >"+($_.Name)+"<")
				Write-Host ("[!] Suffix: "+$suffix)
				Write-Host ("[!] Suffix-test: "+($suffix -eq $_CONF_DNS_SUFFIX))
				Write-Host ("[!] Suffix-Expected: "+$_CONF_DNS_SUFFIX)
				Write-Host ("[!] isValidDomainCertificate: "+$cert)
			}
		}
	}catch [Exception]{
	  Write-Error $_.Exception.GetType().FullName, $_.Exception.Message
	  Write-Error $_.Exception | format-list -force *
	}
}



if( $env:USERDNSDOMAIN.ToUpper() -ne $_CONF_DNS_SUFFIX.ToUpper() ){
	Write-Host "[!] %USERDNSDOMAIN% is not the same as the DHCP suffix. Is it normal ? Expecting identical value !!!!!!"
}

# Detect if $_CONF_ALLOWED_THUMBPRINT is a fil with a list of thumbprint
if( [System.IO.File]::Exists($_CONF_ALLOWED_THUMBPRINT) -or $_CONF_ALLOWED_THUMBPRINT.StartsWith('C:\') ){
	$tmp = (cat $_CONF_ALLOWED_THUMBPRINT -ErrorAction SilentlyContinue)
	if(($tmp -ne $null) -and ($tmp -ne "")) {
		$_CONF_ALLOWED_THUMBPRINT = $tmp.Replace("`r",'').Split("`n")
	}else{
		# If $_CONF_ALLOWED_THUMBPRINT is empty => we need to get the current thumbprint
		$cert = Get-RemoteSslCertificate $_CONF_DNS_SUFFIX 636
		$chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
		$chain.Build($cert) | out-null
		$rootCA = $chain.ChainElements[$chain.ChainElements.Count-1]
		$rootCA = $rootCA.Certificate.Thumbprint.ToUpper()
		$rootCA | Out-File -Append $_CONF_ALLOWED_THUMBPRINT -Encoding ascii
		$_CONF_ALLOWED_THUMBPRINT = @($rootCA)
		Write-Host "[*] First run, whitelisting the certificate $rootCA"
	}
}

# Event detector
$networkChange = [System.Net.NetworkInformation.NetworkChange]
Register-ObjectEvent -InputObject $networkChange -EventName NetworkAddressChanged -Action {
	write-host "New network activity detected !"
	checkDomainStatus
} > $null;

while($true)
{
	checkDomainStatus
	Sleep 60000
}
