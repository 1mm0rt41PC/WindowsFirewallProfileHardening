# DHCP suffix. Normaly this value is the same has the domain name (see the value of %USERDNSDOMAIN%)
$_CONF_DNS_SUFFIX = '1mm0rt41.lab.local'

$_CONF_TIME_OUT = 2000# Milli-seconds
$_CONF_ALLOWED_THUMBPRINT = @(
	'D1C2373A92889FDFEA795EF9DE00BFE8650586B5',
	''# DO NOT REMOVE
)
# REMOVE THIS TEST IN PROD
if( $env:USERDNSDOMAIN.ToUpper() -ne $_CONF_DNS_SUFFIX.ToUpper() ){
	Write-Host "%USERDNSDOMAIN% is not the same as the DHCP suffix. Is it normal ? Expecting identical value !!!!!!"
}






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
		Write-Host "Possible Attack !!! Invalid rootCA >$rootCA<"
		return $false
	}
	return $true
}

function checkDomainStatus
{
	try {
		Get-NetConnectionProfile -NetworkCategory Private | Set-NetConnectionProfile -NetworkCategory Public
		Get-NetConnectionProfile -NetworkCategory DomainAuthenticated -ErrorAction SilentlyContinue | foreach {
			$suffix = ($_ | Get-DnsClient).ConnectionSpecificSuffix
			if( $suffix -ne $_CONF_DNS_SUFFIX -or (-not isValidDomainCertificate) ){
				$_ | Set-NetConnectionProfile -NetworkCategory Public
			}
		}
	}	
}


# Event detector
$networkChange = [System.Net.NetworkInformation.NetworkChange]
Register-ObjectEvent -InputObject $networkChange -EventName NetworkAddressChanged -Action {
	write-host "New network activity detected !"
	checkDomainStatus
} > $null;

# Recheck network status every 1minute
$timer = New-Object System.Timers.Timer -Property @{ Interval=60000; AutoReset=$false };
Register-ObjectEvent $timer -EventName Elapsed -SourceIdentifier ADGWM_Timer -Action {
	write-host "Checking network activity..."
	checkDomainStatus
} > $null;
