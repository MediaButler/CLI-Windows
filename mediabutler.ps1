#Requires -Version 5.0
# Script to setup/configure MediaButler
# HalianElf
using namespace System.Management.Automation

# Define variables
$InformationPreference = 'Continue'
$uuid = "fb67fb8b-9000-4a70-a67b-2f2b626780bb"
$userDataPath = '.\userData.json'
$plexLoginURL = "https://plex.tv/users/sign_in.json"
$mbLoginURL = "https://auth.mediabutler.io/login"
$mbDiscoverURL = "https://auth.mediabutler.io/login/discover"
$userData = @{}
$setupChecks = @{
	"sonarr"=$false;
	"sonarr4k"=$false;
	"radarr"=$false;
	"radarr4k"=$false;
	"radarr3d"=$false;
	"tautulli"=$false;
}

# Function to change the color output of text
# https://blog.kieranties.com/2018/03/26/write-information-with-colours
function Write-ColorOutput() {
	[CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Object]$MessageData,
        [ConsoleColor]$ForegroundColor = $Host.UI.RawUI.ForegroundColor, # Make sure we use the current colours by default
        [ConsoleColor]$BackgroundColor = $Host.UI.RawUI.BackgroundColor,
        [Switch]$NoNewline
    )

    $msg = [HostInformationMessage]@{
        Message         = $MessageData
        ForegroundColor = $ForegroundColor
        BackgroundColor = $BackgroundColor
        NoNewline       = $NoNewline.IsPresent
    }

    Write-Information $msg
}

# Check if userData.json exists
# Returns the array of the User Data
function checkUserData() {
	if (Test-Path $userDataPath -PathType Leaf) {
		$fileIn = Get-Content -Raw -Path $userDataPath | ConvertFrom-Json
		$fileIn.psobject.properties | Foreach-Object { $userData[$_.Name] = $_.Value }
	}
}

# Check if Plex Auth Token is saved in userData and if not print menu and get it from user
function checkPlexAuth() {
	if ([string]::IsNullOrEmpty($userData.authToken)) {
		Write-Information ""
		Write-Information "First thing we need are your Plex credentials so please choose from one of the following options:"
		Write-Information ""
		Write-Information "1. Plex Username and Password"
		Write-Information "2. Plex token"
		Write-Information ""

		$valid = $false
		do {
			$ans = Read-Host 'Enter selection'
			if ($ans -eq 1) {
				$userData.authToken = plexLogin
				$mbLoginResponse = mbLogin $userdata.authToken
				$valid = $true
			} elseif ($ans -eq 2) {
				do {
					Write-Information ""
					Write-Information "Please enter your Plex token:"
					$authTokenEnc = Read-Host -AsSecureString
					$credentials = New-Object System.Management.Automation.PSCredential -ArgumentList "authToken", $authTokenEnc
					$userdata.authToken = $credentials.GetNetworkCredential().Password
					$mbLoginResponse = mbLogin $userdata.authToken
					if([string]::IsNullOrEmpty($mbLoginResponse)) {
						Write-ColorOutput -ForegroundColor red -MessageData "The credentials that you provided are not valid!"
					}
				} while ([string]::IsNullOrEmpty($mbLoginResponse))
				$valid = $true
			} else {
				Write-ColorOutput -ForegroundColor red -MessageData "Invalid Response. Please try again."
			}
		} while (-Not ($valid))
		$userData | ConvertTo-Json | Out-File -FilePath $userDataPath
	}
}

# Function for logging into Plex with a Username/Password
# This will loop until valid credentials are provided
# Returns Plex authToken
function plexLogin() {
	$authToken = ""
	do {
		try {
			# Reset variables
			$failedLogin = $false
			$err = ""

			# Prompt for Username/Password
			Write-Information ""
			Write-Information "Please enter your Plex username:"
			$plexusername = Read-Host
			Write-Information "Please enter your Plex password:"
			$plexpassword = Read-Host -AsSecureString
			$credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $plexusername, $plexpassword
			$plexptpasswd = $credentials.GetNetworkCredential().Password

			# Format requests in JSON for API Call
			$headers = @{
				"X-Plex-Device"="API";
				"X-Plex-Device-Name"="DeviceName";
				"X-Plex-Product"="MediaButler";
				"X-Plex-Version"="v1.0";
				"X-Plex-Platform-Version"="v1.0";
				"X-Plex-Client-Identifier"="df9e71a5-a6cd-488e-8730-aaa9195f7435";
			};
			$creds = @{
				"login"="$plexusername";
				"password"="$plexptpasswd";
			};
			$body = @{
				"user"=$creds;
				"json"="true";
			};
			$body = $body | ConvertTo-Json

			Write-Information "Now we're going to make sure you provided valid credentials..."

			$response = Invoke-WebRequest -Uri $plexLoginURL -Method POST -Headers $headers -Body $body -ContentType "application/json" -UseBasicParsing
			$response = $response | ConvertFrom-Json
			$authToken = $response.user.authToken
			Write-ColorOutput -ForegroundColor green -MessageData "Success!"
		} catch [System.Net.WebException] {
			$err = $_.Exception.Response.StatusCode
			$failedLogin = $true
			if ($err -eq "Unauthorized") {
				Write-ColorOutput -ForegroundColor red -MessageData "The credentials that you provided are not valid!"
			}
		}
	} while ($failedLogin)
	$authToken
}

# Checks if provided authToken is valid
# Returns the response from MediaButler Login (empty string if failed)
function mbLogin($authToken) {
	$response = ""
	try {
		# Auth with PlexToken to MediaButler
		$headers = @{
			"MB-Client-Identifier"=$uuid;
		};
		$body = @{
			"authToken"=$authToken;
		};
		$body = $body | ConvertTo-Json
		$response = Invoke-WebRequest -Uri $mbLoginURL -Method POST -Headers $headers -Body $body -ContentType "application/json" -UseBasicParsing

		# Convert to Array so it can be used
		$response = $response | ConvertFrom-Json
		$response
	} catch [System.Net.WebException] {
		$response
	}
}

# Choose Server for MediaButler
function chooseServer() {
	if (([string]::IsNullOrEmpty($userData.machineId)) -Or ([string]::IsNullOrEmpty($userData.mbToken))) {
		if ([string]::IsNullOrEmpty($mbLoginResponse)) {
			$mbLoginResponse = mbLogin $userdata.authToken
		}
		# Print Owned Servers and create menu with them
		$i = 0
		Write-Information ""
		Write-Information "Please choose which Plex Server you would like to setup MediaButler for:"
		$menu = @{}
		foreach ($server in $mbLoginResponse.servers) {
			try {
				$owner = [System.Convert]::ToBoolean($server.owner)
			} catch [FormatException] {
				$owner = $false
			}
			if ($owner) {
				$i++
				Write-Information "$i. $($server.name)"
				$serverInfo = @{"serverName"="$($server.name)"; "machineId"="$($server.machineId)"; "mbToken"="$($server.token)";};
				$menu.Add($i,($serverInfo))
			}
		}
		do {
			$ans = Read-Host 'Enter selection'
			$ans = [int]$ans
			if ($ans -ge 1 -And $ans -le $i) {
				$valid = $true
				$userData.serverName = $menu.Item($ans).serverName
				$userData.machineId = $menu.Item($ans).machineId
				$userData.mbToken = $menu.Item($ans).mbToken
			} else {
				$valid = $false
				Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
			}
		} while (-Not ($valid))
		$userData | ConvertTo-Json | Out-File -FilePath $userDataPath
	}
}

# Takes a MediaButler url and tests it for the API version. If that doesn't come back with an API version above 1.1.12, it's not MediaButler
# Returns $true or $false
function testMB($url) {
	$isMB = $false
	try {
		$response = Invoke-WebRequest -Uri $url"version" -TimeoutSec 10 -UseBasicParsing
		$response = $response | ConvertFrom-Json
		$apiVersion = $response.apiVersion.Split(".")
		if (($apiVersion[0] -gt 1) -Or ($apiVersion[1] -gt 1) -Or ($apiVersion[2] -ge 12)) {
			$isMB = $true;
		}
	} catch [System.Net.WebException] {
		$isMB = $false;
	}
	$isMB
}

# Get MediaButler URL
function getMbURL() {
	if ([string]::IsNullOrEmpty($userData.mbURL)) {
		# Test if localhost is MediaButler server
		$isMB = $false;
		# Use Plex token and Machine ID to get URL
		try {
			if (testMB "http://127.0.0.1:9876/") {
				$mbURL = "http://127.0.0.1:9876/"
			} else {
				$headers = @{
					"MB-Client-Identifier"=$uuid;
				};
				$body = @{
					"authToken"=$userData.authToken;
					"machineId"=$userData.machineId;
				};
				$body = $body | ConvertTo-Json
				$mbURL = Invoke-WebRequest -Uri $mbDiscoverURL -Method POST -Headers $headers -Body $body -ContentType "application/json"  -UseBasicParsing
			}
			Write-Information "Is this the correct MediaButler URL?"
			Write-ColorOutput -ForegroundColor yellow -MessageData $mbURL
			Write-Information ""
			Write-ColorOutput -ForegroundColor green -nonewline -MessageData "[Y]"; Write-ColorOutput -nonewline -MessageData "es or "; Write-ColorOutput -ForegroundColor red -nonewline -MessageData "[N]"; Write-ColorOutput -MessageData "o";
			$valid = $false
			do {
				$ans = Read-Host
				if (($ans -notlike "y") -And ($ans -notlike "yes") -And ($ans -notlike "n") -And ($ans -notlike "no")) {
					Write-ColorOutput -ForegroundColor red -MessageData "Please specify yes, y, no, or n."
					$valid = $false
				} elseif (($ans -like "y") -Or ($ans -like "yes")) {
					$valid = $true
				} else {
					throw "Not correct URL"
				}
			} while (-Not ($valid))
		} catch {
			# If token doesn't work, ask user and loop until a correct url is given
			do {
				$mbURL = Read-Host 'MediaButler URL'
				$lastChar = $mbURL.SubString($mbURL.Length - 1)
				if ($lastChar -ne "/") {
					$mbURL = "$mbURL/"
				}
				$isMB = testMB $mbURL;
				if(-Not ($isMB)) {
					Write-ColorOutput -ForegroundColor red -MessageData "Invalid Server URL"
				}
			} while(-Not ($isMB));
			$userData.mbURL = $mbURL
		}
		$userData | ConvertTo-Json | Out-File -FilePath $userDataPath
	}
}

# Do status checks on each of the endpoints and see if they're setup
function setupChecks() {
	for ($i=0; $i -lt 6; $i++) {
		switch ($i) {
			0 { $endpoint = "sonarr"; break }
			1 { $endpoint = "sonarr4k"; break }
			2 { $endpoint = "radarr"; break }
			3 { $endpoint = "radarr4k"; break }
			4 { $endpoint = "radarr3d"; break }
			5 { $endpoint = "tautulli"; break }
		}
		$headers = @{
			"Content-Type"="application/json"
			"MB-Client-Identifier"=$uuid;
			"Authorization"="Bearer " + $userData.mbToken;
		};
		$formattedURL = [System.String]::Concat(($userData.mbURL), 'configure/', ($endpoint))
		try {
			$response = Invoke-WebRequest -Uri $formattedURL -Method GET -Headers $headers -UseBasicParsing
			$response = $response | ConvertFrom-Json
		} catch {
			Write-Debug $_.Exception.Response
		}
		if (-Not [string]::IsNullOrEmpty($response.settings)) {
			$setupChecks.($endpoint) = $true
		}
	}
}

# Print the main menu
# Returns selection
function mainMenu() {
	Write-Information ""
	Write-Information "*****************************************"
	Write-Information "*               Main Menu               *"
	Write-Information "*****************************************"
	Write-Information "Please choose which application you would"
	Write-Information "   like to configure for MediaButler:    "
	Write-Information ""
	Write-Information "1. Sonarr"
	Write-Information "2. Radarr"
	Write-ColorOutput -nonewline -MessageData "3. "
	if ($setupChecks.tautulli) {
		Write-ColorOutput -ForegroundColor green -MessageData "Tautulli"
	} else {
		Write-ColorOutput -ForegroundColor red -MessageData "Tautulli"
	}
	Write-Information "4. Exit"
	Write-Information ""
	do {
		$ans = Read-Host 'Enter selection'
		if (-Not(($ans -ge 1) -And ($ans -le 4))) {
			Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
			$valid = $false
		} elseif ($ans -eq 1) {
			$valid = $true
			sonarrMenu
		} elseif ($ans -eq 2) {
			$valid = $true
			radarrMenu
		} elseif ($ans -eq 3) {
			$valid = $true
			setupTautulli
		} elseif ($ans -eq 4) {
			$valid = $true
			exitMenu
		}
	} while (-Not($valid))
}

function exitMenu() {
	Write-Information ""
	Write-Information "This will exit the program and any unfinished config setup will be lost."
	Write-Information "Are you sure you wish to exit?"
	Write-ColorOutput -ForegroundColor green -nonewline -MessageData "[Y]"; Write-ColorOutput -nonewline -MessageData "es or "; Write-ColorOutput -ForegroundColor red -nonewline -MessageData "[N]"; Write-ColorOutput -MessageData "o";
	do {
		$ans = Read-Host
		if (($ans -notlike "y") -And ($ans -notlike "yes") -And ($ans -notlike "n") -And ($ans -notlike "no")) {
			Write-ColorOutput -ForegroundColor red -MessageData "Please specify yes, y, no, or n."
			$valid = $false
		} elseif (($ans -like "n") -Or ($ans -like "no")) {
			$valid = $true
			mainMenu
		} else {
			Exit
		}
	} while (-Not ($valid))
}

# Print the Sonarr menu and get response
function sonarrMenu() {
	Write-Information ""
	Write-Information "*****************************************"
	Write-Information "*           Sonarr Setup Menu           *"
	Write-Information "*****************************************"
	Write-Information "Please choose which version of Sonarr you"
	Write-Information "would like to configure for MediaButler: "
	Write-Information ""
	Write-ColorOutput -nonewline -MessageData "1. "
	if ($setupChecks.sonarr) {
		Write-ColorOutput -ForegroundColor green -MessageData "Sonarr"
	} else {
		Write-ColorOutput -ForegroundColor red -MessageData "Sonarr"
	}
	Write-ColorOutput -nonewline -MessageData "2. "
	if ($setupChecks.sonarr4k) {
		Write-ColorOutput -ForegroundColor green -MessageData "Sonarr 4K"
	} else {
		Write-ColorOutput -ForegroundColor red -MessageData "Sonarr 4K"
	}
	Write-Information "3. Back to Main Menu"
	Write-Information ""
	do {
		$ans = Read-Host 'Enter selection'
		if (-Not(($ans -ge 1) -And ($ans -le 3))) {
			Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
			$valid = $false
		} elseif (($ans -eq 1) -Or ($ans -eq 2)) {
			$valid = $true
			$ans = [int]$ans
			setupArr ($ans + 10)
		} elseif ($ans -eq 3) {
			$valid = $true
			mainMenu
		}
	} while (-Not($valid))
}

# Print the Radarr menu and get response
function radarrMenu() {
	Write-Information ""
	Write-Information "*****************************************"
	Write-Information "*           Radarr Setup Menu           *"
	Write-Information "*****************************************"
	Write-Information "Please choose which version of Radarr you"
	Write-Information "would like to configure for MediaButler: "
	Write-Information ""
	Write-ColorOutput -nonewline -MessageData "1. "
	if ($setupChecks.radarr) {
		Write-ColorOutput -ForegroundColor green -MessageData "Radarr"
	} else {
		Write-ColorOutput -ForegroundColor red -MessageData "Radarr"
	}
	Write-ColorOutput -nonewline -MessageData "2. "
	if ($setupChecks.radarr4k) {
		Write-ColorOutput -ForegroundColor green -MessageData "Radarr 4K"
	} else {
		Write-ColorOutput -ForegroundColor red -MessageData "Radarr 4K"
	}
	Write-ColorOutput -nonewline -MessageData "3. "
	if ($setupChecks.radarr3d) {
		Write-ColorOutput -ForegroundColor green -MessageData "Radarr 3D"
	} else {
		Write-ColorOutput -ForegroundColor red -MessageData "Radarr 3D"
	}
	Write-Information "4. Back to Main Menu"
	Write-Information ""
	do {
		$ans = Read-Host 'Enter selection'
		if (-Not(($ans -ge 1) -And ($ans -le 4))) {
			Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
			$valid = $false
		} elseif (($ans -ge 1) -Or ($ans -le 3)) {
			$valid = $true
			$ans = [int]$ans
			setupArr ($ans + 20)
		} elseif ($ans -eq 4) {
			$valid = $true
			mainMenu
		}
	} while (-Not($valid))
}

# Function to get the Tautulli information, test it and send it to the MediaButler server
function setupTautulli() {
	if ($setupChecks.tautulli -eq $true) {
		Write-ColorOutput -ForegroundColor red -MessageData "Tautulli appears to be setup already!"
		Write-ColorOutput -ForegroundColor yellow -MessageData "Do you wish to continue?"
		Write-ColorOutput -ForegroundColor green -nonewline -MessageData "[Y]"; Write-ColorOutput -nonewline -MessageData "es or "; Write-ColorOutput -ForegroundColor red -nonewline -MessageData "[N]"; Write-ColorOutput -MessageData "o";
		do {
			$answ = Read-Host
			if (($answ -notlike "y") -And ($answ -notlike "yes") -And ($answ -notlike "n") -And ($answ -notlike "no")) {
				Write-ColorOutput -ForegroundColor red -MessageData "Please specify yes, y, no, or n."
				$cont = $true
			} elseif (($answ -like "y") -Or ($answ -like "yes")) {
				$cont = $false
			} elseif (($answ -like "n") -Or ($answ -like "no")) {
				$cont = $false
				mainMenu
			}
		} while ($cont)
	}
	# Tautulli URL
	Write-Information ""
	Write-Information "Please enter your Tautulli URL (IE: http://127.0.0.1:8181/tautulli/):"
	do {
		$tauURL = Read-Host -Prompt "URL"
		$lastChar = $tauURL.SubString($tauURL.Length - 1)
		if ($lastChar -ne "/") {
			$tauURL = "$tauURL/"
		}
		Write-Information "Checking that the provided Tautulli URL is valid..."
		try {
			$response = Invoke-WebRequest -Uri $tauURL"auth/login" -Method Head -UseBasicParsing
			[String]$title = $response -split "`n" | Select-String -Pattern '<title>'
		} catch {
			Write-Debug $_.Exception.Response
		}
		if ($title -like "*Tautulli*") {
			Write-ColorOutput -ForegroundColor green -MessageData "Success!"
			$valid = $true
		} else {
			Write-ColorOutput -ForegroundColor red -MessageData "Received something other than a 200 OK response!"
			$valid = $false
		}
	} while (-Not($valid))

	# API Key
	Write-Information ""
	Write-Information "Please enter your Tautulli API key"
	do {
		$tauAPI = Read-Host -Prompt 'API' -AsSecureString
		$credentials = New-Object System.Management.Automation.PSCredential -ArgumentList "apiKey", $tauAPI
		$tauAPI = $credentials.GetNetworkCredential().Password
		Write-Information ""
		Write-Information "Testing that the provided Tautulli API Key is valid..."
		try {
			$response = Invoke-WebRequest -Uri $tauURL"api/v2?apikey="$tauAPI"&cmd=arnold" -UseBasicParsing
			$response = $response | ConvertFrom-Json
		} catch {
			Write-Debug $_.Exception.Response
		}
		if ($null -eq $response.response.message) {
			Write-ColorOutput -ForegroundColor green -MessageData "Success!"
			$valid = $true
		} else {
			Write-ColorOutput -ForegroundColor red -MessageData "Received something other than an OK response!"
			$valid = $false
		}
	} while (-Not($valid))

	# Set MediaButler formatting
	$headers = @{
		"Content-Type"="application/json"
		"MB-Client-Identifier"=$uuid;
		"Authorization"="Bearer " + $userData.mbToken;
	};
	$body = @{
		"url"=$tauURL;
		"apikey"=$tauAPI;
	};
	$body = $body | ConvertTo-Json
	$formattedURL = [System.String]::Concat(($userData.mbURL), 'configure/tautulli')

	# Test and Save to MediaButler
	Write-Information ""
	Write-Information "Testing the full Tautulli config for MediaButler..."
	try {
		$response = Invoke-WebRequest -Uri $formattedURL -Method PUT -Headers $headers -Body $body -UseBasicParsing
		$response = $response | ConvertFrom-Json
	} catch {
		Write-Debug $_.Exception.Response
	}
	if ($response.message -eq "success") {
		Write-ColorOutput -ForegroundColor green -MessageData "Success!"
		Write-Information ""
		Write-Information "Saving the Tautulli config to MediaButler..."
		try {
			$response = Invoke-WebRequest -Uri $formattedURL -Method POST -Headers $headers -Body $body -UseBasicParsing
			$response = $response | ConvertFrom-Json
		} catch {
			Write-Debug $_.Exception.Response
		}
		if ($response.message -eq "success") {
			Write-ColorOutput -ForegroundColor green -MessageData "Done! Tautulli has been successfully configured for"
			$str = "MediaButler with the " + $userData.serverName + " Plex server."
			Write-ColorOutput -ForegroundColor green $str
			Start-Sleep -s 3
			Write-Information "Returning you to the Main Menu..."
		}  elseif ($response.message -ne "success") {
			Write-ColorOutput -ForegroundColor red -MessageData "Config push failed! Please try again later."
			Start-Sleep -s 3
		}
	} elseif ($response.message -ne "success") {
		Write-ColorOutput -ForegroundColor red -MessageData "Hmm, something weird happened. Please try again."
		Start-Sleep -s 3
	}
	mainMenu
}

# Fucntion to get a list of Profiles from *arr and create a menu for the user to pick from
# Returns selected profile name
function arrProfiles($response) {
	Write-Information ""
	Write-Information "Please choose which profile you would like to set as the default for MediaButler:"
	$menu = @{}
	$i = 0
	foreach ($profile in $response) {
		$i++
		Write-Information "$i. $($profile.name)"
		$menu.Add($i,($profile.name))
	}
	do {
		$ans = Read-Host 'Profile'
		if (($ans -ge 1) -And ($ans -le $i)) {
			$valid = $true
			$ans = [int]$ans
			$menu.Item($ans)
		} else {
			$valid = $false
			Write-ColorOutput -ForegroundColor red -MessageData "Invalid Response."
		}
	} while (-Not ($valid))
}

function arrRootDir($response) {
	Write-Information ""
	Write-Information "Please choose which root directory you would like to set as the default for MediaButler:"
	$menu = @{}
	$i = 0
	foreach ($rootDir in $response) {
		$i++
		Write-Information "$i. $($rootDir.path)"
		$menu.Add($i,($rootDir.path))
	}
	do {
		$ans = Read-Host 'Profile'
		if (($ans -ge 1) -And ($ans -le $i)) {
			$valid = $true
			$ans = [int]$ans
			$menu.Item($ans)
		} else {
			$valid = $false
			Write-ColorOutput -ForegroundColor red -MessageData "Invalid Response."
		}
	} while (-Not ($valid))
}

# Function to set up Sonarr
function setupArr($ans) {
	if ($ans -eq 11) {
		$endpoint = "sonarr"
		$arr = "Sonarr"
		$exURL = "http://127.0.0.1:8989/sonarr/"
	} elseif ($ans -eq 12) {
		$endpoint = "sonarr4k"
		$arr = "Sonarr"
		$exURL = "http://127.0.0.1:8989/sonarr/"
	} elseif ($ans -eq 21) {
		$endpoint = "radarr"
		$arr = "Radarr"
		$exURL = "http://127.0.0.1:7878/radarr/"
	} elseif ($ans -eq 22) {
		$endpoint = "radarr4k"
		$arr = "Radarr"
		$exURL = "http://127.0.0.1:7878/radarr/"
	} elseif ($ans -eq 23) {
		$endpoint = "radarr3d"
		$arr = "Radarr"
		$exURL = "http://127.0.0.1:7878/radarr/"
	}
	$setupChecks.($endpoint) = $false
	if ($setupChecks.($endpoint) -eq $true) {
		Write-ColorOutput -ForegroundColor red -MessageData "$arr appears to be setup already!"
		Write-ColorOutput -ForegroundColor yellow -MessageData "Do you wish to continue?"
		Write-ColorOutput -ForegroundColor green -nonewline -MessageData "[Y]"; Write-ColorOutput -nonewline -MessageData "es or "; Write-ColorOutput -ForegroundColor red -nonewline -MessageData "[N]"; Write-ColorOutput -MessageData "o";
		do {
			$answ = Read-Host
			if (($answ -notlike "y") -And ($answ -notlike "yes") -And ($answ -notlike "n") -And ($answ -notlike "no")) {
				Write-ColorOutput -ForegroundColor red -MessageData "Please specify yes, y, no, or n."
				$cont = $true
			} elseif (($answ -like "y") -Or ($answ -like "yes")) {
				$cont = $false
			} elseif (($answ -like "n") -Or ($answ -like "no")) {
				$cont = $false
				if (($ans -gt 10) -And ($ans -lt 20)) {
					sonarrMenu
				} elseif (($ans -gt 20) -And ($ans -lt 30)) {
					radarrMenu
				}
			}
		} while ($cont)
	}
	# Sonarr URL
	Write-Information ""
	Write-Information "Please enter your $arr URL (IE: $exURL):"
	do {
		$url = Read-Host -Prompt "URL"
		$lastChar = $url.SubString($url.Length - 1)
		if ($lastChar -ne "/") {
			$url = "$url/"
		}
		Write-Information "Checking that the provided $arr URL is valid..."
		try {
			$response = Invoke-WebRequest -Uri $url -UseBasicParsing
			[String]$title = $response -split "`n" | Select-String -Pattern '<title>'
		} catch {
			Write-Debug $_.Exception
		}
		if ($title -like "*$arr*") {
			Write-ColorOutput -ForegroundColor green -MessageData "Success!"
			$valid = $true
		} else {
			Write-ColorOutput -ForegroundColor red -MessageData "Received something other than a 200 OK response!"
			$valid = $false
		}
	} while (-Not($valid))

	# API Key
	Write-Information ""
	Write-Information "Please enter your $arr API key"
	do {
		$err = ""
		$apiKey = Read-Host -Prompt 'API' -AsSecureString
		$credentials = New-Object System.Management.Automation.PSCredential -ArgumentList "apiKey", $apiKey
		$apiKey = $credentials.GetNetworkCredential().Password
		Write-Information ""
		Write-Information "Testing that the provided $arr API Key is valid..."
		try {
			$headers = @{
				"X-Api-Key"=$apiKey
			};
			$response = Invoke-WebRequest -Uri $sonarrURL"api/system/status" -Headers $headers -UseBasicParsing
			$response = $response | ConvertFrom-Json
		} catch {
			$err = $_.Exception.Response.StatusCode
		}
		if ($err -eq "Unauthorized") {
			Write-ColorOutput -ForegroundColor red -MessageData "Received something other than an OK response!"
			$valid = $false
		} else {
			Write-ColorOutput -ForegroundColor green -MessageData "Success!"
			$valid = $true
		}
	} while (-Not($valid))

	# Default Profile
	try {
		$headers = @{
			"X-Api-Key"=$apiKey
		};
		$response = Invoke-WebRequest -Uri $url"api/profile" -Headers $headers -UseBasicParsing
		$response = $response | ConvertFrom-Json
		$arrProfile = arrProfiles $response
	} catch {
		Write-Debug $_.Exception
	}

	# Default Root Directory
	try {
		$headers = @{
			"X-Api-Key"=$apiKey
		};
		$response = Invoke-WebRequest -Uri $url"api/rootfolder" -Headers $headers -UseBasicParsing
		$response = $response | ConvertFrom-Json
		$rootDir = arrRootDir $response
	} catch {
		Write-Debug $_.Exception
	}

	# Set MediaButler formatting
	$headers = @{
		"Content-Type"="application/json"
		"MB-Client-Identifier"=$uuid;
		"Authorization"="Bearer " + $userData.mbToken;
	};
	$body = @{
		"url"=$url;
		"apikey"=$apiKey;
		"defaultProfile"=$arrProfile
		"defaultRoot"=$rootDir
	};
	$body = $body | ConvertTo-Json
	$formattedURL = [System.String]::Concat(($userData.mbURL), 'configure/', ($endpoint))

	# Test and Save to MediaButler
	Write-Information ""
	Write-Information "Testing the full $arr config for MediaButler..."
	try {
		$response = Invoke-WebRequest -Uri $formattedURL -Method PUT -Headers $headers -Body $body -UseBasicParsing
		$response = $response | ConvertFrom-Json
	} catch {
		Write-Debug $_.Exception
	}
	if ($response.message -eq "success") {
		Write-ColorOutput -ForegroundColor green -MessageData "Success!"
		Write-Information ""
		Write-Information "Saving the $arr config to MediaButler..."
		try {
			$response = Invoke-WebRequest -Uri $formattedURL -Method POST -Headers $headers -Body $body -UseBasicParsing
			$response = $response | ConvertFrom-Json
		} catch {
			Write-Debug $_.Exception
		}
		if ($response.message -eq "success") {
			Write-ColorOutput -ForegroundColor green -MessageData "Done! $arr has been successfully configured for"
			Write-ColorOutput -ForegroundColor green -MessageData "MediaButler with the $($userData.serverName) Plex server."
			Start-Sleep -s 3
			Write-Information "Returning you to the Main Menu..."
			mainMenu
		}  elseif ($response.message -ne "success") {
			Write-ColorOutput -ForegroundColor red -MessageData "Config push failed! Please try again later."
			Start-Sleep -s 3
		}
	} elseif ($response.message -ne "success") {
		Write-ColorOutput -ForegroundColor red -MessageData "Hmm, something weird happened. Please try again."
		Start-Sleep -s 3
	}
	if (($ans -gt 10) -And ($ans -lt 20)) {
		sonarrMenu
	} elseif (($ans -gt 20) -And ($ans -lt 30)) {
		radarrMenu
	}
}

function main () {
	Write-Information "Welcome to the MediaButler setup utility!"
	checkUserData
	checkPlexAuth
	chooseServer
	getMbURL
	setupChecks
	mainMenu
}

main