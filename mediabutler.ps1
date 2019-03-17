#Requires -Version 5.0
# Script to setup/configure MediaButler
# HalianElf
using namespace System.Management.Automation

# Define variables
$InformationPreference = 'Continue'
$Host.UI.RawUI.BackgroundColor = 'Black'
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
$isAdmin = $false
Clear-Host

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
		do {
			Write-Information ""
			Write-ColorOutput -ForegroundColor gray -MessageData "First thing we need are your Plex credentials so please choose from one of the following options:"
			Write-Information ""
			Write-ColorOutput -nonewline -MessageData "1) "; Write-ColorOutput -ForegroundColor gray -MessageData "Plex Username and Password"
			Write-ColorOutput -nonewline -MessageData "2) "; Write-ColorOutput -ForegroundColor gray -MessageData "Plex token"
			Write-Information ""
			$valid = $false
			Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Selection: "
			$ans = Read-Host
			try {
				$ans = [int]$ans
			} catch {
				[int]$ans = 0
			}
			if ($ans -eq 1) {
				$userData.authToken = plexLogin
				$mbLoginResponse = mbLogin $userdata.authToken
				$valid = $true
			} elseif ($ans -eq 2) {
				do {
					Write-Information ""
					Write-ColorOutput -ForegroundColor gray -MessageData "Please enter your Plex token:"
					$authTokenEnc = Read-Host -AsSecureString
					$credentials = New-Object System.Management.Automation.PSCredential -ArgumentList "authToken", $authTokenEnc
					$userdata.authToken = $credentials.GetNetworkCredential().Password
					$mbLoginResponse = mbLogin $userdata.authToken
					Write-Information ""
					Write-ColorOutput -ForegroundColor gray -MessageData "Now we're going to make sure you provided valid credentials..."
					if([string]::IsNullOrEmpty($mbLoginResponse)) {
						Write-ColorOutput -ForegroundColor red -MessageData "The credentials that you provided are not valid!"
					} else {
						Write-ColorOutput -ForegroundColor green -MessageData "Success!"
					}
				} while ([string]::IsNullOrEmpty($mbLoginResponse))
				$valid = $true
			} else {
				Write-Information ""
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
			Write-ColorOutput -ForegroundColor gray -MessageData "Please enter your Plex username:"
			$plexusername = Read-Host
			Write-Information ""
			Write-ColorOutput -ForegroundColor gray -MessageData "Please enter your Plex password:"
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
			Write-Information ""
			Write-ColorOutput -ForegroundColor gray -MessageData "Now we're going to make sure you provided valid credentials..."
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
		Write-ColorOutput -ForegroundColor gray -MessageData "Please choose which Plex Server you would like to setup MediaButler for:"
		Write-Information ""
		$menu = @{}
		foreach ($server in $mbLoginResponse.servers) {
			try {
				$owner = [System.Convert]::ToBoolean($server.owner)
			} catch [FormatException] {
				$owner = $false
			}
			if ($owner) {
				$i++
				Write-ColorOutput -nonewline -MessageData "$i) "; Write-ColorOutput -ForegroundColor gray -MessageData "$($server.name)"
				$serverInfo = @{"serverName"="$($server.name)"; "machineId"="$($server.machineId)"; "mbToken"="$($server.token)";};
				$menu.Add($i,($serverInfo))
			}
		}
		Write-Information ""
		do {
			Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Server: "
			$ans = Read-Host
			try {
				$ans = [int]$ans
			} catch {
				[int]$ans = 0
			}
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
		$manual = $false
		# Use Plex token and Machine ID to get URL
		try {
			Write-ColorOutput -ForegroundColor gray -MessageData "Gathering required information..."
			$headers = @{
				"MB-Client-Identifier"=$uuid;
			};
			$body = @{
				"authToken"=$userData.authToken;
				"machineId"=$userData.machineId;
			};
			$body = $body | ConvertTo-Json
			$mbURL = Invoke-WebRequest -Uri $mbDiscoverURL -Method POST -Headers $headers -Body $body -ContentType "application/json"  -UseBasicParsing
			Write-ColorOutput -ForegroundColor green -MessageData "Done!"
			Write-Information ""
			Write-ColorOutput -ForegroundColor gray -MessageData "Is this the correct MediaButler URL?"
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
					$manual = $true
					throw "Not correct URL"
				}
			} while (-Not ($valid))
		} catch {
			if (-Not($manual)) {
				# If token doesn't work, ask user and loop until a correct url is given
				Write-ColorOutput -ForegroundColor red -MessageData "Unable to automatically retrieve your MediaButler URL!"
				Write-ColorOutput -ForegroundColor yellow -MessageData "This is typically indicative of port 9876 not being forwarded."
				Write-ColorOutput -ForegroundColor yellow -MessageData "Please check your port forwarding and try again."
			}
			do {
				Write-ColorOutput -ForegroundColor gray -MessageData "Please enter the correct MediaButler URL:"
				$mbURL = Read-Host
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

# Do status checks on each of the endpoints to see if they're setup and set boolean
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
			Write-Debug $_.Exception
		}
		if (-Not [string]::IsNullOrEmpty($response.settings)) {
			$setupChecks.($endpoint) = $true
		}
	}
}

# Check if logged in user is admin of the chosen server
function checkAdmin() {
	$headers = @{
		"Content-Type"="application/json"
		"MB-Client-Identifier"=$uuid;
		"Authorization"="Bearer " + $userData.mbToken;
	};
	$formattedURL = [System.String]::Concat(($userData.mbURL), 'user/@me/')
	try {
		$response = Invoke-WebRequest -Uri $formattedURL -Method GET -Headers $headers -UseBasicParsing
		$response = $response | ConvertFrom-Json
		if ($response.permissions -contains "ADMIN") {
			$script:isAdmin = $true
		}
	} catch {
		Write-Debug $_.Exception
	}
}

# Print the main menu and get input
function mainMenu() {
	do {
		Write-Information ""
		Write-Information "*****************************************"
		Write-Information "*              ~Main Menu~              *"
		Write-Information "*****************************************"
		Write-ColorOutput -ForegroundColor gray -MessageData "Please select from the following options:"
		Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "        ("; Write-ColorOutput -ForegroundColor red -nonewline -MessageData "*"; Write-ColorOutput -ForegroundColor gray -MessageData " indicates Admin only)         "
		Write-Information ""
		Write-ColorOutput -nonewline -MessageData "1) "; Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Configure Applications"; Write-ColorOutput -ForegroundColor red -MessageData "*"
		Write-ColorOutput -nonewline -MessageData "2) "; Write-ColorOutput -ForegroundColor gray -MessageData "Media Requests"
		Write-ColorOutput -nonewline -MessageData "3) "; Write-ColorOutput -ForegroundColor gray -MessageData "Media Issues"
		Write-ColorOutput -nonewline -MessageData "4) "; Write-ColorOutput -ForegroundColor gray -MessageData "Playback Information"
		Write-ColorOutput -nonewline -MessageData "5) "; Write-ColorOutput -ForegroundColor gray -MessageData "Library Information"
		Write-ColorOutput -nonewline -MessageData "6) "; Write-ColorOutput -ForegroundColor gray -MessageData "Media Search"
		Write-ColorOutput -nonewline -MessageData "7) "; Write-ColorOutput -ForegroundColor gray -MessageData "Reset Config"
		Write-ColorOutput -nonewline -MessageData "8) "; Write-ColorOutput -ForegroundColor gray -MessageData "Exit"
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Selection: "
		$ans = Read-Host
		try {
			$ans = [int]$ans
		} catch {
			[int]$ans = 0
		}
		if (-Not(($ans -ge 1) -And ($ans -le 8))) {
			Write-Information ""
			Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
			$valid = $false
		} elseif ($ans -eq 1) {
			if (-Not ($isAdmin)) {
				$valid = $false
				Write-Information ""
				Write-ColorOutput -ForegroundColor red -MessageData "You do not have permission to access this menu!"
			} elseif ($isAdmin) {
				$valid = $true
				endpointMenu
			}
		} elseif ($ans -eq 2) {
			$valid = $true
			requestsMenu
		} elseif ($ans -eq 3) {
			$valid = $true
			issuesMenu
		} elseif ($ans -eq 4) {
			$valid = $true
			playbackMenu
		} elseif ($ans -eq 5) {
			$valid = $true
			Write-Information ""
			Write-ColorOutput -ForegroundColor red -MessageData "Not setup yet!"
			mainMenu
			#libraryMenu
		} elseif ($ans -eq 6) {
			$valid = $true
			searchMenu
		} elseif ($ans -eq 7) {
			$valid = $true
			resetAll
		} elseif ($ans -eq 8) {
			$valid = $true
			exitMenu
		}
	} while (-Not($valid))
}

# Print the Endpoint Menu and get input
function endpointMenu() {
	do {
		Write-Information ""
		Write-Information "*****************************************"
		Write-Information "*     ~Endpoint Configuration Menu~     *"
		Write-Information "*****************************************"
		Write-ColorOutput -ForegroundColor gray -MessageData "Please choose which application you would"
		Write-ColorOutput -ForegroundColor gray -MessageData "   like to configure for MediaButler:    "
		Write-Information ""
		Write-ColorOutput -nonewline -MessageData "1) "
		if ($setupChecks.sonarr -And $setupChecks.sonarr4k) {
			Write-ColorOutput -ForegroundColor green -MessageData "Sonarr"
		} elseif ($setupChecks.sonarr -Or $setupChecks.sonarr4k) {
			Write-ColorOutput -ForegroundColor yellow -MessageData "Sonarr"
		} else {
			Write-ColorOutput -ForegroundColor red -MessageData "Sonarr"
		}
		Write-ColorOutput -nonewline -MessageData "2) "
		if ($setupChecks.radarr -And $setupChecks.radarr4k -And $setupChecks.radarr3d) {
			Write-ColorOutput -ForegroundColor green -MessageData "Radarr"
		} elseif ($setupChecks.radarr -Or $setupChecks.radarr4k -Or $setupChecks.radarr3d) {
			Write-ColorOutput -ForegroundColor yellow -MessageData "Radarr"
		} else {
			Write-ColorOutput -ForegroundColor red -MessageData "Radarr"
		}
		Write-ColorOutput -nonewline -MessageData "3) "
		if ($setupChecks.tautulli) {
			Write-ColorOutput -ForegroundColor green -MessageData "Tautulli"
		} else {
			Write-ColorOutput -ForegroundColor red -MessageData "Tautulli"
		}
		Write-ColorOutput -nonewline -MessageData "4) "; Write-ColorOutput -ForegroundColor gray -MessageData "Return to Main Menu"
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Selection: "
		$ans = Read-Host
		try {
			$ans = [int]$ans
		} catch {
			[int]$ans = 0
		}
		if (-Not(($ans -ge 1) -And ($ans -le 4))) {
			Write-Information ""
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
			mainMenu
		}
	} while (-Not($valid))
}

# Print the Requests Menu and get input
function requestsMenu() {
	do {
		Write-Information ""
		Write-Information "*****************************************"
		Write-Information '*            ~Requests Menu~            *'
		Write-Information "*****************************************"
		Write-ColorOutput -ForegroundColor gray -MessageData "Please select from the following options:"
		Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "        ("; Write-ColorOutput -ForegroundColor red -nonewline -MessageData "*"; Write-ColorOutput -ForegroundColor gray -MessageData " indicates Admin only)         "
		Write-Information ""
		Write-ColorOutput -nonewline -MessageData "1) "; Write-ColorOutput -ForegroundColor gray -MessageData "Submit Request"
		Write-ColorOutput -nonewline -MessageData "2) "; Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Manage Requests"; Write-ColorOutput -ForegroundColor red "*"
		Write-ColorOutput -nonewline -MessageData "3) "; Write-ColorOutput -ForegroundColor gray -MessageData "Back to Main Menu"
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Selection: "
		$ans = Read-Host
		try {
			$ans = [int]$ans
		} catch {
			[int]$ans = 0
		}
		if (-Not(($ans -ge 1) -And ($ans -le 3))) {
			Write-Information ""
			Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
			$valid = $false
		} elseif ($ans -eq 1) {
			$valid = $true
			submitRequest
		} elseif ($ans -eq 2) {
			if (-Not ($isAdmin)) {
				$valid = $false
				Write-Information ""
				Write-ColorOutput -ForegroundColor red -MessageData "You do not have permission to access this menu!"
			} elseif ($isAdmin) {
				$valid = $true
				manageRequests
			}
		} elseif ($ans -eq 3) {
			$valid = $true
			mainMenu
		}
	} while (-Not($valid))
}

# Print the Issues menu and get input
function issuesMenu() {
	do {
		Write-Information ""
		Write-Information "*****************************************"
		Write-Information '*             ~Issues Menu~             *'
		Write-Information "*****************************************"
		Write-ColorOutput -ForegroundColor gray -MessageData "Please select from the following options:"
		Write-ColorOutput -nonewline -ForegroundColor gray -MessageData "        ("; Write-ColorOutput -ForegroundColor red -nonewline -MessageData "*"; Write-ColorOutput -ForegroundColor gray -MessageData " indicates Admin only)         "
		Write-Information ""
		Write-ColorOutput -nonewline -MessageData "1) "; Write-ColorOutput -ForegroundColor gray -MessageData "Add Issue"
		Write-ColorOutput -nonewline -MessageData "2) "; Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Manage Issues"; Write-ColorOutput -ForegroundColor red "*"
		Write-ColorOutput -nonewline -MessageData "3) "; Write-ColorOutput -ForegroundColor gray -MessageData "Back to Main Menu"
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Selection: "
		$ans = Read-Host
		try {
			$ans = [int]$ans
		} catch {
			[int]$ans = 0
		}
		if (-Not(($ans -ge 1) -And ($ans -le 3))) {
			Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
			$valid = $false
		} elseif ($ans -eq 1) {
			$valid = $true
			Write-Information ""
			Write-ColorOutput -ForegroundColor red -MessageData "Not setup yet!"
			mainMenu
			#addIssue
		} elseif ($ans -eq 2) {
			if (-Not ($isAdmin)) {
				$valid = $false
				Write-ColorOutput -ForegroundColor red -MessageData "You do not have permission to access this menu!"
			} elseif ($isAdmin) {
				$valid = $true
				Write-Information ""
				Write-ColorOutput -ForegroundColor red -MessageData "Not setup yet!"
				mainMenu
				#manageIssues
			}
		} elseif ($ans -eq 3) {
			$valid = $true
			mainMenu
		}
	} while (-Not($valid))
}

# Print the Playback Menu and get input
function playbackMenu() {
	do {
		Write-Information ""
		Write-Information "*****************************************"
		Write-Information '*            ~Playback Menu~            *'
		Write-Information "*****************************************"
		Write-ColorOutput -ForegroundColor gray -MessageData "Please select from the following options:"
		Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "        ("; Write-ColorOutput -ForegroundColor red -nonewline -MessageData "*"; Write-ColorOutput -ForegroundColor gray -MessageData " indicates Admin only)         "
		Write-Information ""
		Write-ColorOutput -nonewline -MessageData "1) "; Write-ColorOutput -ForegroundColor gray -MessageData "Playback History"
		Write-ColorOutput -nonewline -MessageData "2) "; Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Now Playing"; Write-ColorOutput -ForegroundColor red "*"
		Write-ColorOutput -nonewline -MessageData "3) "; Write-ColorOutput -ForegroundColor gray -MessageData "Back to Main Menu"
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Selection: "
		$ans = Read-Host
		try {
			$ans = [int]$ans
		} catch {
			[int]$ans = 0
		}
		if (-Not(($ans -ge 1) -And ($ans -le 3))) {
			Write-Information ""
			Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
			$valid = $false
		} elseif ($ans -eq 1) {
			$valid = $true
			playbackHistory
		} elseif ($ans -eq 2) {
			if (-Not ($isAdmin)) {
				$valid = $false
				Write-Information ""
				Write-ColorOutput -ForegroundColor red -MessageData "You do not have permission to access this menu!"
			} elseif ($isAdmin) {
				$valid = $true
				nowPlaying
			}
		} elseif ($ans -eq 3) {
			$valid = $true
			mainMenu
		}
	} while (-Not($valid))
}

# Print the Search Menu and get input
function searchMenu() {
	do {
		Write-Information ""
		Write-Information "*****************************************"
		Write-Information '*             ~Search Menu~             *'
		Write-Information "*****************************************"
		Write-ColorOutput -ForegroundColor gray -MessageData "Please select from the following options:"
		Write-Information ""
		Write-ColorOutput -nonewline -MessageData "1) "; Write-ColorOutput -ForegroundColor gray -MessageData "TV Show"
		Write-ColorOutput -nonewline -MessageData "2) "; Write-ColorOutput -ForegroundColor gray -MessageData "Movie"
		Write-ColorOutput -nonewline -MessageData "3) "; Write-ColorOutput -ForegroundColor gray -MessageData "Music"
		Write-ColorOutput -nonewline -MessageData "4) "; Write-ColorOutput -ForegroundColor gray -MessageData "Back to Main Menu"
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Selection: "
		$ans = Read-Host
		try {
			$ans = [int]$ans
		} catch {
			[int]$ans = 0
		}
		if (-Not(($ans -ge 1) -And ($ans -le 4))) {
			Write-Information ""
			Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
			$valid = $false
		} elseif ($ans -eq 1) {
			$valid = $true
			Write-Information ""
			Write-ColorOutput -ForegroundColor red -MessageData "Not setup yet!"
			searchMenu
		} elseif ($ans -eq 2) {
			$valid = $true
			Write-Information ""
			Write-ColorOutput -ForegroundColor red -MessageData "Not setup yet!"
			searchMenu
		} elseif ($ans -eq 3) {
			$valid = $true
			Write-Information ""
			Write-ColorOutput -ForegroundColor red -MessageData "Not setup yet!"
			searchMenu
		}elseif ($ans -eq 4) {
			$valid = $true
			mainMenu
		}
	} while (-Not($valid))
}

# Print the Exit Menu
function exitMenu() {
	do {
		Write-Information ""
		Write-ColorOutput -ForegroundColor red -MessageData "This will exit the program and any unfinished config setup will be lost."
		Write-ColorOutput -ForegroundColor yellow -MessageData "Are you sure you wish to exit?"
		Write-Information ""
		Write-ColorOutput -ForegroundColor green -nonewline -MessageData "[Y]"; Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "es or "; Write-ColorOutput -ForegroundColor red -nonewline -MessageData "[N]"; Write-ColorOutput -ForegroundColor gray -MessageData "o";
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

# Delete userData.json
function resetAll() {
	do {
		Write-Information ""
		Write-ColorOutput -ForegroundColor red -MessageData "**WARNING!!!** This will reset ALL setup progress!"
		Write-ColorOutput -ForegroundColor yellow -MessageData "Do you wish to continue?"
		Write-Information ""
		Write-ColorOutput -ForegroundColor green -nonewline -MessageData "[Y]"; Write-ColorOutput -nonewline -MessageData "es or "; Write-ColorOutput -ForegroundColor red -nonewline -MessageData "[N]"; Write-ColorOutput -MessageData "o";
		$answ = Read-Host
		if (($answ -notlike "y") -And ($answ -notlike "yes") -And ($answ -notlike "n") -And ($answ -notlike "no")) {
			Write-ColorOutput -ForegroundColor red -MessageData "Please specify yes, y, no, or n."
			$valid = $false
		} elseif (($answ -like "y") -Or ($answ -like "yes")) {
			$valid = $true
			Remove-Item $userDataPath
			Exit
		} elseif (($answ -like "n") -Or ($answ -like "no")) {
			$valid = $true
			mainMenu
		}
	} while (-Not($valid))
}

# Print the Sonarr menu and get response
function sonarrMenu() {
	do {
		Write-Information ""
		Write-Information "*****************************************"
		Write-Information "*           Sonarr Setup Menu           *"
		Write-Information "*****************************************"
		Write-ColorOutput -ForegroundColor gray -MessageData "Please choose which version of Sonarr you"
		Write-ColorOutput -ForegroundColor gray -MessageData "would like to configure for MediaButler: "
		Write-Information ""
		Write-ColorOutput -nonewline -MessageData "1) "
		if ($setupChecks.sonarr) {
			Write-ColorOutput -ForegroundColor green -MessageData "Sonarr"
		} else {
			Write-ColorOutput -ForegroundColor red -MessageData "Sonarr"
		}
		Write-ColorOutput -nonewline -MessageData "2) "
		if ($setupChecks.sonarr4k) {
			Write-ColorOutput -ForegroundColor green -MessageData "Sonarr 4K"
		} else {
			Write-ColorOutput -ForegroundColor red -MessageData "Sonarr 4K"
		}
		Write-ColorOutput -nonewline -MessageData "3) "; Write-ColorOutput -ForegroundColor gray -MessageData "Back to Main Menu"
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Selection: "
		$ans = Read-Host
		try {
			$ans = [int]$ans
		} catch {
			[int]$ans = 0
		}
		if (-Not(($ans -ge 1) -And ($ans -le 3))) {
			Write-Information ""
			Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
			$valid = $false
		} elseif (($ans -ge 1) -And ($ans -le 2)) {
			$valid = $true
			setupArr ($ans + 10)
		} elseif ($ans -eq 3) {
			$valid = $true
			mainMenu
		}
	} while (-Not($valid))
}

# Print the Radarr menu and get response
function radarrMenu() {
	do {
		Write-Information ""
		Write-Information "*****************************************"
		Write-Information "*           Radarr Setup Menu           *"
		Write-Information "*****************************************"
		Write-ColorOutput -ForegroundColor gray -MessageData "Please choose which version of Radarr you"
		Write-ColorOutput -ForegroundColor gray -MessageData "would like to configure for MediaButler: "
		Write-Information ""
		Write-ColorOutput -nonewline -MessageData "1) "
		if ($setupChecks.radarr) {
			Write-ColorOutput -ForegroundColor green -MessageData "Radarr"
		} else {
			Write-ColorOutput -ForegroundColor red -MessageData "Radarr"
		}
		Write-ColorOutput -nonewline -MessageData "2) "
		if ($setupChecks.radarr4k) {
			Write-ColorOutput -ForegroundColor green -MessageData "Radarr 4K"
		} else {
			Write-ColorOutput -ForegroundColor red -MessageData "Radarr 4K"
		}
		Write-ColorOutput -nonewline -MessageData "3) "
		if ($setupChecks.radarr3d) {
			Write-ColorOutput -ForegroundColor green -MessageData "Radarr 3D"
		} else {
			Write-ColorOutput -ForegroundColor red -MessageData "Radarr 3D"
		}
		Write-ColorOutput -nonewline -MessageData "4) "; Write-ColorOutput -ForegroundColor gray -MessageData "Back to Main Menu"
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Selection: "
		$ans = Read-Host
		try {
			$ans = [int]$ans
		} catch {
			[int]$ans = 0
		}
		if (-Not(($ans -ge 1) -And ($ans -le 4))) {
			Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
			$valid = $false
		} elseif (($ans -ge 1) -And ($ans -le 3)) {
			$valid = $true
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
		do {
			Write-ColorOutput -ForegroundColor red -MessageData "Tautulli appears to be setup already!"
			Write-ColorOutput -ForegroundColor yellow -MessageData "Do you wish to continue?"
			Write-ColorOutput -ForegroundColor green -nonewline -MessageData "[Y]"; Write-ColorOutput -nonewline -MessageData "es or "; Write-ColorOutput -ForegroundColor red -nonewline -MessageData "[N]"; Write-ColorOutput -MessageData "o";
			$answ = Read-Host
			if (($answ -notlike "y") -And ($answ -notlike "yes") -And ($answ -notlike "n") -And ($answ -notlike "no")) {
				Write-ColorOutput -ForegroundColor red -MessageData "Please specify yes, y, no, or n."
				$valid = $false
			} elseif (($answ -like "y") -Or ($answ -like "yes")) {
				$valid = $true
			} elseif (($answ -like "n") -Or ($answ -like "no")) {
				$valid = $true
				mainMenu
			}
		} while (-Not($valid))
	}
	# Tautulli URL
	do {
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -MessageData "Please enter your Tautulli URL (IE: http://127.0.0.1:8181/tautulli/):"
		$tauURL = Read-Host
		$lastChar = $tauURL.SubString($tauURL.Length - 1)
		if ($lastChar -ne "/") {
			$tauURL = "$tauURL/"
		}
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -MessageData "Checking that the provided Tautulli URL is valid..."
		try {
			$formattedURL = [System.String]::Concat(($tauURL), 'auth/login')
			$response = Invoke-WebRequest -Uri $formattedURL -UseBasicParsing
			[String]$title = $response -split "`n" | Select-String -Pattern '<title>'
		} catch {
			Write-Debug $_.Exception
		}
		if ($title -like "*Tautulli*") {
			Write-ColorOutput -ForegroundColor green -MessageData "Success!"
			$valid = $true
		} else {
			Write-ColorOutput -ForegroundColor red -MessageData "There was an error while attempting to validate the provided URL!"
			$valid = $false
		}
	} while (-Not($valid))

	# API Key
	do {
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -MessageData "Please enter your Tautulli API key"
		$tauAPI = Read-Host -AsSecureString
		$credentials = New-Object System.Management.Automation.PSCredential -ArgumentList "apiKey", $tauAPI
		$tauAPI = $credentials.GetNetworkCredential().Password
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -MessageData "Testing that the provided Tautulli API Key is valid..."
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
			Write-ColorOutput -ForegroundColor red -MessageData "There was an error while attempting to validate the provided API key!"
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
	Write-ColorOutput -ForegroundColor gray -MessageData "Testing the full Tautulli config for MediaButler..."
	try {
		$response = Invoke-WebRequest -Uri $formattedURL -Method PUT -Headers $headers -Body $body -UseBasicParsing
		$response = $response | ConvertFrom-Json
	} catch {
		Write-Debug $_.Exception.Response
	}
	if ($response.message -eq "success") {
		Write-ColorOutput -ForegroundColor green -MessageData "Success!"
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -MessageData "Saving the Tautulli config to MediaButler..."
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
			$setupChecks.tautulli = $true
			Write-Information ""
			Write-ColorOutput -ForegroundColor gray -MessageData "Returning you to the Main Menu..."
			Start-Sleep -s 3
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
	do {
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -MessageData "Please choose which profile you would like to set as the default for MediaButler:"
		$menu = @{}
		$i = 0
		Write-Information ""
		foreach ($prof in $response) {
			$i++
			Write-ColorOutput -nonewline -MessageData "$i) "; Write-ColorOutput -ForegroundColor gray -MessageData "$($prof.name)"
			$menu.Add($i,($prof.name))
		}
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Profile (1-$($i)): "
		$ans = Read-Host
		try {
			$ans = [int]$ans
		} catch {
			[int]$ans = 0
		}
		if (($ans -ge 1) -And ($ans -le $i)) {
			$valid = $true
			$menu.Item($ans)
		} else {
			$valid = $false
			Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
		}
	} while (-Not ($valid))
}

# Print Root Directories in a menu and get response
function arrRootDir($response) {
	do {
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -MessageData "Please choose which root directory you would like to set as the default for MediaButler:"
		$menu = @{}
		$i = 0
		Write-Information ""
		foreach ($rootDir in $response) {
			$i++
			Write-ColorOutput -nonewline -MessageData "$i) "; Write-ColorOutput -ForegroundColor gray -MessageData "$($rootDir.path)"
			$menu.Add($i,($rootDir.path))
		}
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Root Dir (1-$($i)): "
		$ans = Read-Host
		try {
			$ans = [int]$ans
		} catch {
			[int]$ans = 0
		}
		if (($ans -ge 1) -And ($ans -le $i)) {
			$valid = $true
			$menu.Item($ans)
		} else {
			$valid = $false
			Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
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
	if ($setupChecks.Item($endpoint) -eq $true) {
		do {
			Write-ColorOutput -ForegroundColor red -MessageData "$arr appears to be setup already!"
			Write-ColorOutput -ForegroundColor yellow -MessageData "Do you wish to continue?"
			Write-ColorOutput -ForegroundColor green -nonewline -MessageData "[Y]"; Write-ColorOutput -nonewline -MessageData "es or "; Write-ColorOutput -ForegroundColor red -nonewline -MessageData "[N]"; Write-ColorOutput -MessageData "o";
			$answ = Read-Host
			if (($answ -notlike "y") -And ($answ -notlike "yes") -And ($answ -notlike "n") -And ($answ -notlike "no")) {
				Write-ColorOutput -ForegroundColor red -MessageData "Please specify yes, y, no, or n."
				$valid = $false
			} elseif (($answ -like "y") -Or ($answ -like "yes")) {
				$valid = $true
			} elseif (($answ -like "n") -Or ($answ -like "no")) {
				$valid = $true
				if (($ans -gt 10) -And ($ans -lt 20)) {
					sonarrMenu
				} elseif (($ans -gt 20) -And ($ans -lt 30)) {
					radarrMenu
				}
			}
		} while (-Not($valid))
	}
	# URL
	do {
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -MessageData "Please enter your $arr URL (IE: $exURL):"
		$url = Read-Host
		$lastChar = $url.SubString($url.Length - 1)
		if ($lastChar -ne "/") {
			$url = "$url/"
		}
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -MessageData "Checking that the provided $arr URL is valid..."
		try {
			$response = Invoke-WebRequest -Uri $url -UseBasicParsing -MaximumRedirection 0
			[String]$title = $response -split "`n" | Select-String -Pattern '<title>'
		} catch {
			Write-Debug $_.Exception
		}
		if ($title -like "*$arr*") {
			Write-ColorOutput -ForegroundColor green -MessageData "Success!"
			$valid = $true
		} else {
			Write-ColorOutput -ForegroundColor red -MessageData "There was an error while attempting to validate the provided URL!"
			$valid = $false
		}
	} while (-Not($valid))

	# API Key
	Write-Information ""
	Write-ColorOutput -ForegroundColor gray -MessageData  "Please enter your $arr API key"
	do {
		$err = ""
		$apiKey = Read-Host -AsSecureString
		$credentials = New-Object System.Management.Automation.PSCredential -ArgumentList "apiKey", $apiKey
		$apiKey = $credentials.GetNetworkCredential().Password
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -MessageData "Testing that the provided $arr API Key is valid..."
		try {
			$headers = @{
				"X-Api-Key"=$apiKey
			};
			$formattedURL = [System.String]::Concat(($url), 'api/system/status')
			$response = Invoke-WebRequest -Uri $formattedURL -Headers $headers -UseBasicParsing
			$response = $response | ConvertFrom-Json
		} catch {
			$err = $_.Exception.Response.StatusCode
		}
		if ($err -eq "Unauthorized") {
			Write-ColorOutput -ForegroundColor red -MessageData "There was an error while attempting to validate the provided API key!"
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
	Write-ColorOutput -ForegroundColor gray -MessageData "Testing the full $arr config for MediaButler..."
	try {
		$response = Invoke-WebRequest -Uri $formattedURL -Method PUT -Headers $headers -Body $body -UseBasicParsing
		$response = $response | ConvertFrom-Json
	} catch {
		Write-Debug $_.Exception
	}
	if ($response.message -eq "success") {
		Write-ColorOutput -ForegroundColor green -MessageData "Success!"
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -MessageData "Saving the $arr config to MediaButler..."
		try {
			$response = Invoke-WebRequest -Uri $formattedURL -Method POST -Headers $headers -Body $body -UseBasicParsing
			$response = $response | ConvertFrom-Json
		} catch {
			Write-Debug $_.Exception
		}
		if ($response.message -eq "success") {
			Write-ColorOutput -ForegroundColor green -MessageData "Done! $arr has been successfully configured for"
			Write-ColorOutput -ForegroundColor green -MessageData "MediaButler with the $($userData.serverName) Plex server."
			$setupChecks.($endpoint)= $true
			Write-Information ""
			Write-ColorOutput -ForegroundColor gray -MessageData "Returning you to the Main Menu..."
			Start-Sleep -s 3
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


# Submit a TV or Movie Request
function submitRequest() {
	Write-Information ""
	Write-Information "*****************************************"
	Write-Information "*          ~Submit A Request~           *"
	Write-Information "*****************************************"
	Write-ColorOutput -ForegroundColor gray -MessageData "What would you like to request?"
	Write-Information ""
	Write-ColorOutput -nonewline -MessageData "1) "; Write-ColorOutput -ForegroundColor gray -MessageData "TV"
	Write-ColorOutput -nonewline -MessageData "2) "; Write-ColorOutput -ForegroundColor gray -MessageData "Movie"
	Write-ColorOutput -nonewline -MessageData "3) "; Write-ColorOutput -ForegroundColor gray -MessageData "Music"
	Write-ColorOutput -nonewline -MessageData "4) "; Write-ColorOutput -ForegroundColor gray -MessageData "Back to Main Menu"
	Write-Information ""
	do {
		Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Selection: "
		$ans = Read-Host
		if (-Not(($ans -ge 1) -And ($ans -le 4))) {
			Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
			$valid = $false
		} elseif ($ans -eq 1) {
			$valid = $true
			$type="tv"
		} elseif ($ans -eq 2) {
			$valid = $true
			$type="movie"
		} elseif ($ans -eq 3) {
			$valid = $true
			$type="music"
			Write-ColorOutput -ForegroundColor red -MessageData "Not configured yet!"
			resultsMenu
		} elseif ($ans -eq 4) {
			$valid = $true
			mainMenu
		}
	} while (-Not($valid))
	Write-Information ""
	if ($type -eq "tv") {
		Write-ColorOutput -ForegroundColor gray -MessageData "What show would you like to request?"
	} elseif ($type -eq "movie") {
		Write-ColorOutput -ForegroundColor gray -MessageData "What movie would you like to request?"
	} elseif ($type -eq "music") {
		Write-ColorOutput -ForegroundColor gray -MessageData "What music would you like to request?"
	}
	$ans = Read-Host
	$headers = @{
		"Content-Type"="application/json"
		"MB-Client-Identifier"=$uuid;
		"Authorization"="Bearer " + $userData.mbToken;
	};
	$formattedURL = [System.String]::Concat(($userData.mbURL), ($type), "?query=", $ans)
	try {
		$response = Invoke-WebRequest -Uri $formattedURL -Method GET -Headers $headers -UseBasicParsing
		$response = $response | ConvertFrom-Json
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -MessageData "Here are your results:"
		Write-Information ""
		$menu = @{}
		$i = 0
		foreach ($result in $response.results) {
			$i++
			if ($type -eq "tv") {
				Write-ColorOutput -nonewline -MessageData "$i) "; Write-ColorOutput -ForegroundColor gray -MessageData "$($result.seriesName)"
				$resultInfo = @{"title"="$($result.seriesName)"; "id"="$($result.id)";};
			} elseif ($type -eq "movie") {
				Write-ColorOutput -nonewline -MessageData "$i) "; Write-ColorOutput -ForegroundColor gray -MessageData "$($result.title) ($($result.year))"
				$resultInfo = @{"title"="$($result.title)"; "id"="$($result.imdbid)";};
			}
			$menu.Add($i,($resultInfo))
		}
		$i++
		Write-ColorOutput -nonewline -MessageData "$i) "; Write-ColorOutput -ForegroundColor gray -MessageData "Cancel"
		$resultInfo = @{"title"="Cancel"; "id"="Cancel";};
		$menu.Add($i,($resultInfo))
		do {
			Write-Information ""
			Write-ColorOutput -ForegroundColor gray -MessageData "Which would you like to request?"
			Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Selection (1-$($i)): "
			$ans = Read-Host
			try {
				$ans = [int]$ans
			} catch {
				[int]$ans = 0
			}
			if ($ans -ge 1 -And $ans -lt $i) {
				$id = $menu.Item($ans).id
				$title = $menu.Item($ans).title
				$valid = $true
			} elseif ($ans -eq $i) {
				$valid = $true
				requestsMenu
			} else {
				$valid = $false
				Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
			}
		} while (-Not($valid))
	} catch {
		Write-Debug $_.Exception
	}
	Write-Information ""
	Write-ColorOutput -ForegroundColor gray -MessageData "Submitting your request..."
	try {
		$body = @{}
		if ($type -eq "tv") {
			$body = @{
				"type"=$type;
				"title"=$title
				"tvdbId"=$id
			};
		} elseif ($type -eq "movie") {
			$body = @{
				"type"=$type;
				"title"=$title
				"imdbId"=$id
			};
		}
		$body = $body | ConvertTo-Json
		$formattedURL = [System.String]::Concat(($userData.mbURL), "requests")
		$response = Invoke-WebRequest -Uri $formattedURL -Method POST -Headers $headers -Body $body -ContentType "application/json"  -UseBasicParsing
		Write-ColorOutput -ForegroundColor green -MessageData "Success! $title has been requested."
	} catch {
		Write-Debug $_.ErrorDetails.Message
		$err = $_.ErrorDetails.Message | ConvertFrom-Json
		if ($err.message -eq "Item Exists") {
			Write-ColorOutput -ForegroundColor red -MessageData "$title already exists on Plex!"
		} elseif ($err.message -eq "Request already exists") {
			Write-ColorOutput -ForegroundColor red -MessageData "$title has already been requested!"
		}
	}
	Write-Information ""
	Write-ColorOutput -ForegroundColor gray -MessageData "Returning you to the Requests Menu..."
	Start-Sleep -s 3
	requestsMenu
}

# View Requests
function manageRequests() {
	$headers = @{
		"Content-Type"="application/json"
		"MB-Client-Identifier"=$uuid;
		"Authorization"="Bearer " + $userData.mbToken;
	};
	$formattedURL = [System.String]::Concat(($userData.mbURL), "requests")
	Write-Information ""
	Write-ColorOutput -ForegroundColor gray -MessageData "Here are the current requests:"
	$menu = @{}
	$i = 0
	try {
		$response = Invoke-WebRequest -Uri $formattedURL -Method GET -Headers $headers -ContentType "application/json"  -UseBasicParsing
		$response = $response | ConvertFrom-Json
		foreach ($request in $response) {
			$i++
			Write-ColorOutput -nonewline -MessageData "$i) "; Write-ColorOutput -ForegroundColor gray -MessageData "$($request.title)"
			$requestInfo = @{"title"="$($request.title)"; "id"="$($request._id)"; "requestedBy"="$($request.username)"; "requestedDate"="$($request.dateAdded)"; "requestStatus"="$($request.status)";};
			$menu.Add($i,($requestInfo))
		}
		$i++
		Write-ColorOutput -nonewline -MessageData "$i) "; Write-ColorOutput -ForegroundColor gray -MessageData "Cancel"
		$resultInfo = @{"title"="Cancel"; "id"="Cancel";};
		$menu.Add($i,($resultInfo))
	} catch {
		Write-Debug $_.Exception
	}
	do {
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -MessageData "Which request would you like to manage?"
		Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Selection (1-$($i)): "
		$ans = Read-Host
		try {
			$ans = [int]$ans
		} catch {
			[int]$ans = 0
		}
		if ($ans -ge 1 -And $ans -lt $i) {
			$valid = $true
			$id = $menu.Item($ans).id
			$title = $menu.Item($ans).title
			$requestedBy = $menu.Item($ans).requestedBy
			$requestedDate = $menu.Item($ans).requestedDate
			$requestStatus = $menu.Item($ans).requestStatus
		} elseif ($ans -eq $i) {
			$valid = $true
			requestsMenu
		} else {
			$valid = $false
			Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
		}
	} while (-Not($valid))
	Write-Information ""
	Write-Information "Request information:"
	Write-Information ""
	Write-ColorOutput -ForegroundColor magenta -nonewline -MessageData "Title: "; Write-ColorOutput -ForegroundColor gray -MessageData $title
	Write-ColorOutput -ForegroundColor magenta -nonewline -MessageData "Submitted By: "; Write-ColorOutput -ForegroundColor gray -MessageData $requestedBy
	Write-ColorOutput -ForegroundColor magenta -nonewline -MessageData "Date Requested: "; Write-ColorOutput -ForegroundColor gray -MessageData $requestedDate.SubString(0,10)
	Write-ColorOutput -ForegroundColor magenta -nonewline -MessageData "Request Status: "
	if ($requestStatus -eq '0') {
		Write-ColorOutput -ForegroundColor red -MessageData "Pending"
	} elseif ($requestStatus -eq '1') {
		Write-ColorOutput -ForegroundColor darkcyan -MessageData "Downloading"
	} elseif ($requestStatus -eq '2') {
		Write-ColorOutput -ForegroundColor yellow -MessageData "Partially Filled"
	} elseif ($requestStatus -eq '3') {
		Write-ColorOutput -ForegroundColor green -MessageData "Filled"
	}
	do {
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -MessageData "What would you like to do with this request?"
		Write-Information ""
		Write-ColorOutput -nonewline -MessageData "1) "; Write-ColorOutput -ForegroundColor gray -MessageData "Approve Request"
		Write-ColorOutput -nonewline -MessageData "2) "; Write-ColorOutput -ForegroundColor gray -MessageData "Deny Request"
		Write-ColorOutput -nonewline -MessageData "3) "; Write-ColorOutput -ForegroundColor gray -MessageData "Back to Manage Requests"
		Write-Information ""
		Write-ColorOutput -ForegroundColor gray -nonewline -MessageData "Selection: "
		$ans = Read-Host
		try {
			$ans = [int]$ans
		} catch {
			[int]$ans = 0
		}
		if (-Not(($ans -ge 1) -And ($ans -le 3))) {
			$valid = $false
			Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
		} elseif ($ans -eq 1) {
			$valid = $true
			$formattedURL = [System.String]::Concat(($userData.mbURL), "requests/", ($id))
			try {
				$response = Invoke-WebRequest -Uri $formattedURL -Method POST -Headers $headers -ContentType "application/json"  -UseBasicParsing
				$response = $response | ConvertFrom-Json
				Write-ColorOutput -ForegroundColor green -MessageData "Success! The request for $title has been approved."
				Write-Information ""
				Write-ColorOutput -ForegroundColor gray -MessageData "Returning you to the Requests Menu..."
				Start-Sleep -s 3
			} catch {
				Write-Debug $_.Exception
			}
			requestsMenu
		} elseif ($ans -eq 2) {
			$valid = $true
			$formattedURL = [System.String]::Concat(($userData.mbURL), "requests/", ($id))
			try {
				$response = Invoke-WebRequest -Uri $formattedURL -Method DEL -Headers $headers -ContentType "application/json"  -UseBasicParsing
				$response = $response | ConvertFrom-Json
				Write-ColorOutput -ForegroundColor green -MessageData "Requset has been sucessfully removed!"
				Write-Information ""
				Write-ColorOutput -ForegroundColor gray -MessageData "Returning you to the Requests Menu..."
				Start-Sleep -s 3
			} catch {
				Write-Debug $_.Exception
			}
			requestsMenu
		} elseif ($ans -eq 3) {
			$valid = $true
			requestsMenu
		}
	} while (-Not($valid))
}

<#function addIssue() {
	Write-Information ""
	Write-Information "What is your issue?"
	$ans = Read-Host
	$headers = @{
		"Content-Type"="application/json"
		"MB-Client-Identifier"=$uuid;
		"Authorization"="Bearer " + $userData.mbToken;
	};
	$body = @{
		"issue"=$ans
	};
	$formattedURL = [System.String]::Concat(($userData.mbURL), "/issue")
	try {
		$response = Invoke-WebRequest -Uri $formattedURL -Method POST -Headers $headers -UseBasicParsing
		$response = $response | ConvertFrom-Json
		Write-Information ""
		Write-Information "Here are your results:"
		$menu = @{}
		$i = 0
		foreach ($result in $response.results) {
			$i++
			Write-Information "$i. $($result.seriesName)"
			$resultInfo = @{"title"="$($result.seriesName)"; "id"="$($result.id)";};
			$menu.Add($i,($resultInfo))
		}
		Write-Information ""
		Write-Information "Which would you like to request?"
		$ans = Read-Host
		$ans = [int]$ans
		if ($ans -ge 1 -And $ans -le $i) {
			$id = $menu.Item($ans).id
			$title = $menu.Item($ans).title
		} else {
			Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
			requestsMenu
		}
	} catch {
		Write-Debug $_.Exception
	}
	Write-Information ""
	Write-Information "Sending your issue to the server..."
	try {
		$body = @{}
		if ($type -eq "tv") {
			$body = @{
				"type"=$type;
				"title"=$title
				"tvdbId"=$id
			};
		} elseif ($type -eq "movie") {
			$body = @{
				"type"=$type;
				"title"=$title
			};
		}
		$body = $body | ConvertTo-Json
		$formattedURL = [System.String]::Concat(($userData.mbURL), "requests")
		$response = Invoke-WebRequest -Uri $formattedURL -Method POST -Headers $headers -Body $body -ContentType "application/json"  -UseBasicParsing
		Write-ColorOutput -ForegroundColor green -MessageData "Success! $title has been requested."
	} catch {
		Write-Debug $_.ErrorDetails.Message
		$error = $_.ErrorDetails.Message | ConvertFrom-Json
		if ($error.message -eq "Item Exists") {
			Write-ColorOutput -ForegroundColor red -MessageData "$title has already been added."
		} elseif ($error.message -eq "Request already exists") {
			Write-ColorOutput -ForegroundColor red -MessageData "$title has already been requested."
		}
	}
	Write-Information "Returning you to the Issues Menu..."
	Start-Sleep -s 3
	issuesMenu
}

# View Requests
function manageIssues() {
	$headers = @{
		"Content-Type"="application/json"
		"MB-Client-Identifier"=$uuid;
		"Authorization"="Bearer " + $userData.mbToken;
	};
	$formattedURL = [System.String]::Concat(($userData.mbURL), "requests")
	Write-Information ""
	Write-Information "Here are the current requests:"
	$menu = @{}
	$i = 0
	try {
		$response = Invoke-WebRequest -Uri $formattedURL -Method GET -Headers $headers -ContentType "application/json"  -UseBasicParsing
		$response = $response | ConvertFrom-Json
		foreach ($issue in $response) {
			$i++
			Write-Information "$i. $($issue.title) ($($issue.type)) requested by $($issue.username)"
			$requestInfo = @{"title"="$($issue.title)"; "id"="$($issue._id)";};
			$menu.Add($i,($requestInfo))
		}
	} catch {
		Write-Debug $_.Exception
	}
	Write-Information ""
	Write-Information "Which request would you like to manage?"
	$ans = Read-Host
	$ans = [int]$ans
	if ($ans -ge 1 -And $ans -le $i) {
		$id = $menu.Item($ans).id
		$title = $menu.Item($ans).title
	} else {
		Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
		Start-Sleep -s 3
		requestsMenu
	}
	Write-Information ""
	Write-Information "What would you like to do?"
	Write-Information ""
	Write-Information "1. Delete"
	Write-Information "2. To be added"
	Write-Information ""
	$ans = Read-Host 'Enter selection'
	if (-Not(($ans -ge 1) -And ($ans -le 2))) {
		Write-ColorOutput -ForegroundColor red -MessageData "You did not specify a valid option!"
		requestsMenu
	} elseif ($ans -eq 1) {
		Write-Information ""
		Write-Information "Are you sure you want to delete this request?"
		Write-Information ""
		Write-ColorOutput -ForegroundColor green -nonewline -MessageData "[Y]"; Write-ColorOutput -nonewline -MessageData "es or "; Write-ColorOutput -ForegroundColor red -nonewline -MessageData "[N]"; Write-ColorOutput -MessageData "o";
		$valid = $false
		do {
			$answ = Read-Host
			if (($answ -notlike "y") -And ($answ -notlike "yes") -And ($answ -notlike "n") -And ($answ -notlike "no")) {
				Write-ColorOutput -ForegroundColor red -MessageData "Please specify yes, y, no, or n."
				$valid = $false
			} elseif (($answ -like "y") -Or ($answ -like "yes")) {
				$valid = $true
				$formattedURL = [System.String]::Concat(($userData.mbURL), "issues/", ($id))
				try {
					$response = Invoke-WebRequest -Uri $formattedURL -Method DEL -Headers $headers -ContentType "application/json"  -UseBasicParsing
					$response = $response | ConvertFrom-Json
					Write-ColorOutput -ForegroundColor green -nonewline -MessageData "Success! The request for $title has been deleted."
					Write-Information ""
					Write-Information "Returning you to the Requests Menu..."
					Start-Sleep -s 3
					requestsMenu
				} catch {
					Write-Debug $_.Exception
				}
				requestsMenu
			} else {
				Write-Information "Returning you to the Requests Menu..."
				Start-Sleep -s 3
				requestsMenu
			}
		} while (-Not ($valid))
	} elseif ($ans -eq 2) {
		requestsMenu
	}
}#>

# Print the playback history for the current user/server
function playbackHistory() {
	$headers = @{
		"Content-Type"="application/json"
		"MB-Client-Identifier"=$uuid;
		"Authorization"="Bearer " + $userData.mbToken;
	};
	$formattedURL = [System.String]::Concat(($userData.mbURL), "tautulli/history")
	try {
		$response = Invoke-WebRequest -Uri $formattedURL -Method GET -Headers $headers -UseBasicParsing
		$response = $response | ConvertFrom-Json
		Write-Information ""
		Write-ColorOutput -ForegroundColor blue -MessageData "============================================================"
		if (-Not [string]::IsNullOrEmpty($response.response.data.data)) {
			[Int]$count = [String]$response.response.data.total_duration.length
			if ($count -le 8) {
				$tabs = "`t`t`t`t"
			} elseif ($count -gt 8 -And $count -le 16) {
				$tabs = "`t`t`t"
			} elseif ($count -gt 16 -And $count -le 24) {
				$tabs = "`t`t"
			} elseif ($count -gt 24) {
				$tabs = "`t"
			}
			Write-Information "Total Duration`t`t`tShown Duration"
			Write-ColorOutput -ForegroundColor green -MessageData "$($response.response.data.total_duration)$($tabs)$($response.response.data.filter_duration)"
			foreach ($item in $response.response.data.data) {
				if ($item.media_type -eq "movie") {
					$title = "$($item.full_title) ($($item.year))"
				} elseif ($item.media_type -eq "Episode") {
					$season = [String]$item.parent_media_index
					$episode = [String]$item.media_index
					$title = "$($item.full_title) - S$($season.PadLeft(2,'0'))E$($episode.PadLeft(2,'0'))"
				} elseif ($item.media_type -eq "track") {
					$title = "$($item.full_title)"
				}
				[Int]$duration = [Int]$item.stopped - [Int]$item.started
				[Int]$mins = $duration/60
				[Int]$secs = $duration%60
				$friendlyDuration = "[$($mins)m $($secs)s]"
				$playbackType = (Get-Culture).TextInfo.ToTitleCase($item.transcode_decision)
				Write-Information $title
				Write-ColorOutput -ForegroundColor darkgray -MessageData "$($playbackType) - $($item.platform) - $($item.player) $friendlyDuration"
			}
			Write-ColorOutput -ForegroundColor blue -MessageData "============================================================"
		} else {
			Write-Information ""
			Write-ColorOutput -ForegroundColor yellow -MessageData "There is no playback history at this time."
		}
	} catch {
		Write-Debug $_.Exception
	}
	playbackMenu
}

# Get what is currently playing on the server
function nowPlaying() {
	$headers = @{
		"Content-Type"="application/json"
		"MB-Client-Identifier"=$uuid;
		"Authorization"="Bearer " + $userData.mbToken;
	};
	$formattedURL = [System.String]::Concat(($userData.mbURL), "tautulli/activity")
	try {
		$response = Invoke-WebRequest -Uri $formattedURL -Method GET -Headers $headers -UseBasicParsing
		$response = $response | ConvertFrom-Json
		if (-Not [string]::IsNullOrEmpty($response.data.sessions)) {
			foreach ($session in $response.data.sessions) {
				if ($session.media_type -eq "episode") {
					$title = "$($session.grandparent_title) - S$($session.parent_media_index.PadLeft(2,'0'))E$($session.media_index.PadLeft(2,'0')) - $($session.title)"
				} elseif ($session.media_type -eq "movie") {
					$title = "$($session.title) ($($session.year))"
				} elseif ($session.media_type -eq "track") {
					$title = "$($session.grandparent_title) - $($session.parent_title) - $($session.title)"
				}
				$state = (Get-Culture).TextInfo.ToTitleCase($session.state)
				$playbackType = (Get-Culture).TextInfo.ToTitleCase($session.transcode_decision)
				Write-Information ""
				Write-ColorOutput -ForegroundColor blue -MessageData "============================================================"
				Write-ColorOutput -ForegroundColor magenta -nonewline -MessageData "Playback: "; Write-Information $state
				Write-ColorOutput -ForegroundColor magenta -nonewline -MessageData "User: "; Write-Information $session.username
				Write-ColorOutput -ForegroundColor magenta -nonewline -MessageData "IP Address: "; Write-Information $session.ip_address
				Write-ColorOutput -ForegroundColor magenta -nonewline -MessageData "Device: "; Write-Information $session.device
				Write-ColorOutput -ForegroundColor magenta -nonewline -MessageData "Playing: "; Write-Information $title
				Write-ColorOutput -ForegroundColor magenta -nonewline -MessageData "Playback Type: "; Write-Information $playbackType
				Write-ColorOutput -ForegroundColor magenta -nonewline -MessageData "Profile: "; Write-Information $session.quality_profile
				Write-ColorOutput -ForegroundColor magenta -nonewline -MessageData "Session Key: "; Write-Information $session.session_key
				Write-ColorOutput -ForegroundColor blue -MessageData "============================================================"
			}
		} else {
			Write-Information ""
			Write-ColorOutput -ForegroundColor yellow -MessageData "There are no active streams at this time."
		}
	} catch {
		Write-Information $_.Exception
	}
	playbackMenu
}

function main () {
	checkUserData
	checkPlexAuth
	chooseServer
	getMbURL
	checkAdmin
	if ($isAdmin) {
		setupChecks
	}
	mainMenu
}

main