# Setup initial variables
$uuid = "fb67fb8b-9000-4a70-a67b-2f2b626780bb"
$userDataPath = '.\userData.json'
$plexLoginURL = "https://plex.tv/users/sign_in.json"
$mbLoginURL = "https://auth.mediabutler.io/login"
$mbDiscoverURL = "https://auth.mediabutler.io/login/discover"

# Function for logging into Plex with a Username/Password
# This will loop until valid credentials are provided
# Returns Plex authToken
function plexLogin() {
	$failedLogin = $false
	$authToken = ""
	do {
		try {
			# Reset variables
			$failedLogin = $false
			$err = ""
			
			# Prompt for Username/Password
			Write-Host ""
			$plexusername = Read-Host -Prompt 'Plex Username'
			$plexpassword = Read-Host -Prompt 'Plex Password' -AsSecureString
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
			}
			$body = $body | ConvertTo-Json

			$response = Invoke-WebRequest -Uri $plexLoginURL -Method POST -Headers $headers -Body $body -ContentType "application/json"
			$response = $response | ConvertFrom-Json
			$authToken = $response.user.authToken
		} catch [System.Net.WebException] {
			$err = $_.Exception.Response.StatusCode
			$failedLogin = $true
			if ($err -eq "Unauthorized") {
				Write-Host -ForegroundColor Red -BackgroundColor Black "Invalid Credentials"
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
			"MB-Client-Identifier"="$uuid"; 
		};
		$body = @{
			"authToken"="$authToken";
		}; 
		$body = $body | ConvertTo-Json
		$response = Invoke-WebRequest -Uri $mbLoginURL -Method POST -Headers $headers -Body $body -ContentType "application/json"
		
		# Convert to Array so it can be used
		$response = $response | ConvertFrom-Json
		$response
		
	} catch [System.Net.WebException] {
		$response
	}
}

# Takes a MediaButler url and tests it for the API version. If that doesn't come back with an API version above 1.1.12, it's not MediaButler
# Returns $true or $false
function testMB($url) {
	$isMB = $false
	try {
		$response = Invoke-WebRequest -Uri $url/version
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

# Check if userData.json exists
# Returns the array of the User Data
function checkUserData () {
	if (Test-Path $userDataPath -PathType Leaf) {
		$fileIn = Get-Content -Raw -Path $userDataPath | ConvertFrom-Json
		$fileIn.psobject.properties | Foreach-Object { $userData[$_.Name] = $_.Value }
	}
}

# Check if Plex Auth Token is saved in userData and if not print menu and get it from user
function checkPlexAuth() {
	if ([string]::IsNullOrEmpty($userData.authToken)) {
		Write-Host "First thing we need are your Plex credentials so please choose from one of the following options:"
		Write-Host ""
		Write-Host "1. Plex Username and Password"
		Write-Host "2. Plex token"
		Write-Host ""

		$valid = $false
		do {
			[int]$ans = Read-Host 'Enter selection'
			if ($ans -eq 1) {
				$userData.authToken = plexLogin
				$mbLoginResponse = mbLogin $userdata.authToken
				$valid = $true
			} elseif ($ans -eq 2) {
				do {
					Write-Host ""
					$authTokenEnc = Read-Host -Prompt 'Plex Auth Token' -AsSecureString
					$credentials = New-Object System.Management.Automation.PSCredential -ArgumentList "token", $authTokenEnc
					$userdata.authToken = $credentials.GetNetworkCredential().Password
					$mbLoginResponse = mbLogin $userdata.authToken
					if([string]::IsNullOrEmpty($mbLoginResponse)) {
						Write-Host -ForegroundColor Red -BackgroundColor Black "Invalid Plex Auth Token"
					}
				} while([string]::IsNullOrEmpty($mbLoginResponse))
				$valid = $true
			} else {
				Write-Host -ForegroundColor Red -BackgroundColor Black "Invalid Response. Please try again."
			}
		} while (-Not ($valid))
		$userData | ConvertTo-Json | Out-File -FilePath $userDataPath
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
		Write-Host ""
		Write-Host "Please choose which Plex Server you would like to setup MediaButler for:"
		$menu = @{}
		foreach ($server in $mbLoginResponse.servers) { 
			try {
				$owner = [System.Convert]::ToBoolean($server.owner) 
			} catch [FormatException] {
				$owner = $false
			}
			if($owner) {
				$i++
				Write-Host "$i. $($server.name)"
				$serverInfo = @{"serverName"="$($server.name)"; "machineId"="$($server.machineId)"; "mbToken"="$($server.token)";};
				$menu.Add($i,($serverInfo))
			}
		}
		[int]$ans = Read-Host 'Enter selection'
		$userData.serverName = $menu.Item($ans).serverName
		$userData.machineId = $menu.Item($ans).machineId
		$userData.mbToken = $menu.Item($ans).mbToken
		$userData | ConvertTo-Json | Out-File -FilePath $userDataPath
	}
}

# Get MediaButler URL
function getMbURL () {
	if ([string]::IsNullOrEmpty($userData.mbURL)) {
		# Test if localhost is MediaButler server
		$isMB = $false;
		# Use Plex token and Machine ID to get URL
		try {
			if (testMB http://127.0.0.1:9876/) {
				$mbURL = http://127.0.0.1:9876/
			} else {
				$headers = @{
					"MB-Client-Identifier"="$uuid"; 
				};
				$body = @{
					"authToken"="$userData.authToken";
					"machineId"="$userData.machineId";
				}; 
				$body = $body | ConvertTo-Json
				$mbURL = Invoke-WebRequest -Uri $mbDiscoverURL -Method POST -Headers $headers -Body $body -ContentType "application/json"
			}
			Write-Host "Is this the correct MediaButler URL?"
			Write-Host -ForegroundColor Yellow $mbURL
			Write-Host ""
			Write-Host -nonewline -ForegroundColor Green "[Y]";Write-Host -nonewline "es or ";Write-Host -nonewline -ForegroundColor Red "[N]";Write-Host "o"
			$valid = $false
			do {
				$ans = Read-Host
				if (($ans -notlike "y") -And ($ans -notlike "yes") -And ($ans -notlike "n") -And ($ans -notlike "no")) {
					Write-Host -ForegroundColor Red -BackgroundColor Black "Please specify yes, y, no, or n."
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
				$isMB = testMB $mbURL;
				if(-Not ($isMB)) {
					Write-Host "Invalid Server URL"
				}
			} while(-Not ($isMB));
			$lastChar = $mbURL.SubString($mbURL.Length - 1)
			if ($lastChar -ne "/") {
				$mbURL = "$mbURL/"
			}
			$userData.mbURL = $mbURL
		}
		$userData | ConvertTo-Json | Out-File -FilePath $userDataPath
	}
}


# Print the main menu
# Returns selection
function mainMenu() {
	Write-Host ""
	Write-Host "*****************************************"
	Write-Host "*               Main Menu               *"
	Write-Host "*****************************************"
	Write-Host "Please choose which application you would"
	Write-Host "   like to configure for MediaButler:    "
	Write-Host ""
	Write-Host "1. Sonarr"
	Write-Host "2. Radarr"
	Write-Host "3. Tautulli"
	Write-Host "4. Exit"
	Write-Host ""
	[int]$ans = Read-Host 'Enter selection'
	$ans
}

function exitMenu() {
	
}

# Print the Sonarr menu and get response
function sonarrMenu() {
	Write-Host "*****************************************"
	Write-Host "*           Sonarr Setup Menu           *"
	Write-Host "*****************************************"
	Write-Host "Please choose which version of Sonarr you"
	Write-Host "would like to configure for MediaButler: "
	Write-Host ""
	Write-Host "1. Sonarr"
	Write-Host "2. Sonarr 4K"
	Write-Host "3. Back to Main Menu"
	Write-Host ""
	do {
		[int]$ans = Read-Host 'Enter selection'
		if (-Not(($ans -ge 1) -And ($ans -le 3))) {
			Write-Host -ForegroundColor Red -BackgroundColor Black "You did not specify a valid option!"
			$valid = $false
		} elseif (($ans -eq 1) -Or ($ans -eq 2)) {
			setupSonarr $ans $userData
		} elseif ($ans -eq 3) {
			$valid = $true
			# Back to Main menu
		}
	} while(-Not($valid))	
}

# Print the Radarr menu and get response
function radarrMenu() {
	Write-Host "*****************************************"
	Write-Host "*           Radarr Setup Menu           *"
	Write-Host "*****************************************"
	Write-Host "Please choose which version of Radarr you"
	Write-Host "would like to configure for MediaButler: "
	Write-Host ""
	Write-Host "1. Radarr"
	Write-Host "2. Radarr 4K"
	Write-Host "3. Radarr 3D"
	Write-Host "4. Back to Main Menu"
	Write-Host ""
	do {
		[int]$ans = Read-Host 'Enter selection'
		if (-Not(($ans -ge 1) -And ($ans -le 4))) {
			Write-Host -ForegroundColor Red -BackgroundColor Black "You did not specify a valid option!"
			$valid = $false
		} elseif (($ans -ge 1) -Or ($ans -le 3)) {
			setupRadarr $ans $userData
		} elseif ($ans -eq 4) {
			$valid = $true
			# Back to Main menu
		}
	} while(-Not($valid))	
}

# Function to get the Tautulli information, test it and send it to the MediaButler server
function setupTautulli() {
	# Tautulli URL
	Write-Host ""
	Write-Host "Please enter your Tautulli URL (IE: http://127.0.0.1:8181/tautulli/):"
	do {
		$tauURL = Read-Host -Prompt "URL"
		$lastChar = $tauURL.SubString($tauURL.Length - 1)
		if ($lastChar -ne "/") {
			$tauURL = "$tauURL/"
		}
		Write-Host "Checking that the provided Tautulli URL is valid..."
		try {
			$response = Invoke-WebRequest -Uri $tauURL"auth/login" -Method Head
		} catch {}
		if ($response.statuscode -eq "200") {
			Write-Host -ForegroundColor Green "Success!"
			$valid = $true
		} else {
			Write-Host -ForegroundColor Red -BackgroundColor Black "Received something other than a 200 OK response!"
			$valid = $false
		}
	} while (-Not($valid))
	
	# API Key
	Write-Host ""
	Write-Host "Please enter your Tautulli API key"
	do {
		$tauAPI = Read-Host -Prompt "API"
		Write-Host ""
		Write-Host "Testing that the provided Tautulli API Key is valid..."
		try {
			$response = Invoke-WebRequest -Uri $tauURL"api/v2?apikey="$tauAPI"&cmd=arnold"
			$response = $response | ConvertFrom-Json
		} catch {}
		if ($response.response.message -eq $null) {
			Write-Host -ForegroundColor Green "Success!"
			$valid = $true
		} else {
			Write-Host -ForegroundColor Red -BackgroundColor Black "Received something other than an OK response!"
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
	Write-Host ""
	Write-Host "Testing the full Tautulli config for MediaButler..."
	try {
		$response = Invoke-WebRequest -Uri $formattedURL -Method PUT -Headers $headers -Body $body
		$response = $response | ConvertFrom-Json
	} catch {}
	if ($response.message -eq "success") {
		Write-Host -ForegroundColor Green "Success!"
		Write-Host ""
		Write-Host "Saving the Tautulli config to MediaButler..."
		try {
			$response = Invoke-WebRequest -Uri $formattedURL -Method POST -Headers $headers -Body $body
			$response = $response | ConvertFrom-Json
		} catch {}
		if ($response.message -eq "success") {
			Write-Host -ForegroundColor Green "Done! Tautulli has been successfully configured for"
			Write-Host -ForegroundColor Green "MediaButler with the"$userData.serverName"Plex server."
			Start-Sleep -s 3
			Write-Host Returning you to the Main Menu...
		}  elseif ($response.message -ne "success") {
			Write-Host -ForegroundColor Red "Config push failed! Please try again later."
			Start-Sleep -s 3
		}
	} elseif ($response.message -ne "success") {
		Write-Host -ForegroundColor Red -BackgroundColor Black "Hmm, something weird happened. Please try again."
		Start-Sleep -s 3
	}
}

# Fucntion to get a list of Profiles from *arr and create a menu for the user to pick from
# Returns selected profile name
function arrProfiles($response) {
	Write-Host ""
	Write-Host "Please choose which profile you would like to set as the default for MediaButler:"
	$menu = @{}
	$i = 0
	foreach ($profile in $response) { 
		$i++
		Write-Host "$i. $($profile.name)"
		$menu.Add($i,($profile.name))
	}
	do {
		[int]$ans = Read-Host 'Profile'
		if (($ans -ge 1) -And ($ans -le $i)) {
			$valid = $true
			$menu.Item($ans)
		} else {
			$valid = $false
			Write-Host -ForegroundColor Red -BackgroundColor Black "Invalid Response."
		}
	} while(-Not ($valid))
}

function arrRootDir($response) {
	Write-Host ""
	Write-Host "Please choose which root directory you would like to set as the default for MediaButler:"
	$menu = @{}
	$i = 0
	foreach ($rootDir in $response) { 
		$i++
		Write-Host "$i. $($rootDir.path)"
		$menu.Add($i,($rootDir.path))
	}
	do {
		[int]$ans = Read-Host 'Profile'
		if (($ans -ge 1) -And ($ans -le $i)) {
			$valid = $true
			$menu.Item($ans)
		} else {
			$valid = $false
			Write-Host -ForegroundColor Red -BackgroundColor Black "Invalid Response."
		}
	} while(-Not ($valid))
}

# Function to set up Sonarr
function setupSonarr($ans) {
	# Sonarr URL
	Write-Host ""
	Write-Host "Please enter your Sonarr URL (IE: http://127.0.0.1:8989/sonarr/):"
	do {
		$sonarrURL = Read-Host -Prompt "URL"
		$lastChar = $sonarrURL.SubString($sonarrURL.Length - 1)
		if ($lastChar -ne "/") {
			$sonarrURL = "$sonarrURL/"
		}
		Write-Host "Checking that the provided Sonarr URL is valid..."
		try {
			$response = Invoke-WebRequest -Uri $sonarrURL"auth/login" -Method Head
		} catch {}
		if ($response.statuscode -eq "200") {
			Write-Host -ForegroundColor Green "Success!"
			$valid = $true
		} else {
			Write-Host -ForegroundColor Red -BackgroundColor Black "Received something other than a 200 OK response!"
			$valid = $false
		}
	} while (-Not($valid))
	
	# API Key
	Write-Host ""
	Write-Host "Please enter your Sonarr API key"
	do {
		$err = ""
		$sonarrAPI = Read-Host -Prompt "API"
		Write-Host ""
		Write-Host "Testing that the provided Sonarr API Key is valid..."
		try {
			$headers = @{
				"X-Api-Key"=$sonarrAPI
			};
			$response = Invoke-WebRequest -Uri $sonarrURL"api/system/status" -Headers $headers
			$response = $response | ConvertFrom-Json
		} catch {
			$err = $_.Exception.Response.StatusCode
		}
		if ($err -eq "Unauthorized") {
			Write-Host -ForegroundColor Red -BackgroundColor Black "Received something other than an OK response!"
			$valid = $false
		} else {
			Write-Host -ForegroundColor Green "Success!"
			$valid = $true
		}
	} while (-Not($valid))

	# Default Profile
	try {
		$headers = @{
			"X-Api-Key"=$sonarrAPI
		};
		$response = Invoke-WebRequest -Uri $sonarrURL"api/profile" -Headers $headers
		$response = $response | ConvertFrom-Json
		$sonarrProfile = arrProfiles $response
	} catch {
		Write-Host -ForegroundColor Red -BackgroundColor Black "Something went wrong..."
	}

	# Default Root Directory
	try {
		$headers = @{
			"X-Api-Key"=$sonarrAPI
		};
		$response = Invoke-WebRequest -Uri $sonarrURL"api/rootfolder" -Headers $headers
		$response = $response | ConvertFrom-Json
		$sonarrRootDir = arrRootDir $response
	} catch {
		Write-Host -ForegroundColor Red -BackgroundColor Black "Something went wrong..."
	}

	# Set MediaButler formatting
	if($ans -eq 1) {
		$endpoint = "sonarr"
	} elseif ($ans -eq 2) {
		$endpoint = "sonarr4k"
	}
	$headers = @{
		"Content-Type"="application/json"
		"MB-Client-Identifier"=$uuid; 
		"Authorization"="Bearer " + $userData.mbToken;
	};
	$body = @{
		"url"=$sonarrURL;
		"apikey"=$sonarrAPI;
		"defaultProfile"=$sonarrProfile
		"defaultRoot"=$sonarrRootDir
	};
	$body = $body | ConvertTo-Json
	$formattedURL = [System.String]::Concat(($userData.mbURL), 'configure/', ($endpoint))

	# Test and Save to MediaButler
	Write-Host ""
	Write-Host "Testing the full Sonarr config for MediaButler..."
	try {
		$response = Invoke-WebRequest -Uri $formattedURL -Method PUT -Headers $headers -Body $body
		$response = $response | ConvertFrom-Json
	} catch {}
	if ($response.message -eq "success") {
		Write-Host -ForegroundColor Green "Success!"
		Write-Host ""
		Write-Host "Saving the Sonarr config to MediaButler..."
		try {
			$response = Invoke-WebRequest -Uri $formattedURL -Method POST -Headers $headers -Body $body
			$response = $response | ConvertFrom-Json
		} catch {}
		if ($response.message -eq "success") {
			Write-Host -ForegroundColor Green "Done! Sonarr has been successfully configured for"
			Write-Host -ForegroundColor Green "MediaButler with the"$userData.serverName"Plex server."
			Start-Sleep -s 3
			Write-Host Returning you to the Main Menu...
			sonarrMenu $userData
		}  elseif ($response.message -ne "success") {
			Write-Host -ForegroundColor Red "Config push failed! Please try again later."
			Start-Sleep -s 3
			sonarrMenu $userData
		}
	} elseif ($response.message -ne "success") {
		Write-Host -ForegroundColor Red -BackgroundColor Black "Hmm, something weird happened. Please try again."
		Start-Sleep -s 3
		sonarrMenu $userData
	}
	sonarrMenu $userData
}

function main () {
	Write-Host "Welcome to the MediaButler setup utility!"
	checkUserData
	$userDataTest
	checkPlexAuth
	chooseServer
	getMbURL
	do {
		$ans = mainMenu
		if (-Not(($ans -ge 1) -And ($ans -le 4))) {
			Write-Host -ForegroundColor Red -BackgroundColor Black "You did not specify a valid option!"
			$valid = $false
		} elseif ($ans -eq 1) {
			sonarrMenu
		} elseif ($ans -eq 2) {
			radarrMenu
		} elseif ($ans -eq 3) {
			setupTautulli
		} elseif ($ans -eq 4) {
			Exit
		}
	} while(-Not($valid))
}

$Global:userData = @{}
main