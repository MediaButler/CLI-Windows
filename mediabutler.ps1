# Setup initial variables
$uuid = "fb67fb8b-9000-4a70-a67b-2f2b626780bb"
$userDataPath = '.\userData.json'
$plexLoginURL = "https://plex.tv/users/sign_in.json"
$mbLoginURL = "https://auth.mediabutler.io/login"
$mbDiscoverURL = "https://auth.mediabutler.io/login/discover"

function Write-ColorOutput($ForegroundColor, $message) {
    # Save the current color
    $fc = $host.UI.RawUI.ForegroundColor

    # Set the new color
	$host.UI.RawUI.ForegroundColor = $ForegroundColor

	# Write out the message
	Write-Information $message -InformationAction Continue

    # Restore the original color
    $host.UI.RawUI.ForegroundColor = $fc
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
			Write-Information "" -InformationAction Continue
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
			};
			$body = $body | ConvertTo-Json

			#$str = $headers | Out-String
			#Write-Host $body
			#Write-Host $str

			$response = Invoke-WebRequest -Uri $plexLoginURL -Method POST -Headers $headers -Body $body -ContentType "application/json"
			$response = $response | ConvertFrom-Json
			$authToken = $response.user.authToken
		} catch [System.Net.WebException] {
			$err = $_.Exception.Response.StatusCode
			$failedLogin = $true
			if ($err -eq "Unauthorized") {
				Write-ColorOutput red "Invalid Credentials"
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
		$response = Invoke-WebRequest -Uri $url"version" -TimeoutSec 10
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
function checkUserData() {
	if (Test-Path $userDataPath -PathType Leaf) {
		$fileIn = Get-Content -Raw -Path $userDataPath | ConvertFrom-Json
		$fileIn.psobject.properties | Foreach-Object { $userData[$_.Name] = $_.Value }
	}
}

# Check if Plex Auth Token is saved in userData and if not print menu and get it from user
function checkPlexAuth() {
	if ([string]::IsNullOrEmpty($userData.authToken)) {
		Write-Information "" -InformationAction Continue
		Write-Information "First thing we need are your Plex credentials so please choose from one of the following options:" -InformationAction Continue
		Write-Information "" -InformationAction Continue
		Write-Information "1. Plex Username and Password" -InformationAction Continue
		Write-Information "2. Plex token" -InformationAction Continue
		Write-Information "" -InformationAction Continue

		$valid = $false
		do {
			[int]$ans = Read-Host 'Enter selection'
			if ($ans -eq 1) {
				$userData.authToken = plexLogin
				$mbLoginResponse = mbLogin $userdata.authToken
				$valid = $true
			} elseif ($ans -eq 2) {
				do {
					Write-Information "" -InformationAction Continue
					$authTokenEnc = Read-Host -Prompt 'Plex Auth Token' -AsSecureString
					$credentials = New-Object System.Management.Automation.PSCredential -ArgumentList "authToken", $authTokenEnc
					$userdata.authToken = $credentials.GetNetworkCredential().Password
					$mbLoginResponse = mbLogin $userdata.authToken
					if([string]::IsNullOrEmpty($mbLoginResponse)) {
						Write-ColorOutput red "Invalid Plex Auth Token"
					}
				} while ([string]::IsNullOrEmpty($mbLoginResponse))
				$valid = $true
			} else {
				Write-ColorOutput red "Invalid Response. Please try again."
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
		Write-Information "" -InformationAction Continue
		Write-Information "Please choose which Plex Server you would like to setup MediaButler for:" -InformationAction Continue
		$menu = @{}
		foreach ($server in $mbLoginResponse.servers) {
			try {
				$owner = [System.Convert]::ToBoolean($server.owner)
			} catch [FormatException] {
				$owner = $false
			}
			if ($owner) {
				$i++
				Write-Information "$i. $($server.name)" -InformationAction Continue
				$serverInfo = @{"serverName"="$($server.name)"; "machineId"="$($server.machineId)"; "mbToken"="$($server.token)";};
				$menu.Add($i,($serverInfo))
			}
		}
		do {
			[int]$ans = Read-Host 'Enter selection'
			if ($ans -ge 1 -And $ans -le $i) {
				$valid = $true
				$userData.serverName = $menu.Item($ans).serverName
				$userData.machineId = $menu.Item($ans).machineId
				$userData.mbToken = $menu.Item($ans).mbToken
			} else {
				$valid = $false
				Write-ColorOutput red "You did not specify a valid option!"
			}
		} while (-Not ($valid))
		$userData | ConvertTo-Json | Out-File -FilePath $userDataPath
	}
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
				$mbURL = Invoke-WebRequest -Uri $mbDiscoverURL -Method POST -Headers $headers -Body $body -ContentType "application/json"
			}
			Write-Information "Is this the correct MediaButler URL?" -InformationAction Continue
			Write-ColorOutput yellow $mbURL
			Write-Information "" -InformationAction Continue
			Write-Information "[Y]es or [N]o" -InformationAction Continue
			$valid = $false
			do {
				$ans = Read-Host
				if (($ans -notlike "y") -And ($ans -notlike "yes") -And ($ans -notlike "n") -And ($ans -notlike "no")) {
					Write-ColorOutput red "Please specify yes, y, no, or n."
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
					Write-ColorOutput red "Invalid Server URL"
				}
			} while(-Not ($isMB));
			$userData.mbURL = $mbURL
		}
		$userData | ConvertTo-Json | Out-File -FilePath $userDataPath
	}
}

# Print the main menu
# Returns selection
function mainMenu() {
	Write-Information "" -InformationAction Continue
	Write-Information "*****************************************" -InformationAction Continue
	Write-Information "*               Main Menu               *" -InformationAction Continue
	Write-Information "*****************************************" -InformationAction Continue
	Write-Information "Please choose which application you would" -InformationAction Continue
	Write-Information "   like to configure for MediaButler:    " -InformationAction Continue
	Write-Information "" -InformationAction Continue
	Write-Information "1. Sonarr" -InformationAction Continue
	Write-Information "2. Radarr" -InformationAction Continue
	Write-Information "3. Tautulli" -InformationAction Continue
	Write-Information "4. Exit" -InformationAction Continue
	Write-Information "" -InformationAction Continue
	do {
		[int]$ans = Read-Host 'Enter selection'
		if (-Not(($ans -ge 1) -And ($ans -le 4))) {
			Write-ColorOutput red "You did not specify a valid option!"
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
	Exit
}

# Print the Sonarr menu and get response
function sonarrMenu() {
	Write-Information "" -InformationAction Continue
	Write-Information "*****************************************" -InformationAction Continue
	Write-Information "*           Sonarr Setup Menu           *" -InformationAction Continue
	Write-Information "*****************************************" -InformationAction Continue
	Write-Information "Please choose which version of Sonarr you" -InformationAction Continue
	Write-Information "would like to configure for MediaButler: " -InformationAction Continue
	Write-Information "" -InformationAction Continue
	Write-Information "1. Sonarr" -InformationAction Continue
	Write-Information "2. Sonarr 4K" -InformationAction Continue
	Write-Information "3. Back to Main Menu" -InformationAction Continue
	Write-Information "" -InformationAction Continue
	do {
		[int]$ans = Read-Host 'Enter selection'
		if (-Not(($ans -ge 1) -And ($ans -le 3))) {
			Write-ColorOutput red "You did not specify a valid option!"
			$valid = $false
		} elseif (($ans -eq 1) -Or ($ans -eq 2)) {
			$valid = $true
			setupSonarr $ans
		} elseif ($ans -eq 3) {
			$valid = $true
			mainMenu
		}
	} while (-Not($valid))
}

# Print the Radarr menu and get response
function radarrMenu() {
	Write-Information "" -InformationAction Continue
	Write-Information "*****************************************" -InformationAction Continue
	Write-Information "*           Radarr Setup Menu           *" -InformationAction Continue
	Write-Information "*****************************************" -InformationAction Continue
	Write-Information "Please choose which version of Radarr you" -InformationAction Continue
	Write-Information "would like to configure for MediaButler: " -InformationAction Continue
	Write-Information "" -InformationAction Continue
	Write-Information "1. Radarr" -InformationAction Continue
	Write-Information "2. Radarr 4K" -InformationAction Continue
	Write-Information "3. Radarr 3D" -InformationAction Continue
	Write-Information "4. Back to Main Menu" -InformationAction Continue
	Write-Information "" -InformationAction Continue
	do {
		[int]$ans = Read-Host 'Enter selection'
		if (-Not(($ans -ge 1) -And ($ans -le 4))) {
			Write-ColorOutput red "You did not specify a valid option!"
			$valid = $false
		} elseif (($ans -ge 1) -Or ($ans -le 3)) {
			$valid = $true
			setupRadarr $ans
		} elseif ($ans -eq 4) {
			$valid = $true
			mainMenu
		}
	} while (-Not($valid))
}

# Function to get the Tautulli information, test it and send it to the MediaButler server
function setupTautulli() {
	# Tautulli URL
	Write-Information "" -InformationAction Continue
	Write-Information "Please enter your Tautulli URL (IE: http://127.0.0.1:8181/tautulli/):" -InformationAction Continue
	do {
		$tauURL = Read-Host -Prompt "URL"
		$lastChar = $tauURL.SubString($tauURL.Length - 1)
		if ($lastChar -ne "/") {
			$tauURL = "$tauURL/"
		}
		Write-Information "Checking that the provided Tautulli URL is valid..." -InformationAction Continue
		try {
			$response = Invoke-WebRequest -Uri $tauURL"auth/login" -Method Head
		} catch {
			Write-Debug $_.Exception.Response
		}
		if ($response.statuscode -eq "200") {
			Write-ColorOutput green "Success!"
			$valid = $true
		} else {
			Write-ColorOutput red "Received something other than a 200 OK response!"
			$valid = $false
		}
	} while (-Not($valid))

	# API Key
	Write-Information "" -InformationAction Continue
	Write-Information "Please enter your Tautulli API key" -InformationAction Continue
	do {
		$tauAPI = Read-Host -Prompt 'API' -AsSecureString
		$credentials = New-Object System.Management.Automation.PSCredential -ArgumentList "apiKey", $tauAPI
		$tauAPI = $credentials.GetNetworkCredential().Password
		Write-Information "" -InformationAction Continue
		Write-Information "Testing that the provided Tautulli API Key is valid..." -InformationAction Continue
		try {
			$response = Invoke-WebRequest -Uri $tauURL"api/v2?apikey="$tauAPI"&cmd=arnold"
			$response = $response | ConvertFrom-Json
		} catch {
			Write-Debug $_.Exception.Response
		}
		if ($null -eq $response.response.message) {
			Write-ColorOutput green "Success!"
			$valid = $true
		} else {
			Write-ColorOutput red "Received something other than an OK response!"
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
	Write-Information "" -InformationAction Continue
	Write-Information "Testing the full Tautulli config for MediaButler..." -InformationAction Continue
	try {
		$response = Invoke-WebRequest -Uri $formattedURL -Method PUT -Headers $headers -Body $body
		$response = $response | ConvertFrom-Json
	} catch {
		Write-Debug $_.Exception.Response
	}
	if ($response.message -eq "success") {
		Write-ColorOutput green "Success!"
		Write-Information "" -InformationAction Continue
		Write-Information "Saving the Tautulli config to MediaButler..." -InformationAction Continue
		try {
			$response = Invoke-WebRequest -Uri $formattedURL -Method POST -Headers $headers -Body $body
			$response = $response | ConvertFrom-Json
		} catch {
			Write-Debug $_.Exception.Response
		}
		if ($response.message -eq "success") {
			Write-ColorOutput green "Done! Tautulli has been successfully configured for"
			$str = "MediaButler with the " + $userData.serverName + " Plex server."
			Write-ColorOutput green $str
			Start-Sleep -s 3
			Write-Information "Returning you to the Main Menu..." -InformationAction Continue
		}  elseif ($response.message -ne "success") {
			Write-ColorOutput red "Config push failed! Please try again later."
			Start-Sleep -s 3
		}
	} elseif ($response.message -ne "success") {
		Write-ColorOutput red "Hmm, something weird happened. Please try again."
		Start-Sleep -s 3
	}
	mainMenu
}

# Fucntion to get a list of Profiles from *arr and create a menu for the user to pick from
# Returns selected profile name
function arrProfiles($response) {
	Write-Information "" -InformationAction Continue
	Write-Information "Please choose which profile you would like to set as the default for MediaButler:" -InformationAction Continue
	$menu = @{}
	$i = 0
	foreach ($profile in $response) {
		$i++
		Write-Information "$i. $($profile.name)" -InformationAction Continue
		$menu.Add($i,($profile.name))
	}
	do {
		[int]$ans = Read-Host 'Profile'
		if (($ans -ge 1) -And ($ans -le $i)) {
			$valid = $true
			$menu.Item($ans)
		} else {
			$valid = $false
			Write-ColorOutput red "Invalid Response."
		}
	} while (-Not ($valid))
}

function arrRootDir($response) {
	Write-Information "" -InformationAction Continue
	Write-Information "Please choose which root directory you would like to set as the default for MediaButler:" -InformationAction Continue
	$menu = @{}
	$i = 0
	foreach ($rootDir in $response) {
		$i++
		Write-Information "$i. $($rootDir.path)" -InformationAction Continue
		$menu.Add($i,($rootDir.path))
	}
	do {
		[int]$ans = Read-Host 'Profile'
		if (($ans -ge 1) -And ($ans -le $i)) {
			$valid = $true
			$menu.Item($ans)
		} else {
			$valid = $false
			Write-ColorOutput red "Invalid Response."
		}
	} while (-Not ($valid))
}

# Function to set up Sonarr
function setupSonarr($ans) {
	# Sonarr URL
	Write-Information "" -InformationAction Continue
	Write-Information "Please enter your Sonarr URL (IE: http://127.0.0.1:8989/sonarr/):" -InformationAction Continue
	do {
		$sonarrURL = Read-Host -Prompt "URL"
		$lastChar = $sonarrURL.SubString($sonarrURL.Length - 1)
		if ($lastChar -ne "/") {
			$sonarrURL = "$sonarrURL/"
		}
		Write-Information "Checking that the provided Sonarr URL is valid..." -InformationAction Continue
		try {
			$response = Invoke-WebRequest -Uri $sonarrURL"auth/login" -Method Head
		} catch {
			Write-Debug $_.Exception.Response
		}
		if ($response.statuscode -eq "200") {
			Write-ColorOutput green "Success!"
			$valid = $true
		} else {
			Write-ColorOutput red "Received something other than a 200 OK response!"
			$valid = $false
		}
	} while (-Not($valid))

	# API Key
	Write-Information "" -InformationAction Continue
	Write-Information "Please enter your Sonarr API key" -InformationAction Continue
	do {
		$err = ""
		$sonarrAPI = Read-Host -Prompt 'API' -AsSecureString
		$credentials = New-Object System.Management.Automation.PSCredential -ArgumentList "apiKey", $sonarrAPI
		$sonarrAPI = $credentials.GetNetworkCredential().Password
		Write-Information "" -InformationAction Continue
		Write-Information "Testing that the provided Sonarr API Key is valid..." -InformationAction Continue
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
			Write-ColorOutput red "Received something other than an OK response!"
			$valid = $false
		} else {
			Write-ColorOutput green "Success!"
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
		Write-ColorOutput red "Something went wrong..."
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
		Write-ColorOutput red "Something went wrong..."
	}

	# Set MediaButler formatting
	if ($ans -eq 1) {
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
	Write-Information "" -InformationAction Continue
	Write-Information "Testing the full Sonarr config for MediaButler..." -InformationAction Continue
	try {
		$response = Invoke-WebRequest -Uri $formattedURL -Method PUT -Headers $headers -Body $body
		$response = $response | ConvertFrom-Json
	} catch {
		Write-Debug $_.Exception.Response
	}
	if ($response.message -eq "success") {
		Write-ColorOutput green "Success!"
		Write-Information "" -InformationAction Continue
		Write-Information "Saving the Sonarr config to MediaButler..." -InformationAction Continue
		try {
			$response = Invoke-WebRequest -Uri $formattedURL -Method POST -Headers $headers -Body $body
			$response = $response | ConvertFrom-Json
		} catch {
			Write-Debug $_.Exception.Response
		}
		if ($response.message -eq "success") {
			Write-ColorOutput green "Done! Sonarr has been successfully configured for"
			$str = "MediaButler with the "+ $userData.serverName + " Plex server."
			Write-ColorOutput green $str
			Start-Sleep -s 3
			Write-Information "Returning you to the Main Menu..." -InformationAction Continue
			mainMenu
		}  elseif ($response.message -ne "success") {
			Write-ColorOutput red "Config push failed! Please try again later."
			Start-Sleep -s 3
			sonarrMenu
		}
	} elseif ($response.message -ne "success") {
		Write-ColorOutput red "Hmm, something weird happened. Please try again."
		Start-Sleep -s 3
		sonarrMenu
	}
	sonarrMenu
}

function setupRadarr($ans) {
	# Sonarr URL
	Write-Information "" -InformationAction Continue
	Write-Information "Please enter your Sonarr URL (IE: http://127.0.0.1:7878/radarr/):" -InformationAction Continue
	do {
		$radarrURL = Read-Host -Prompt "URL"
		$lastChar = $radarrURL.SubString($radarrURL.Length - 1)
		if ($lastChar -ne "/") {
			$radarrURL = "$radarrURL/"
		}
		Write-Information "Checking that the provided Sonarr URL is valid..." -InformationAction Continue
		try {
			$response = Invoke-WebRequest -Uri $radarrURL"auth/login" -Method Head
		} catch {
			Write-Debug $_.Exception.Response
		}
		if ($response.statuscode -eq "200") {
			Write-ColorOutput green "Success!"
			$valid = $true
		} else {
			Write-ColorOutput red "Received something other than a 200 OK response!"
			$valid = $false
		}
	} while (-Not($valid))

	# API Key
	Write-Information "" -InformationAction Continue
	Write-Information "Please enter your Radarr API key" -InformationAction Continue
	do {
		$err = ""
		$radarrAPI = Read-Host -Prompt 'API' -AsSecureString
		$credentials = New-Object System.Management.Automation.PSCredential -ArgumentList "apiKey", $radarrAPI
		$radarrAPI = $credentials.GetNetworkCredential().Password
		Write-Information "" -InformationAction Continue
		Write-Information "Testing that the provided Radarr API Key is valid..." -InformationAction Continue
		try {
			$headers = @{
				"X-Api-Key"=$radarrAPI
			};
			$response = Invoke-WebRequest -Uri $radarrURL"api/system/status" -Headers $headers
			$response = $response | ConvertFrom-Json
		} catch {
			$err = $_.Exception.Response.StatusCode
		}
		if ($err -eq "Unauthorized") {
			Write-ColorOutput red "Received something other than an OK response!"
			$valid = $false
		} else {
			Write-ColorOutput green "Success!"
			$valid = $true
		}
	} while (-Not($valid))

	# Default Profile
	try {
		$headers = @{
			"X-Api-Key"=$radarrAPI
		};
		$response = Invoke-WebRequest -Uri $radarrURL"api/profile" -Headers $headers
		$response = $response | ConvertFrom-Json
		$radarrProfile = arrProfiles $response
	} catch {
		Write-ColorOutput red "Something went wrong..."
	}

	# Default Root Directory
	try {
		$headers = @{
			"X-Api-Key"=$radarrAPI
		};
		$response = Invoke-WebRequest -Uri $radarrURL"api/rootfolder" -Headers $headers
		$response = $response | ConvertFrom-Json
		$radarrRootDir = arrRootDir $response
	} catch {
		Write-ColorOutput red "Something went wrong..."
	}

	# Set MediaButler formatting
	if ($ans -eq 1) {
		$endpoint = "radarr"
	} elseif ($ans -eq 2) {
		$endpoint = "radarr4k"
	} elseif ($ans -eq 3) {
		$endpoint = "radarr3d"
	}
	$headers = @{
		"Content-Type"="application/json"
		"MB-Client-Identifier"=$uuid;
		"Authorization"="Bearer " + $userData.mbToken;
	};
	$body = @{
		"url"=$radarrURL;
		"apikey"=$radarrAPI;
		"defaultProfile"=$radarrProfile
		"defaultRoot"=$radarrRootDir
	};
	$body = $body | ConvertTo-Json
	$formattedURL = [System.String]::Concat(($userData.mbURL), 'configure/', ($endpoint))

	# Test and Save to MediaButler
	Write-Information "" -InformationAction Continue
	Write-Information "Testing the full Radarr config for MediaButler..." -InformationAction Continue
	try {
		$response = Invoke-WebRequest -Uri $formattedURL -Method PUT -Headers $headers -Body $body
		$response = $response | ConvertFrom-Json
	} catch {
		Write-Debug $_.Exception.Response
	}
	if ($response.message -eq "success") {
		Write-ColorOutput green "Success!"
		Write-Information "" -InformationAction Continue
		Write-Information "Saving the Radarr config to MediaButler..." -InformationAction Continue
		try {
			$response = Invoke-WebRequest -Uri $formattedURL -Method POST -Headers $headers -Body $body
			$response = $response | ConvertFrom-Json
		} catch {
			Write-Debug $_.Exception.Response
		}
		if ($response.message -eq "success") {
			Write-ColorOutput green "Done! Radarr has been successfully configured for"
			$str = "MediaButler with the " + $userData.serverName + " Plex server."
			Write-ColorOutput green $str
			Start-Sleep -s 3
			Write-Information "Returning you to the Main Menu..." -InformationAction Continue
			mainMenu
		}  elseif ($response.message -ne "success") {
			Write-ColorOutput red "Config push failed! Please try again later."
			Start-Sleep -s 3
			radarrMenu
		}
	} elseif ($response.message -ne "success") {
		Write-ColorOutput red "Hmm, something weird happened. Please try again."
		Start-Sleep -s 3
		radarrMenu
	}
	radarrMenu
}

function main () {
	Write-Information "Welcome to the MediaButler setup utility!" -InformationAction Continue
	checkUserData
	checkPlexAuth
	chooseServer
	getMbURL
	mainMenu
}

$Global:userData = @{}
main