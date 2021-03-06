<p align="center"><img src="https://raw.githubusercontent.com/christronyxyocum/mb-setup-utility/assets/Images/mb_small.png"><img src="https://raw.githubusercontent.com/christronyxyocum/mb-setup-utility/assets/Images/ps_small.png"></p>

# MediaButler Windows CLI Utility

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/569a11e2f08d48edab7c57404417ba29)](https://www.codacy.com/app/HalianElf/CLI-Windows?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=MediaButler/CLI-Windows&amp;utm_campaign=Badge_Grade)
[![Chat on Discord](https://img.shields.io/discord/379374148436230144.svg)](https://discord.gg/nH9t5sm)
[![made-with-powershell](https://img.shields.io/badge/Made%20with-Powershell-1f425f.svg)](https://github.com/PowerShell/PowerShell)
[![](https://badge-size.herokuapp.com/MediaButler/CLI-Windows/master/mediabutler.ps1)](https://github.com/MediaButler/CLI-Windows/blob/master/mediabutler.ps1)

## What is it?

A command line tool to enable usage of the [MediaButler Server](https://github.com/MediaButler/Server)

## Features

 - [x] Can configure Sonarr/Radarr/Tautulli for use with the [Server](https://github.com/MediaButler/Server)
 - [x] Add and Manage Requests
 - [ ] Add and Manage Issues
 - [x] Media Search
 - [x] Retrieve currently playing statistics
 - [x] Playback History

 ## Why do you need my Plex username and password?

 As the [Server](https://github.com/MediaButler/Server) only supports authenticated forms of communication, we require this information to perform an authentication with Plex. This information is used ONLY to perform Plex authencation and is not saved. We do however save a resulting token that is unique that is saved so you do not have to perform authentication again.

 ## Requirements

 We have done everything in our power to limit the dependancies this application has and for most users, it should have it installed. However in case you do not you will require the following:

  - PowerShell 5 or later - PowerShell 5 is available for Windows 7 and up.

  or

  - PowerShell Core

 ## Installing and Using

 The simplest method would be to either download the file manually or cloning this git repository.

     git clone https://github.com/MediaButler/CLI-Windows.git

### Windows (PowerShell >= 5) Users

Please be warned that by default Windows Policies are to block any and all scripts that are not made directly on your machine. We need to make a few changes in order to get windows to accept the script. This can be done by opening an Administrative PowerShell prompt and running the following commands:

    Set-ExecutionPolicy RemoteSigned
    // Select Yes to the warning that it gives you.
    cd C:\path\to\CLI-Windows
    Unblock-File .\mediabutler.ps1

This only needs to be performed once.

You can also start PowerShell in exception mode for this specific file by running `PowerShell.exe -ExecutionPolicy RemoteSigned -File C:\path\to\CLI-Windows\mediabutler.ps1`

### Using

Running can be done by opening a PowerShell prompt and running the following:

    cd C:\path\to\CLI-Windows
    .\mediabutler.ps1

### Docker

You can also run the client inside a docker envrionment by running

    docker run -it mediabutler/cli-windows

## Support

Further help and support using this script can be found in [our Wiki](https://github.com/MediaButler/Wiki/wiki) or drop by our [Discord Server](https://discord.gg/nH9t5sm)