# BlockTheSpot

## Video, audio & banner adblock/skip for Spotify

**Current Version:** 0.13

**Last updated:** 5th March 2019

**Last tested version:** 1.1.4.197.g92d52c4f

#### Important Notice

If you are using Spotify 1.1.5.xxx or newer, please use run the automatic downgrade script [here](https://github.com/master131/BlockTheSpot/raw/master/downgrade.bat) which will downgrade to 1.1.4.197.g92d52c4f and also disable auto-update. Thanks @CHEF-KOCH.

#### How do I re-enable automatic updates?

Run Command Prompt as administrator and enter the following command:
```
icacls "%localappdata%\Spotify\Update" /reset /T
```

### Features:
* Windows only
* Set and forget
* Blocks all banner/video/audio ads within the app
* Retains friend, vertical video and radio functionality
* Unlocks the skip function for any track

:warning: This mod is for the [**Desktop release**](https://www.spotify.com/download/windows/) of Spotify on Windows and **not the Microsoft Store version**.

### Install/Uninstall:

#### Easy Installation:
[Download](https://github.com/master131/BlockTheSpot/raw/master/install.bat) and run install.bat. You don't need to download any other file. 

PS - It's not encrypted at all, it's a batch file with the mod embedded at the end (see the "MZ" header). You can always use the manual installation method.

#### Manual Installation:
[Download](https://github.com/master131/BlockTheSpot/raw/master/netutils.dll) and drop netutils.dll inside the Spotify installation folder (next to Spotify.exe).

The default Spotify installation location is: %APPDATA%/Spotify (copy and paste into Explorer address bar)

#### Uninstall:
To uninstall, simply delete netutils.dll from your Spotify installation (see above for the location).
