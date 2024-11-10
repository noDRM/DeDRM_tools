# DeDRM_tools
This is a repository that tracks all the scripts and other tools for removing DRM from eBooks.

The provided plugins should work with both Calibre 5.x/6.x (Python 3), as well as Calibre 4.x and lower (Python 2).<br>
If you encounter issues with the plugins in Calibre 4.x or lower, please open a bug report. 

The original repository of Apprentice Harper [is no longer maintained](https://github.com/apprenticeharper/DeDRM_tools#no-longer-maintained), so I've taken over, merged a bunch of open PRs, and added a ton more features and bugfixes. 

## FAQ

You are urged to read the [FAQ](https://github.com/noDRM/DeDRM_tools/blob/master/FAQs.md). 

The most common issue however - You can't load the nested archive with all the tools into Calibre.<br>
You need to unarchive the downloaded tools archive, to get just the archive with the standalone plugin.<br>
Beta versions may be just the plugin, don't unarchive that.<br>

## Versions
The latest stable (released) version is v10.0.3, [available here](https://github.com/noDRM/DeDRM_tools/releases/tag/v10.0.3).<br>

The latest beta is v10.0.9, as a release candidate for v10.1.0, [available here](https://github.com/noDRM/DeDRM_tools/releases/tag/v10.0.9).<br>

The latest alpha version, completely untested, [available here](https://github.com/noDRM/DeDRM_tools_autorelease/releases).<br>
With each commit in this repository, a new alpha version containing the latest code changes will be automatically uploaded.<br>
If you want the most up-to-date code to test things and you are okay with the plugins occasionally breaking, you can use this version.

## Tools

The individual scripts are released as two plugins for Calibre: DeDRM and Obok.

### DeDRM

The DeDRM plugin handles books that use Amazon DRM, Adobe Digital Editions DRM, Barnes & Noble DRM, and some historical formats.<br>
For the latest Amazon KFX format, users of the Calibre plugin should also install the KFX Input plugin from the standard Calibre plugin menu.<br>
It is also available from [the MobileRead thread](https://www.mobileread.com/forums/showthread.php?t=291290).

Note that Amazon changes the DRM for KFX files frequently. What works for KFX today might not work tomorrow.

### Obok

The Obok plugin handles Kobo DRM.

## Changelog
Take a look at [the CHANGELOG](https://github.com/noDRM/DeDRM_tools/blob/master/CHANGELOG.md) to see a list of changes since the last version by Apprentice Harper (v7.2.1). 

## Contributions

Contributions are welcome, including, but not limited to: 
* Speed improvements and UI enhancements
* Expanding the range of books handled
* Improving key retrieval
* General bug fixes

Special thanks to all the developers who have done the hard work of reverse engineering and provided the first DeDRM tools.
