# Historical VirusTotal data for Nim binaries.

This is a repository that uses automation to constantly retrieve false positive data about windows nim binaries.

In this repository, there lies a `json/` folder filled with even more json folders!

Every single folder inside `json/` contains VirusTotal results for a list of different nim versions at a specific date.
The date format is this: `yyyy-mm-dd-hh:mm:ss` with maybe an extra `-NUM` if the date itself is already taken (Fx. when there are leap seconds and so on)

So if you see a folder named `json-2024-04-27-17:45:02` then you'll know that this specific scan began in the April 27th 2024, with the time being 17:45. 

Inside the folders, you'll find a bunch of json files, these are the pure VirusTotal API results just saved as a file. 
Every single file will follow this format: `version_architecture.json` (*Note:* This might change if I decide to scan Linux binaries in addition to Windows ones, so, y'know, be wary.)

So if you see a file named `2.0.4_x64.json` then it's the analysis results for Nim 2.0.4 64 bit windows release.

Also, you might have noticed another file in the root named `latest`, this file contains the path to the latest scan results.

## Why?

Why not? Collecting this data will allow us to see which antivirus companies constantly flag Nim binaries as malware. Because: surprise, surprise, they can flag binaries **again** which is why reporting false positives is a laborious process that drains people's sanity involving email, captcha submissions and broken web forums.

Dealing with false positives easily is why I made `nim-fp-suite` and `nim-fp-data` is a pure hobby project that serves no purpose other than to archive historical data showing which AV is least likely to flag Nim.

And we might be able to make lovely graphs in the near future! hopefully showing a decline!

## Todo-list

1. Consider scanning different OSes: Right now, `nim-fp-data` only processes Nim binaries for Windows, where false positives have the biggest impact on the community. This would require a major re-write of both `nim-fp-data` and `nim-fp-suite` which is maybe for the best, but I'd rather not have to deal with virustotal's fucked up API again.
2. Consider scanning different architectures: This is maybe not relevant considering Nim binaries aren't available for Windows ARM.
