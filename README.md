# Domain Reputation Inspector

Fiddler Classic extension for malware traffic review. It watches intercepted HTTP and HTTPS sessions, records each hostname, looks up existing VirusTotal domain reports, and matches hosts against Emerging Threats Snort and Suricata domain indicators stored locally.

Compiled builds are on the GitHub Releases page. This repository holds the public source used to produce those builds. The project does not include, embed, or ship any API keys.

## Install the compiled build

Download DomainReputationInspector-1.0.0.zip from [Releases](https://github.com/lucas-link-code/Domain-Reputation-Extension-for-Fiddler-Classic/releases). Extract the folder, then run `install.bat` from that folder.

The installer copies files into:

```
%USERPROFILE%\Documents\Fiddler2\Scripts
```

Close Fiddler Classic before you install. The script will try to stop Fiddler if it is still running.

You need these files next to `install.bat`:

- DomainReputationInspector.dll
- DomainReputationInspector.dll.config
- Newtonsoft.Json.dll
- System.Data.SQLite.dll
- x86\SQLite.Interop.dll
- x64\SQLite.Interop.dll

Start Fiddler Classic. Open the Domain Reputation tab. Paste your VirusTotal API key and click Save. Leave ET Pro Key empty unless you have an ET Pro key.

`validate_installation.bat` checks that the DLLs landed in the Scripts folder.

## API keys

You must supply your own keys for the features you want to use.

VirusTotal: required for reputation counts. Create a free or paid account at https://www.virustotal.com/ and generate an API key. Paste it into VT API Key and click Save. Until you save a key, the Error column shows that the API key is not configured.

Emerging Threats: ET Open is the default and is free. No ET Pro key is required. The extension downloads ET Open rules from rules.emergingthreats.net. If you already have an ET Pro key from Proofpoint, paste it into ET Pro Key and click Save ET. Leave that field empty to stay on ET Open.

Do not commit keys into this repository.

VirusTotal keys are stored in the local user settings for this assembly. ET Pro keys are stored in:

```
%AppData%\DomainReputationInspector\et_rules.db
```

## What it does

Adds a Domain Reputation tab in Fiddler Classic.

Captures the full hostname from each session, including subdomains.

Queries VirusTotal API v3 for an existing domain report only. It does not submit a new analysis.

Checks Emerging Threats indicators locally. Exact host first, then the registrable base domain if needed.

Hides Fiddler sessions that are the extension talking to VirusTotal or Emerging Threats.

## Behaviour

First time a host appears: one VirusTotal query and one ET lookup. Later hits only increment the request count.

Refresh clears the VirusTotal cache for listed hosts and queries again.

Save on the VirusTotal key also re-queries hosts already in the grid.

Double click a row to open the VirusTotal domain report in the browser.

VirusTotal calls are spaced 2 seconds apart. Successful reports are cached for 30 minutes.

ET rules download into `%AppData%\DomainReputationInspector\et_rules.db`. Daily refresh is attempted around 02:00 local time. Update ET forces a download immediately.

## Grid

Columns: Domain, Requests, ApiCallsMade, ET Threat, Malicious, Suspicious, Harmless, Undetected, Status, Error.

Row colour from VirusTotal counts:

- Light coral: at least one malicious vendor
- Light yellow: at least one suspicious vendor, no malicious
- Light green: report returned with neither
- Light gray: query error

ET Threat cell colour: red for high, orange for medium, yellow for low.

## Requirements

- Windows
- Fiddler Classic 2.3.0.0 or later
- .NET Framework 4.6.1
- Your own VirusTotal API key from https://www.virustotal.com/
- Visual Studio Build Tools or MSBuild, plus nuget.exe, if you build from source

## Build from source

On a Windows machine with Fiddler Classic installed so Fiddler.exe can be referenced:

```
build.bat
```

If nuget.exe is in the same folder as build.bat, the script uses it. Otherwise it uses nuget on PATH.

Artefacts land in `bin\PUBLIC`. Copy those files into `%USERPROFILE%\Documents\Fiddler2\Scripts`, or copy `install.bat` into `bin\PUBLIC` and run it from there.

## Troubleshooting

Tab missing: confirm the DLL and SQLite interop folders are in Documents\Fiddler2\Scripts, then fully restart Fiddler. Check the Fiddler Log.

No VirusTotal numbers: paste your own API key and click Save. Save re-queries listed hosts. Use Refresh if a later lookup fails.

ET status stays empty: allow outbound HTTPS to rules.emergingthreats.net, then click Update ET. ET Open does not need a Pro key.

Log line prefixes: [DomainRep], [VT-OPTIMIZED], ET RULES.
