# Process Reconnaissance

The `process_recon.py` script summarizes processes, categories, and subsystems from log entries containing a set of user-provided keywords.
This is useful to when reverse engineering an unknown service to determine target processes and binaries.

## Usage

```
usage: process_recon.py [-h] [-v] keywords [keywords ...]

positional arguments:
  keywords       One or more keywords to scan for

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  Print individual log entries
```

## Example

To produce meaningful output, we

1. start the script,
2. trigger or interact with the service (e.g., open an application), and
3. stop the script.

The following is an example for AirDrop on macOS 11.0 when opening and closing the sharing pane in the Finder application.
The output also shows the frequency of the discovered entities and might provide a guidence where to start digging deeper...

```
$ python3 process_recon.py airdrop
Scanning logs for ['airdrop']. Press Ctrl+C to stop ...
^C

Discovery summary:
Processes (4):
	/usr/libexec/sharingd (28)
	/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder (24)
	/kernel (3)
	/usr/libexec/runningboardd (2)
Categories (7):
	User Defaults (21)
	strings (15)
	AirDrop (5)
	resources (5)
	Daemon (3)
	Browser (3)
	assertion (2)
Subsystems (4):
	com.apple.defaults (21)
	com.apple.CFBundle (20)
	com.apple.sharing (11)
	com.apple.runningboard (2)
```
