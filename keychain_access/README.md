# Monitor Keychain Accesses

This tools monitors a process and exports any accessed keychain items to a JSON file.
We accomplish this by hooking the [`SecItemCopyMatching`](https://developer.apple.com/documentation/security/1398306-secitemcopymatching) function that is universally used by system and third-party applications to access keys, certificates, etc.
Knowledge about these items helps understanding undocumented services as type and name of keychain items might contain information about the cryptographic primitives that services employ.

## Usage

```
usage: keychain_access.py [-h] [-o OUTPUT_FILE] process

positional arguments:
  process               Process name or ID to hook

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT_FILE, --output_file OUTPUT_FILE
                        Output file
```

## Example: `rapportd`

The `rapportd` is responsible for handling Handoff and the Universal Clipboard services. It uses several keys to enable end-to-end encryption between both devices.
To make sure that no secrets are pre-loaded, disable _System Preferences -> General -> Allow Handoff ..._.

Then, run:

```bash
python3 keychain_access.py rapportd`
```

... and enable _System Preferences -> General -> Allow Handoff ..._ again. This will initiate a loading process and print all keys for your iCloud devices.

## Example: Hackme

The [`tests`](tests) directory contains a simply `hackme` program that attempts to access a specific item in the keychain. You can use `keychain_access.py` to monitor the query. In addition, we provide a simple test case via `tests/test.sh` that adds a dummy password to the keychain, starts the `hackme` process, and extracts the password via `keychain_access.py`.

The output of the test case should look as follows:

```
Add dummy password under label org.owlink.findme ...
Start hackme-swift program ...
Extract secret(s) to keychain_access_test.json ...
[Press Ctrl+D to stop and save keychain items]
{'type': 'send', 'payload': {'query': {'class': 'genp', 'labl': 'org.owlink.findme', 'r_Data': '1'}, 'result': '0xf09fa689'}}
[{'query': {'class': 'genp', 'labl': 'org.owlink.findme', 'r_Data': '1'}, 'result': '0xf09fa689'}]
Compare with extracted secret ... sucess!
Clean up ...
password has been deleted.
```
