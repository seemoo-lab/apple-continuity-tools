# Apple Continuity Reverse Engineering Toolkit

This reverse engineering toolkit for macOS was used by [the Open Wireless Link Project](https://owlink.org) to analyze several services in Apple's wireless ecosystem such as [AirDrop](https://github.com/seemoo-lab/opendrop), [Wi-Fi Password Sharing](https://github.com/seemoo-lab/openwifipass), Handoff, and Offline Finding.

## Requirements

### Module Dependencies

The toolkit uses both Python and Node.js modules. To use them, first create a virtual Python environment and then install all dependencies (Python and Node.js) by running:

```
make venv
source venv/bin/activate
make install
```

To uninstall, simply delete the repository folder.

### Disabled System Integrity Protection

Some of the tools require you to (partly) disable macOS' System Integrity Protection (SIP). [**Please be aware of the security implications.**](https://en.wikipedia.org/wiki/System_Integrity_Protection) We indicate this requirement in the table below.
To (partly) disable SIP, boot into recovery mode by restarting macOS and holding ⌘+R. In recovery mode, open the terminal, enter one of the following commands, and reboot macOS.

```bash
# Disable only certain SIP features ...
csrutil enable --without <FEATURE>
# ... or fully disable SIP
csrutil disable
```

To restore full SIP later, reboot in macOS' recovery mode again (⌘+R) and run

```bash
csrutil enable
```

## Tools

We provide a brief overview of the included tools. Please read the respective `README.md` in the subfolders for more information.

| Tool                                         | Description                                                   |    Disable SIP features    |
| -------------------------------------------- | ------------------------------------------------------------- | :------------------------: |
| [`process_recon`](process_recon)             | scan system logs find processes involved in a certain service |             —              |
| [`keychain_access`](keychain_access)         | monitor process access to any keychain items and export them  | all (for system processes) |
| [`continuity_messages`](continuity_messages) | record _Continuity_ messages of the `rapportd` daemon         |        `debugging`         |

## Authors

- Alexander Heinrich
- Milan Stute

## Related Publications

- Milan Stute, Alexander Heinrich, Jannik Lorenz, and Matthias Hollick. **Disrupting Continuity of Apple’s Wireless Ecosystem Security: New Tracking, DoS, and MitM Attacks on iOS and macOS Through Bluetooth Low Energy, AWDL, and Wi-Fi.** _30th USENIX Security Symposium (USENIX Security ’21)_, August 11–13, 2021, Vancouver, B.C., Canada. _To appear_.
- Milan Stute. **Availability by Design: Practical Denial-of-Service-Resilient Distributed Wireless Networks.** Dissertation, _Technical University of Darmstadt_, February 14, 2020. [doi:10.25534/tuprints-00011457](https://doi.org/10.25534/tuprints-00011457)
- Milan Stute, Sashank Narain, Alex Mariotto, Alexander Heinrich, David Kreitschmann, Guevara Noubir, and Matthias Hollick. **A Billion Open Interfaces for Eve and Mallory: MitM, DoS, and Tracking Attacks on iOS and macOS Through Apple Wireless Direct Link.** _28th USENIX Security Symposium (USENIX Security ’19)_, August 14–16, 2019, Santa Clara, CA, USA. [Link](https://www.usenix.org/conference/usenixsecurity19/presentation/stute)

## License

This toolkit is licensed under the [**GNU General Public License v3.0**](LICENSE).
