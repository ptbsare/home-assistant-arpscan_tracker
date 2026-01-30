## Changelog

### 2.0.7

- Introduced a retry of 3 for ARP requests (was 0)
- Set last_seen back in time for known devices that were offline after restart

### 2.0.6

- Fixed issue with ZeroTier interfaces not being detected
- Removed custom config field
- Better IP include/exclude config parsing
- More debug logging for IP include/exclude

### 2.0.5

- Disable unavailable state

### 2.0.4

- Use RestoreEntity to survive reboots/restarts
- Bump ruff from 0.14.10 to 0.14.11 by @dependabot[bot] in #25
- Fix timedelta serialization bug in YAML import by @jleinenbach in #24

### 2.0.3

- Added extra safeguard against possible corrupted config data

### 2.0.2

- You can now set consider_home up to 30 minutes (1800 seconds)

### 2.0.1

- Extended linting, fixed linting bugs, fixed manifext

### 2.0.0

- **Breaking**: Replaced external `arp-scan` command with pure Python (scapy)
- Added GUI configuration flow
- Added YAML migration support
- Added options flow for runtime configuration
- Added vendor lookup via OUI database
- Updated to modern Home Assistant patterns (ScannerEntity, DataUpdateCoordinator)

### 1.x

- Legacy version using external `arp-scan` command
- YAML-only configuration
