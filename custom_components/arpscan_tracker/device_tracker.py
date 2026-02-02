"""Device tracker platform for ARP-Scan."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, cast

import homeassistant.util.dt as dt_util
from homeassistant.components.device_tracker import ScannerEntity, SourceType
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .const import (
    ATTR_IP,
    ATTR_LAST_SEEN,
    ATTR_MAC,
    ATTR_VENDOR,
    CONF_CONSIDER_HOME,
    CONF_INTERFACE,
    DATA_COORDINATOR,
    DEFAULT_CONSIDER_HOME,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up device tracker entities from a config entry."""
    from homeassistant.helpers import entity_registry as er

    coordinator: DataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id][DATA_COORDINATOR]
    consider_home = entry.options.get(CONF_CONSIDER_HOME, DEFAULT_CONSIDER_HOME)
    # Defensive check: ensure consider_home is an int (might be timedelta from corrupted config)
    if isinstance(consider_home, timedelta):
        consider_home = int(consider_home.total_seconds())
    interface = entry.data.get(CONF_INTERFACE, "unknown")

    # Track which devices we've already created entities for
    tracked_macs: set[str] = set()

    # Restore entities from entity registry (devices discovered in previous runs)
    ent_reg = er.async_get(hass)
    restored_entities: list[ArpScanDeviceTracker] = []

    for entity in er.async_entries_for_config_entry(ent_reg, entry.entry_id):
        if entity.unique_id and entity.unique_id.startswith(f"{DOMAIN}_"):
            # Extract MAC from unique_id (format: arpscan_tracker_1c697a658c2b)
            mac_clean = entity.unique_id.replace(f"{DOMAIN}_", "")
            if len(mac_clean) == 12:  # Valid MAC without colons
                # Convert back to MAC format with colons
                mac_formatted = ":".join(mac_clean[i : i + 2] for i in range(0, 12, 2)).lower()
                if mac_formatted not in tracked_macs:
                    tracked_macs.add(mac_formatted)
                    restored_entities.append(
                        ArpScanDeviceTracker(
                            coordinator=coordinator,
                            mac=mac_formatted,
                            consider_home=consider_home,
                            interface=interface,
                            entry_id=entry.entry_id,
                        )
                    )
                    _LOGGER.debug(
                        "Restoring device tracker for MAC %s from registry",
                        mac_formatted,
                    )

    if restored_entities:
        async_add_entities(restored_entities)
        _LOGGER.info("Restored %d device tracker entities from registry", len(restored_entities))

    @callback
    def async_add_new_entities() -> None:
        """Add entities for newly discovered devices."""
        new_entities: list[ArpScanDeviceTracker] = []

        for mac, _device_data in coordinator.data.items():
            if mac not in tracked_macs:
                tracked_macs.add(mac)
                new_entities.append(
                    ArpScanDeviceTracker(
                        coordinator=coordinator,
                        mac=mac,
                        consider_home=consider_home,
                        interface=interface,
                        entry_id=entry.entry_id,
                    )
                )
                _LOGGER.debug("Adding new device tracker for MAC %s", mac)

        if new_entities:
            async_add_entities(new_entities)

    # Add entities for initial data (devices currently online but not restored)
    async_add_new_entities()

    # Listen for coordinator updates to add new devices
    entry.async_on_unload(coordinator.async_add_listener(async_add_new_entities))


class ArpScanDeviceTracker(CoordinatorEntity, RestoreEntity, ScannerEntity):
    """Representation of a device tracked via ARP scan."""

    _attr_has_entity_name = True
    _attr_available = True  # Device trackers are always available, even when offline
    _attr_device_info: DeviceInfo  # type: ignore[assignment]

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        mac: str,
        consider_home: int,
        interface: str,
        entry_id: str,
    ) -> None:
        """Initialize the device tracker."""
        super().__init__(coordinator)

        self._mac = mac.lower()
        self._consider_home = consider_home
        self._interface = interface
        self._entry_id = entry_id
        self._last_seen: datetime | None = dt_util.utcnow() - timedelta(days=365)

        # Get initial device data
        device_data = coordinator.data.get(self._mac, {})
        ip_address = device_data.get("ip", "unknown")
        hostname = device_data.get("hostname")

        # Format MAC for entity_id (remove colons)
        mac_clean = self._mac.replace(":", "")

        # Entity ID uses MAC address (e.g., device_tracker.arpscan_tracker_1c697a658c2)
        self._attr_unique_id = f"{DOMAIN}_{mac_clean}"

        # Display name: hostname if known, otherwise IP address
        if hostname:
            self._attr_name = hostname
        else:
            self._attr_name = ip_address

        # Store for later reference
        self._ip_address = ip_address
        self._hostname: str | None = hostname if isinstance(hostname, str) else None

        # Update last seen on init if device is in data
        if self._mac in coordinator.data:
            self._last_seen = dt_util.utcnow()

        # Device info - all entities share one scanner device
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self._interface)},
            name=f"ARP Scanner ({self._interface})",
            manufacturer="ARP-Scan Tracker",
            model="Network Scanner",
        )

    async def async_added_to_hass(self) -> None:
        """Restore state when entity is added to hass."""
        # IMPORTANT: Restore previous state BEFORE calling super() which registers
        # the coordinator listener. This ensures _last_seen is set before any
        # coordinator updates are processed.
        if (last_state := await self.async_get_last_state()) is not None:
            # Restore last_seen from attributes
            if last_seen_str := last_state.attributes.get(ATTR_LAST_SEEN):
                try:
                    self._last_seen = dt_util.parse_datetime(last_seen_str)
                    _LOGGER.debug(
                        "Restored last_seen for %s: %s",
                        self._mac,
                        self._last_seen,
                    )
                except (ValueError, TypeError):
                    pass

            # Restore IP and hostname if not currently in coordinator data
            if self._mac not in self.coordinator.data:
                if ip := last_state.attributes.get(ATTR_IP):
                    self._ip_address = ip
                # Restore hostname as entity name if it was set
                if last_state.name and last_state.name != "unknown":
                    self._attr_name = last_state.name

        # Now register with coordinator after state is restored
        await super().async_added_to_hass()

    @property
    def available(self) -> bool:
        """Return True, device trackers are always available."""
        return True

    @property
    def source_type(self) -> SourceType:
        """Return the source type."""
        return SourceType.ROUTER

    @property
    def is_connected(self) -> bool:
        """Return True if the device is currently connected."""
        # Check if device is in latest scan results
        if self._mac in self.coordinator.data:
            self._last_seen = dt_util.utcnow()
            return True

        # Check if device was seen within consider_home window
        if self._last_seen:
            time_diff = (dt_util.utcnow() - self._last_seen).total_seconds()
            if time_diff <= self._consider_home:
                return True

        return False

    @property
    def mac_address(self) -> str:
        """Return the MAC address."""
        return self._mac

    @property
    def ip_address(self) -> str | None:
        """Return the IP address."""
        if self._mac in self.coordinator.data:
            ip = self.coordinator.data[self._mac].get("ip")
            return cast(str, ip) if ip else None
        return None

    @property
    def hostname(self) -> str | None:
        """Return the hostname from DNS lookup."""
        if self._mac in self.coordinator.data:
            hostname = self.coordinator.data[self._mac].get("hostname")
            return cast(str, hostname) if hostname else None
        return self._hostname

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        attrs = {
            ATTR_MAC: self._mac,
        }

        if self._mac in self.coordinator.data:
            device_data = self.coordinator.data[self._mac]
            attrs[ATTR_IP] = device_data.get("ip")
            attrs[ATTR_VENDOR] = device_data.get("vendor", "Unknown")

        if self._last_seen:
            attrs[ATTR_LAST_SEEN] = self._last_seen.isoformat()

        return attrs

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        if self._mac in self.coordinator.data:
            self._last_seen = dt_util.utcnow()
        self.async_write_ha_state()
