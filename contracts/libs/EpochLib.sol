// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title EpochLib
 * @notice Library for epoch-related calculations and conversions
 * @dev This library handles conversions between timestamps, slots, and epochs
 *
 * Key terms:
 * - slot: An individual time unit, the smallest unit of time in the system
 * - epoch: A collection of consecutive slots (slotsPerEpoch)
 * - genesisTime: The timestamp when slot 0 began
 * - slotsPerEpoch: Number of slots that make up one epoch
 * - secondsPerSlot: Duration of each slot in seconds
 */
library EpochLib {
    struct EpochConfig {
        uint256 slotsPerEpoch;
        uint256 genesisTime;
        uint256 secondsPerSlot;
    }

    function slotToEpoch(uint256 slot, EpochConfig storage config) internal view returns (uint256) {
        return slot / config.slotsPerEpoch;
    }

    function epochStartSlot(uint256 epoch, EpochConfig storage config) internal view returns (uint256) {
        return epoch * config.slotsPerEpoch;
    }

    function epochEndSlot(uint256 epoch, EpochConfig storage config) internal view returns (uint256) {
        return (epoch + 1) * config.slotsPerEpoch - 1;
    }

    function slotToTime(
        uint256 slot,
        EpochConfig storage config
    ) internal view returns (uint256) {
        return config.genesisTime + slot * config.secondsPerSlot;
    }

    function timeToSlot(
        uint256 timestamp,
        EpochConfig storage config
    ) internal view returns (uint256) {
        require(timestamp >= config.genesisTime, "Time is before genesis");
        return (timestamp - config.genesisTime) / config.secondsPerSlot;
    }

    function currentSlot(
        EpochConfig storage config
    ) internal view returns (uint256) {
        return timeToSlot(block.timestamp, config);
    }

    function epochStartTime(
        uint256 epoch,
        EpochConfig storage config
    ) internal view returns (uint256) {
        uint256 startSlot = epochStartSlot(epoch, config);
        return slotToTime(startSlot, config);
    }

    function epochEndTime(
        uint256 epoch,
        EpochConfig storage config
    ) internal view returns (uint256) {
        uint256 endSlot = epochEndSlot(epoch, config);
        return slotToTime(endSlot, config);
    }
}
