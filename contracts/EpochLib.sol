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
    function slotToEpoch(uint256 slot, uint256 slotsPerEpoch) internal pure returns (uint256) {
        return slot / slotsPerEpoch;
    }

    function epochStartSlot(uint256 epoch, uint256 slotsPerEpoch) internal pure returns (uint256) {
        return epoch * slotsPerEpoch;
    }

    function epochEndSlot(uint256 epoch, uint256 slotsPerEpoch) internal pure returns (uint256) {
        return (epoch + 1) * slotsPerEpoch - 1;
    }

    function slotToTime(
        uint256 slot,
        uint256 genesisTime,
        uint256 secondsPerSlot
    ) internal pure returns (uint256) {
        return genesisTime + slot * secondsPerSlot;
    }

    function timeToSlot(
        uint256 timestamp,
        uint256 genesisTime,
        uint256 secondsPerSlot
    ) internal pure returns (uint256) {
        require(timestamp >= genesisTime, "Time is before genesis");
        return (timestamp - genesisTime) / secondsPerSlot;
    }

    function currentSlot(
        uint256 genesisTime,
        uint256 secondsPerSlot
    ) internal view returns (uint256) {
        return timeToSlot(block.timestamp, genesisTime, secondsPerSlot);
    }

    function currentEpoch(
        uint256 genesisTime,
        uint256 secondsPerSlot,
        uint256 slotsPerEpoch
    ) internal view returns (uint256) {
        uint256 slot = currentSlot(genesisTime, secondsPerSlot);
        return slotToEpoch(slot, slotsPerEpoch);
    }

    function epochStartTime(
        uint256 epoch,
        uint256 genesisTime,
        uint256 slotsPerEpoch,
        uint256 secondsPerSlot
    ) internal pure returns (uint256) {
        uint256 startSlot = epochStartSlot(epoch, slotsPerEpoch);
        return slotToTime(startSlot, genesisTime, secondsPerSlot);
    }

    function epochEndTime(
        uint256 epoch,
        uint256 genesisTime,
        uint256 slotsPerEpoch,
        uint256 secondsPerSlot
    ) internal pure returns (uint256) {
        uint256 endSlot = epochEndSlot(epoch, slotsPerEpoch);
        return slotToTime(endSlot, genesisTime, secondsPerSlot);
    }
}
