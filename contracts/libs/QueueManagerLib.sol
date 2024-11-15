// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {EpochLib} from "./EpochLib.sol";

library QueueManager {
    struct QueueConfig {
        uint256 maxQueueSize;
        uint256 maxChurnPerEpoch;
    }

    struct QueueState {
        uint256 pendingCount;
        mapping(uint256 => uint256) epochBitmap;
    }

    function getNextEpoch(
        QueueState storage self,
        QueueConfig storage config,
        EpochLib.EpochConfig storage epochConfig
    ) internal view returns (uint256) {
        uint256 currentSlot = EpochLib.currentSlot(epochConfig);
        uint256 currentEpoch = EpochLib.slotToEpoch(currentSlot, epochConfig);
        uint256 epochsNeeded = (self.pendingCount + config.maxChurnPerEpoch - 1) / config.maxChurnPerEpoch;
        return currentEpoch + epochsNeeded;
    }
}