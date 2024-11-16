// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Oracle} from "../../contracts/Oracle.sol";

contract OracleHarness is Oracle {
    constructor(
        address _registry
    ) Oracle(_registry) {}

    function exposed_bitmapToNonSignerIds(
        uint256 bitmap
    ) external view returns (uint8[] memory) {
        return _bitmapToNonSignerIds(bitmap);
    }

}
