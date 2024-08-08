// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import "forge-std/console2.sol";
import { LibZip } from "solady/utils/LibZip.sol";
import { ModeCode as ExecutionMode } from "erc7579/lib/ModeLib.sol";

library EncodeLib {
    using LibZip for bytes;
    using EncodeLib for *;

    function packMode(
        bytes memory data,
        SmartSessionMode mode,
        SignerId signerId
    )
        internal
        pure
        returns (bytes memory packed)
    {
        packed = abi.encodePacked(mode, signerId, data);
    }

    function unpackMode(bytes calldata packed)
        internal
        pure
        returns (SmartSessionMode mode, SignerId signerId, bytes calldata data)
    {
        mode = SmartSessionMode(uint8(bytes1(packed[:1])));
        signerId = SignerId.wrap(bytes32(packed[1:33]));
        data = packed[33:];
    }

    function getSignerIdFromSignature(bytes calldata packed) internal pure returns (SignerId signerId) {
        signerId = SignerId.wrap(bytes32(packed[1:33]));
    }

    function encodeUse(SignerId signerId, bytes memory sig) internal pure returns (bytes memory userOpSig) {
        bytes memory d = abi.encode(sig).flzCompress();
        userOpSig = d.packMode(SmartSessionMode.USE, signerId);
    }

    function decodeUse(bytes memory packedSig) internal pure returns (bytes memory signature) {
        (signature) = abi.decode(packedSig.flzDecompress(), (bytes));
    }

    function encodeEnable(
        SignerId signerId,
        bytes memory sig,
        EnableSessions memory enableData
    )
        internal
        pure
        returns (bytes memory packedSig)
    {
        bytes memory data = abi.encode(enableData, sig);
        data = data.flzCompress();
        packedSig = data.packMode(SmartSessionMode.UNSAFE_ENABLE, signerId);
    }

    function decodeEnable(bytes calldata packedSig)
        internal
        pure
        returns (EnableSessions memory enableData, bytes memory signature)
    {
        (enableData, signature) = abi.decode(packedSig.flzDecompress(), (EnableSessions, bytes));
    }

    function decodeInstall(bytes calldata enableData) internal pure returns (InstallSessions[] memory sessions) {
        sessions = abi.decode(enableData, (InstallSessions[]));
    }

    function encodeContext(
        uint192 nonceKey,
        ExecutionMode mode,
        SignerId signerId,
        EnableSessions memory enableData
    )
        internal
        pure
        returns (bytes memory context)
    {
        context = abi.encodePacked(nonceKey, mode, signerId, abi.encode(enableData));
    }
}
