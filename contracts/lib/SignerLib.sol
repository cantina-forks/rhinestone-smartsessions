// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import "../interfaces/ISigner.sol";
import { IdLib } from "./IdLib.sol";

library SignerLib {
    using IdLib for *;
    using FlatBytesLib for *;

    bytes4 internal constant EIP1271_SUCCESS = 0x1626ba7e;

    error SignerNotFound(SignerId signerId, address account);
    error InvalidSessionKeySignature(SignerId signerId, ISigner isigner, address account, bytes32 userOpHash);

    function requireValidISigner(
        mapping(SignerId => mapping(address => SignerConf)) storage $isigners,
        bytes32 hash,
        address account,
        SignerId signerId,
        bytes memory signature
    )
        internal
    {
        ISigner isigner = $isigners[signerId][account].isigner;
        if (address(isigner) == address(0)) revert SignerNotFound(signerId, account);

        // check signature of ISigner first.
        // policies only need to be processed if the signature is correct
        if (
            isigner.validateSignatureWithData({
                hash: hash,
                sig: signature,
                data: $isigners[signerId][account].config.load()
            }) == false
        ) revert InvalidSessionKeySignature(signerId, isigner, account, hash);
    }

    function isValidSigner(
        mapping(SignerId => mapping(address => SignerConf)) storage $isigners,
        bytes32 hash,
        address account,
        SignerId signerId,
        bytes memory signature
    )
        internal
        returns (bool valid)
    {
        ISigner isigner = $isigners[signerId][account].isigner;
        if (address(isigner) == address(0)) revert SignerNotFound(signerId, account);

        // check signature of ISigner first.
        // policies only need to be processed if the signature is correct
        valid = isigner.validateSignatureWithData({
            hash: hash,
            sig: signature,
            data: $isigners[signerId][account].config.load()
        });
    }
}
