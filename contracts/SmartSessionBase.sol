// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "./DataTypes.sol";

import { ISigner } from "./interfaces/ISigner.sol";
import "@rhinestone/flatbytes/src/BytesLib.sol";
import { SentinelList4337Lib } from "sentinellist/SentinelList4337.sol";
import { ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { ConfigLib } from "./lib/ConfigLib.sol";
import { EncodeLib } from "./lib/EncodeLib.sol";
import { IdLib } from "./lib/IdLib.sol";
import { HashLib } from "./lib/HashLib.sol";

abstract contract SmartSessionBase is ERC7579ValidatorBase {
    using FlatBytesLib for *;
    using ConfigLib for *;
    using EncodeLib for *;
    using IdLib for *;
    using HashLib for *;
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;
    using ArrayMap4337Lib for *;
    using ConfigLib for Policy;
    using ConfigLib for EnumerableActionPolicy;

    error InvalidISigner(ISigner isigner);

    event SessionRemoved(SignerId signerId, address smartAccount);

    Policy internal $userOpPolicies;
    Policy internal $erc1271Policies;
    EnumerableActionPolicy internal $actionPolicies;
    mapping(ISigner signer => mapping(address smartAccount => uint256 nonce)) internal $signerNonce;

    mapping(SignerId signerId => mapping(address smartAccount => SignerConf)) internal $isigners;

    function _enableISigner(SignerId signerId, address account, ISigner isigner, bytes memory signerConfig) internal {
        if (!isigner.supportsInterface(type(ISigner).interfaceId)) {
            revert InvalidISigner(isigner);
        }
        SignerConf storage $conf = $isigners[signerId][account];
        $conf.isigner = isigner;
        $conf.config.store(signerConfig);
    }

    function enableUserOpPolicies(SignerId signerId, PolicyData[] memory userOpPolicies) public {
        $userOpPolicies.enable({
            signerId: signerId,
            sessionId: signerId.toUserOpPolicyId().toSessionId(),
            policyDatas: userOpPolicies,
            smartAccount: msg.sender
        });
    }

    function enableERC1271Policies(SignerId signerId, PolicyData[] memory erc1271Policies) public {
        $erc1271Policies.enable({
            signerId: signerId,
            sessionId: signerId.toErc1271PolicyId().toSessionId(),
            policyDatas: erc1271Policies,
            smartAccount: msg.sender
        });
    }

    function enableActionPolicies(SignerId signerId, ActionData[] memory actionPolicies) public {
        $actionPolicies.enable({ signerId: signerId, actionPolicyDatas: actionPolicies, smartAccount: msg.sender });
    }

    function enableSessions(InstallSessions[] memory sessions) public {
        uint256 length = sessions.length;
        for (uint256 i; i < length; i++) {
            SignerId signerId = sessions[i].signerId;
            enableUserOpPolicies({ signerId: signerId, userOpPolicies: sessions[i].userOpPolicies });
            enableERC1271Policies({ signerId: signerId, erc1271Policies: sessions[i].erc1271Policies });
            enableActionPolicies({ signerId: signerId, actionPolicies: sessions[i].actions });
        }
    }

    function removeSession(SignerId signerId) external {
        $userOpPolicies.policyList[signerId].disable(signerId.toUserOpPolicyId().toSessionId(), msg.sender);
        $erc1271Policies.policyList[signerId].disable(signerId.toErc1271PolicyId().toSessionId(), msg.sender);

        uint256 actionLength = $actionPolicies.enabledActionIds[signerId].length(msg.sender);
        for (uint256 i; i < actionLength; i++) {
            ActionId actionId = ActionId.wrap($actionPolicies.enabledActionIds[signerId].get(msg.sender, i));
            $actionPolicies.actionPolicies[actionId].policyList[signerId].disable(
                signerId.toSessionId(actionId), msg.sender
            );
        }
        emit SessionRemoved(signerId, msg.sender);
    }

    function setSigner(SignerId signerId, ISigner signer, bytes memory initData) external {
        _enableISigner(signerId, msg.sender, signer, initData);
    }

    /**
     * Initialize the module with the given data
     *
     * @param data The data to initialize the module with
     */
    function onInstall(bytes calldata data) external override {
        if (data.length == 0) return;

        InstallSessions[] memory sessions = abi.decode(data, (InstallSessions[]));
        enableSessions(sessions);
    }

    /**
     * De-initialize the module with the given data
     *
     * @param data The data to de-initialize the module with
     */
    function onUninstall(bytes calldata data) external override { }

    function isInitialized(address smartAccount) external view returns (bool) { }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == TYPE_VALIDATOR;
    }

    function getDigest(ISigner isigner, address account, EnableSessions memory data) external view returns (bytes32) {
        uint256 nonce = $signerNonce[isigner][account];
        return data.digest(nonce);
    }

    function getSignerId(ISigner isigner, bytes memory isignerInitData) public pure returns (SignerId signerId) {
        signerId = SignerId.wrap(keccak256(abi.encode(isigner, isignerInitData)));
    }

    function _isISignerSet(SignerId signerId, address account) internal view returns (bool) {
        return address($isigners[signerId][account].isigner) != address(0);
    }
}
