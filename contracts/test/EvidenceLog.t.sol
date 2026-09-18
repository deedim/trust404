pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {stdError} from "forge-std/StdError.sol";
import {Hashes} from "@openzeppelin/contracts/utils/cryptography/Hashes.sol";
import {EvidenceLog} from "../src/EvidenceLog.sol";

contract EvidenceLogTest is Test {
    EvidenceLog private evidenceLog;
    address private constant CUSTOMER = address(0xA11CE);
    address private constant INSTITUTION = address(0xBACC);
    bytes32 private constant REQUEST = keccak256("request");
    bytes32 private constant DECISION = keccak256("decision");

    function setUp() public {
        vm.warp(1000);
        evidenceLog = new EvidenceLog(INSTITUTION, 1);
    }

    function test_RequestAndDecision() public {
        _assertCheckpoint(0, 0, Hashes.commutativeKeccak256(bytes32(0), bytes32(0)), 1000);
        bytes32 requestLeaf = _leaf(0, 0, CUSTOMER, 0, REQUEST);
        bytes32 requestRoot = Hashes.commutativeKeccak256(requestLeaf, bytes32(0));
        vm.expectEmit(address(evidenceLog));
        emit EvidenceLog.EntryRecorded(0, 0, CUSTOMER, 0, REQUEST, 1000, 1);
        vm.expectEmit(address(evidenceLog));
        emit EvidenceLog.CheckpointPublished(1, 1, requestRoot, 1000);
        vm.prank(CUSTOMER);
        (uint256 index, uint256 checkpointId) = evidenceLog.registerRequest(REQUEST);
        assertEq(index, 0);
        assertEq(checkpointId, 1);

        vm.warp(1010);
        bytes32 root = Hashes.commutativeKeccak256(requestLeaf, _leaf(1, 1, INSTITUTION, 0, DECISION));
        vm.expectEmit(address(evidenceLog));
        emit EvidenceLog.EntryRecorded(1, 1, INSTITUTION, 0, DECISION, 1010, 2);
        vm.expectEmit(address(evidenceLog));
        emit EvidenceLog.CheckpointPublished(2, 2, root, 1010);
        vm.prank(INSTITUTION);
        (index, checkpointId) = evidenceLog.registerDecision(0, DECISION);
        assertEq(index, 1);
        assertEq(checkpointId, 2);
        assertEq(evidenceLog.size(), 2);
        assertEq(evidenceLog.root(), root);
        assertEq(evidenceLog.checkpointCount(), 3);
        _assertCheckpoint(1, 1, requestRoot, 1000);
        _assertCheckpoint(2, 2, root, 1010);
    }

    function test_RequestDeduplicationIsPerCustomer() public {
        vm.startPrank(CUSTOMER);
        evidenceLog.registerRequest(REQUEST);
        vm.expectRevert(EvidenceLog.DuplicateRequest.selector);
        evidenceLog.registerRequest(REQUEST);
        vm.stopPrank();
        (uint256 index,) = evidenceLog.registerRequest(REQUEST);
        assertEq(index, 1);
    }

    function test_DecisionValidation() public {
        vm.prank(CUSTOMER);
        evidenceLog.registerRequest(REQUEST);
        vm.expectRevert(EvidenceLog.Unauthorized.selector);
        evidenceLog.registerDecision(0, DECISION);

        vm.startPrank(INSTITUTION);
        vm.expectRevert(EvidenceLog.InvalidRequest.selector);
        evidenceLog.registerDecision(99, DECISION);
        evidenceLog.registerDecision(0, DECISION);
        vm.expectRevert(EvidenceLog.DuplicateDecision.selector);
        evidenceLog.registerDecision(0, DECISION);
        vm.expectRevert(EvidenceLog.InvalidRequest.selector);
        evidenceLog.registerDecision(1, DECISION);
        vm.stopPrank();

        vm.expectRevert(EvidenceLog.ZeroAddress.selector);
        new EvidenceLog(address(0), 1);
    }

    function test_ZeroHashesDoNotConsumeRegistration() public {
        vm.startPrank(CUSTOMER);
        vm.expectRevert(EvidenceLog.ZeroHash.selector);
        evidenceLog.registerRequest(bytes32(0));
        evidenceLog.registerRequest(REQUEST);
        vm.stopPrank();
        vm.startPrank(INSTITUTION);
        vm.expectRevert(EvidenceLog.ZeroHash.selector);
        evidenceLog.registerDecision(0, bytes32(0));
        evidenceLog.registerDecision(0, DECISION);
        vm.stopPrank();
        assertEq(evidenceLog.size(), 2);
        assertEq(evidenceLog.checkpointCount(), 3);
    }

    function test_SeparateCheckpointsPreserveScope() public {
        vm.prank(CUSTOMER);
        assertEq(evidenceLog.createCheckpoint(), 1);
        assertEq(abi.encode(evidenceLog.getCheckpoint(0)), abi.encode(evidenceLog.getCheckpoint(1)));
        evidenceLog.registerRequest(REQUEST);
        bytes32 root = evidenceLog.root();
        vm.warp(1060);
        vm.expectEmit(address(evidenceLog));
        emit EvidenceLog.CheckpointPublished(3, 1, root, 1060);
        assertEq(evidenceLog.createCheckpoint(), 3);
        assertEq(evidenceLog.size(), 1);
        assertEq(evidenceLog.checkpointCount(), 4);
        _assertCheckpoint(2, 1, root, 1000);
        _assertCheckpoint(3, 1, root, 1060);
    }

    function test_FullTreeRevertsWithoutChangingState() public {
        evidenceLog.registerRequest(REQUEST);
        evidenceLog.registerRequest(keccak256("second request"));
        bytes32 root = evidenceLog.root();
        vm.recordLogs();
        vm.expectRevert(stdError.memOverflowError);
        evidenceLog.registerRequest(keccak256("third request"));
        vm.prank(INSTITUTION);
        vm.expectRevert(stdError.memOverflowError);
        evidenceLog.registerDecision(0, DECISION);
        assertEq(vm.getRecordedLogs().length, 0);
        assertEq(evidenceLog.size(), 2);
        assertEq(evidenceLog.root(), root);
        assertEq(evidenceLog.checkpointCount(), 3);
        assertEq(evidenceLog.createCheckpoint(), 3);
    }

    function _leaf(uint256 index, uint8 kind, address actor, uint256 requestIndex, bytes32 payloadHash)
        private
        view
        returns (bytes32)
    {
        bytes32 inner = keccak256(
            abi.encode(
                block.chainid, address(evidenceLog), index, kind, actor, requestIndex, payloadHash, block.timestamp
            )
        );
        return keccak256(bytes.concat(inner));
    }

    function _assertCheckpoint(uint256 id, uint256 size, bytes32 root, uint256 issuedAt) private view {
        EvidenceLog.Checkpoint memory checkpoint = evidenceLog.getCheckpoint(id);
        assertEq(checkpoint.size, size);
        assertEq(checkpoint.root, root);
        assertEq(checkpoint.issuedAt, issuedAt);
    }
}
