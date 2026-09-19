// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import {RecordAnchor} from "../RecordAnchor.sol";

interface Vm {
    function prank(address) external;
    function expectRevert(bytes4) external;
    function warp(uint256) external;
    function roll(uint256) external;
}
contract RecordAnchorTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    RecordAnchor anchor;
    function setUp() public { anchor = new RecordAnchor(address(this)); }
    function testStoresChainTimeAndPreservesOldBatch() public {
        vm.warp(1000); vm.roll(10);
        anchor.anchorBatch(1, bytes32(uint256(1)), 2);
        vm.warp(1100); vm.roll(20);
        anchor.anchorBatch(2, bytes32(uint256(2)), 3);
        (bytes32 root, uint256 count, uint256 number, uint256 time) = anchor.batches(1);
        require(root == bytes32(uint256(1)) && count == 2 && number == 10 && time == 1000);
        require(anchor.batchCount() == 2);
    }
    function testRejectsUnauthorizedAndOverwrite() public {
        vm.prank(address(123)); vm.expectRevert(RecordAnchor.Unauthorized.selector);
        anchor.anchorBatch(1, bytes32(uint256(1)), 1);
        anchor.anchorBatch(1, bytes32(uint256(1)), 1);
        vm.expectRevert(RecordAnchor.UnexpectedBatchId.selector);
        anchor.anchorBatch(1, bytes32(uint256(2)), 1);
    }
    function testRejectsEmptyOversizeAndZeroRoot() public {
        vm.expectRevert(RecordAnchor.InvalidBatch.selector); anchor.anchorBatch(1, bytes32(uint256(1)), 0);
        vm.expectRevert(RecordAnchor.InvalidBatch.selector); anchor.anchorBatch(1, bytes32(uint256(1)), 33);
        vm.expectRevert(RecordAnchor.InvalidBatch.selector); anchor.anchorBatch(1, bytes32(0), 1);
        vm.expectRevert(RecordAnchor.InvalidPublisher.selector); new RecordAnchor(address(0));
    }
    function testFuzzAcceptedCount(uint8 count) public {
        uint256 n = uint256(count) % 32 + 1;
        anchor.anchorBatch(1, bytes32(uint256(1)), n);
        (, uint256 stored,,) = anchor.batches(1); require(stored == n);
    }
}
contract TestToken {
    mapping(address => uint256) public balanceOf;
    function setBalance(address owner, uint256 amount) external { balanceOf[owner] = amount; }
}
