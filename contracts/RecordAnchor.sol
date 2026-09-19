// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract RecordAnchor {
    struct Batch {
        bytes32 root;
        uint256 count;
        uint256 blockNumber;
        uint256 anchoredAt;
    }

    error Unauthorized();
    error InvalidPublisher();
    error InvalidBatch();
    error UnexpectedBatchId();

    address public immutable publisher;
    uint256 public batchCount;
    mapping(uint256 => Batch) public batches;

    event BatchAnchored(uint256 indexed batchId, bytes32 root, uint256 count, uint256 blockNumber, uint256 anchoredAt);

    constructor(address publisher_) {
        if (publisher_ == address(0)) revert InvalidPublisher();
        publisher = publisher_;
    }

    function anchorBatch(uint256 expectedBatchId, bytes32 root, uint256 count) external {
        if (msg.sender != publisher) revert Unauthorized();
        if (expectedBatchId != batchCount + 1) revert UnexpectedBatchId();
        if (count == 0 || count > 32 || root == bytes32(0)) revert InvalidBatch();
        batches[expectedBatchId] = Batch(root, count, block.number, block.timestamp);
        batchCount = expectedBatchId;
        emit BatchAnchored(expectedBatchId, root, count, block.number, block.timestamp);
    }
}
