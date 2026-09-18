pragma solidity ^0.8.24;

import {MerkleTree} from "@openzeppelin/contracts/utils/structs/MerkleTree.sol";

contract EvidenceLog {
    using MerkleTree for MerkleTree.Bytes32PushTree;

    enum RequestState {
        Missing,
        Pending,
        Decided
    }

    struct Checkpoint {
        uint256 size;
        bytes32 root;
        uint256 issuedAt;
    }

    error ZeroAddress();
    error ZeroHash();
    error Unauthorized();
    error InvalidRequest();
    error DuplicateRequest();
    error DuplicateDecision();

    event EntryRecorded(
        uint256 indexed index,
        uint8 kind,
        address indexed actor,
        uint256 indexed requestIndex,
        bytes32 payloadHash,
        uint256 recordedAt,
        uint256 checkpointId
    );
    event CheckpointPublished(uint256 indexed checkpointId, uint256 size, bytes32 root, uint256 issuedAt);

    address public immutable institution;
    uint256 public size;
    bytes32 public root;
    MerkleTree.Bytes32PushTree private _tree;
    Checkpoint[] private _checkpoints;
    mapping(uint256 => RequestState) private _requests;
    mapping(address => mapping(bytes32 => bool)) private _requestHashes;

    constructor(address institution_, uint8 treeDepth) {
        if (institution_ == address(0)) revert ZeroAddress();
        institution = institution_;
        root = _tree.setup(treeDepth, bytes32(0));
        createCheckpoint();
    }

    function depth() external view returns (uint256) {
        return _tree.depth();
    }

    function checkpointCount() external view returns (uint256) {
        return _checkpoints.length;
    }

    function getCheckpoint(uint256 checkpointId) external view returns (Checkpoint memory) {
        return _checkpoints[checkpointId];
    }

    function registerRequest(bytes32 requestHash) external returns (uint256 requestIndex, uint256 checkpointId) {
        if (_requestHashes[msg.sender][requestHash]) revert DuplicateRequest();
        _requestHashes[msg.sender][requestHash] = true;
        _requests[size] = RequestState.Pending;
        return _append(0, size, requestHash);
    }

    function registerDecision(uint256 requestIndex, bytes32 decisionHash)
        external
        returns (uint256 decisionIndex, uint256 checkpointId)
    {
        if (msg.sender != institution) revert Unauthorized();
        RequestState state = _requests[requestIndex];
        if (state == RequestState.Missing) revert InvalidRequest();
        if (state == RequestState.Decided) revert DuplicateDecision();
        _requests[requestIndex] = RequestState.Decided;
        return _append(1, requestIndex, decisionHash);
    }

    function createCheckpoint() public returns (uint256 checkpointId) {
        checkpointId = _checkpoints.length;
        _checkpoints.push(Checkpoint(size, root, block.timestamp));
        emit CheckpointPublished(checkpointId, size, root, block.timestamp);
    }

    function _append(uint8 kind, uint256 requestIndex, bytes32 payloadHash)
        private
        returns (uint256 index, uint256 checkpointId)
    {
        if (payloadHash == bytes32(0)) revert ZeroHash();
        index = size++;
        bytes32 inner = keccak256(
            abi.encode(
                block.chainid, address(this), index, kind, msg.sender, requestIndex, payloadHash, block.timestamp
            )
        );
        (, root) = _tree.push(keccak256(bytes.concat(inner)));
        checkpointId = _checkpoints.length;
        emit EntryRecorded(index, kind, msg.sender, requestIndex, payloadHash, block.timestamp, checkpointId);
        createCheckpoint();
    }
}
