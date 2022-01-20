pragma solidity >=0.8.0 <0.9.0;

import {SMT} from "./libraries/SMT.sol";

contract TreasureHunter {
    bytes32 public root;
    SMT.Mode public smtMode = SMT.Mode.WhiteList;
    bool public solved = false;

    mapping(address => bool) public hasTreasure;
    mapping(address => bool) public hasKey;

    event FindKey(address indexed _from);
    event PickupTreasure(address indexed _from);
    event OpenTreasure(address indexed _from);

    constructor() public {
        root = SMT.init();
        _init();
    }

    function _init() internal {
        address B = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
        address A = 0x0ef47A239b19d35614B5358A1b9B8870BBc1EEc8;
        SMT.Leaf[] memory newLeaves = new SMT.Leaf[](2);
        SMT.Leaf[] memory oldLeaves = new SMT.Leaf[](2);
        newLeaves[0] = SMT.Leaf({key: A, value: 1});
        newLeaves[1] = SMT.Leaf({key: B, value: 1});
        oldLeaves[0] = SMT.Leaf({key: A, value: 0});
        oldLeaves[1] = SMT.Leaf({key: B, value: 0});
        bytes32[] memory proof = new bytes32[](4);
        proof[
            0
        ] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[
            1
        ] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[
            2
        ] = 0x0000000000000000000000000000000000000000000000000000000000000048;
        proof[
            3
        ] = 0x000000000000000000000000000000000000000000000000000000000000009e;
        root = SMT.update(proof, newLeaves, oldLeaves, root);
    }

    function enter(bytes32[] memory _proofs) public {
        require(hasKey[msg.sender] == false);
        root = SMT.updateSingleTarget(_proofs, msg.sender, root, SMT.Method.Insert);
    }

    function leave(bytes32[] memory _proofs) public {
        require(hasTreasure[msg.sender] == false);
        root = SMT.updateSingleTarget(_proofs, msg.sender, root, SMT.Method.Delete);
    }

    function findKeys(bytes32[] memory _proofs) public {
        require(smtMode == SMT.Mode.BlackList, "not blacklist mode");
        address[] memory targets = new address[](1);
        targets[0] = msg.sender;
        require(
            SMT.verifyByMode(_proofs, targets, root, smtMode),
            "in blacklist"
        );
        hasKey[msg.sender] = true;
        smtMode = SMT.Mode.WhiteList;
        emit FindKey(msg.sender);
    }

    function pickupTreasure(bytes32[] memory _proofs) public {
        require(smtMode == SMT.Mode.WhiteList, "not whitelist mode");
        address[] memory targets = new address[](1);
        targets[0] = msg.sender;
        require(
            SMT.verifyByMode(_proofs, targets, root, smtMode),
            "not in whitelist"
        );
        hasTreasure[msg.sender] = true;
        smtMode = SMT.Mode.BlackList;
        emit PickupTreasure(msg.sender);
    }

    function openTreasure() public {
        require(hasTreasure[msg.sender] && hasKey[msg.sender], "can't");
        solved = true;
        emit OpenTreasure(msg.sender);
    }

    function isSolved() public view returns (bool) {
        return solved;
    }
}
