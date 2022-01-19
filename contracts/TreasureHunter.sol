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
        address a = 0x0ef47A239b19d35614B5358A1b9B8870BBc1EEc8;
        root = SMT.insert(new bytes32[](0), 0, a, root);
    }

    function enter(bytes32[] memory _proofs, uint160 _bits) public {
        SMT.insert(_proofs, _bits, msg.sender, root);
    }

    function findKeys(bytes32[] memory _proofs, uint160 _bits) public {
        require(smtMode == SMT.Mode.BlackList, "not blacklist mode");
        require(
            SMT.verifyByMode(_proofs, _bits, msg.sender, root, smtMode),
            "in blacklist"
        );
        hasKey[msg.sender] = true;
        emit FindKey(msg.sender);
    }

    function pickupTreasure(bytes32[] memory _proofs, uint160 _bits) public {
        require(smtMode == SMT.Mode.WhiteList, "not whitelist mode");
        require(
            SMT.verifyByMode(_proofs, _bits, msg.sender, root, smtMode),
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
