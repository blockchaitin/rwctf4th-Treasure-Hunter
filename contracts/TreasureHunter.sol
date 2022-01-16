pragma solidity >=0.8.0 <0.9.0;

import {SMT} from "./libraries/SMT.sol";

contract TreasureHunter {
    bytes32 public root;
    SMT.Mode public smtMode;
    mapping(address => bool) public hasTreasure;
    mapping(address => bool) public hasKey;
    bool public isSolved;

    event FindKey(address indexed _from);
    event PickupTreasure(address indexed _from);
    event OpenTreasure(address indexed _from);

    constructor() {
        root = SMT.init();
        smtMode = SMT.Mode.WhiteList;
        _init();
    }

    function _init() internal {
        bytes32[] memory proofs = new bytes32[](0);
        uint160 bits = 0;
        address A = 0x0ef47A239b19d35614B5358A1b9B8870BBc1EEc8;
        root = insert(proofs, bits, A);

        address B = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
        bytes32[] memory proofs = new bytes32[](20);
        proofs[
            0
        ] = 0xc900f070e856257e6229f01632ed3eb7117f32834209f831c24e464c9ab81eaf;
        for (uint8 i = 1; i < 20; i++) {
            proofs[i] = 0;
        }
        uint160 bits = 1;
        root = insert(proofs, bits, B);
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
        isSolved = true;
        emit OpenTreasure(msg.sender);
    }

    function isSolved() public view returns (bool) {
        return isSolved;
    }
}
