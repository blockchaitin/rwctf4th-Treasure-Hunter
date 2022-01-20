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
        address YFI = 0x0bc529c00C6401aEF6D220BE8C6Ea1667F6Ad93e;
        address Uniswap = 0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45;
        address Dai = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
        address Sushi = 0x6B3595068778DD592e39A122f4f5a5cF09C90fE2;
        address VB = 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B;
        address COMP = 0xc00e94Cb662C3520282E6f5717214004A7f26888;
        address CRV = 0xD533a949740bb3306d119CC777fa900bA034cd52;
        address USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
        
        SMT.Leaf[] memory newLeaves = new SMT.Leaf[](8);
        SMT.Leaf[] memory oldLeaves = new SMT.Leaf[](8);
        newLeaves[0] = SMT.Leaf({key: YFI, value: 1});
        newLeaves[1] = SMT.Leaf({key: Uniswap, value: 1});
        newLeaves[2] = SMT.Leaf({key: Dai, value: 1});
        newLeaves[3] = SMT.Leaf({key: Sushi, value: 1});
        
        newLeaves[4] = SMT.Leaf({key: VB, value: 1});
        newLeaves[5] = SMT.Leaf({key: COMP, value: 1});
        newLeaves[6] = SMT.Leaf({key: CRV, value: 1});
        newLeaves[7] = SMT.Leaf({key: USDT, value: 1});
        
        oldLeaves[0] = SMT.Leaf({key: YFI, value: 0});
        oldLeaves[1] = SMT.Leaf({key: Uniswap, value: 0});
        oldLeaves[2] = SMT.Leaf({key: Dai, value: 0});
        oldLeaves[3] = SMT.Leaf({key: Sushi, value: 0});
        
        oldLeaves[4] = SMT.Leaf({key: VB, value: 0});
        oldLeaves[5] = SMT.Leaf({key: COMP, value: 0});
        oldLeaves[6] = SMT.Leaf({key: CRV, value: 0});
        oldLeaves[7] = SMT.Leaf({key: USDT, value: 0});
        
        bytes32[] memory proof = new bytes32[](22);
        proof[0] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[1] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[2] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[3] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[4] = 0x0000000000000000000000000000000000000000000000000000000000000048;
        proof[5] = 0x0000000000000000000000000000000000000000000000000000000000000095;
        proof[6] = 0x0000000000000000000000000000000000000000000000000000000000000048;
        proof[7] = 0x0000000000000000000000000000000000000000000000000000000000000099;
        proof[8] = 0x0000000000000000000000000000000000000000000000000000000000000048;
        proof[9] = 0x000000000000000000000000000000000000000000000000000000000000009e;
        proof[10] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[11] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[12] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[13] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[14] = 0x0000000000000000000000000000000000000000000000000000000000000048;
        proof[15] = 0x000000000000000000000000000000000000000000000000000000000000009b;
        proof[16] = 0x0000000000000000000000000000000000000000000000000000000000000048;
        proof[17] = 0x000000000000000000000000000000000000000000000000000000000000009c;
        proof[18] = 0x0000000000000000000000000000000000000000000000000000000000000048;
        proof[19] = 0x000000000000000000000000000000000000000000000000000000000000009e;
        proof[20] = 0x0000000000000000000000000000000000000000000000000000000000000048;
        proof[21] = 0x000000000000000000000000000000000000000000000000000000000000009f;
        
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
