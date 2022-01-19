pragma solidity >=0.8.0 <0.9.0;

uint256 constant SMT_STACK_SIZE = 32;

library SMT {
    struct Leaf {
        address key;
        uint8 value;
    }

    enum Mode {
        BlackList,
        WhiteList
    }

    function init() internal pure returns (bytes32) {
        return 0;
    }

    function calcLeaf(Leaf memory a) internal pure returns (bytes32) {
        if (a.value == 0) {
            return 0;
        } else {
            return keccak256(abi.encode(a.key, a.value));
        }
    }

    function merge(bytes32 l, bytes32 r) internal pure returns (bytes32) {
        if (l == 0) {
            return r;
        } else if (r == 0) {
            return l;
        } else {
            return keccak256(abi.encode(l, r));
        }
    }

    function insert(
        bytes32[] memory _proofs,
        address _target,
        bytes32 _prevRoot
    ) internal pure returns (bytes32) {
        Leaf memory nextLeaf = Leaf({key: _target, value: 1});
        Leaf memory prevLeaf = Leaf({key: _target, value: 0});
        Leaf[] memory nextLeaves = new Leaf[](1);
        Leaf[] memory prevLeaves = new Leaf[](1);
        nextLeaves[0] = nextLeaf;
        prevLeaves[0] = prevLeaf;
        return update(_proofs, nextLeaves, prevLeaves, _prevRoot);
    }

    function remove(
        bytes32[] memory _proofs,
        address _target,
        bytes32 _prevRoot
    )internal pure returns (bytes32){
        Leaf memory nextLeaf = Leaf({key: _target, value: 0});
        Leaf memory prevLeaf = Leaf({key: _target, value: 1});
        Leaf[] memory nextLeaves = new Leaf[](1);
        Leaf[] memory prevLeaves = new Leaf[](1);
        nextLeaves[0] = nextLeaf;
        prevLeaves[0] = prevLeaf;
        return update(_proofs, nextLeaves, prevLeaves, _prevRoot);
    }

    function verifyByMode(
        bytes32[] memory _proofs,
        address[] memory _target,
        bytes32 _expectedRoot,
        Mode _mode
    ) internal pure returns (bool) {
        Leaf[] memory leaves = new Leaf[](_target.length);
        for(uint i = 0;i<_target.length;i++){
            leaves[i] = Leaf({key: _target[i], value: uint8(_mode)});
        }
        return verify(_proofs, leaves, _expectedRoot);
    }

    
    function verify(
        bytes32[] memory _proofs,
        Leaf[] memory _leaves,
        bytes32 _expectedRoot
    ) internal pure returns (bool) {
        return (calcRoot(_proofs, _leaves) == _expectedRoot);
    }

    function update(
        bytes32[] memory _proofs,
        Leaf[] memory _nextLeaves,
        Leaf[] memory _prevLeaves,
        bytes32 _prevRoot
    ) internal pure returns (bytes32) {
        require(
            verify(_proofs, _prevLeaves, _prevRoot),
            "update proof not valid"
        );
        return calcRoot(_proofs, _nextLeaves);
    }

    function checkGroupSorted(Leaf[] memory _leaves)internal pure returns (bool){
        require(_leaves.length >= 1);
        uint160 temp = 0;
        for(uint i = 0;i < _leaves.length;i++){
            if(temp >= uint160(_leaves[i].key)){
                return false;
            }
            temp = uint160(_leaves[i].key);
        }
        return true;
    }
    function getBit(uint160 key,uint256 height) internal pure returns(uint256){
        if(height>=160){
            revert();
        }
        return (key>>height)&1;
    }
    function parentPath(uint160 key,uint256 height) internal pure returns(uint160){
        if(height>=160){
            revert();
        }
        return copyBit(key,height+1);
    }

    function copyBit(uint160 key,uint256 height) internal pure returns(uint160){
        if(height>=160){
            revert();
        }
        return ((key>>height)<<height);
    }

    function calcRoot(
        bytes32[] memory _proofs,
        Leaf[] memory _leaves
    )internal pure returns (bytes32){
        require(checkGroupSorted(_leafs));
        uint160[] memory stack_keys = new uint160[](SMT_STACK_SIZE);
        bytes32[] memory stack_values = new bytes32[](SMT_STACK_SIZE);
        uint proof_index = 0;
        uint leave_index = 0;
        uint stack_top = 0;

        while(proof_index < _proofs.length){
            if(uint256(_proofs[proof_index]) == 0x4c){
                proof_index++;
                if(stack_top >= SMT_STACK_SIZE){
                    revert();
                }
                if(leave_index >= _leaves.length){
                    revert();
                }
                stack_keys[stack_top] = uint160(_leaves[leave_index].key);
                stack_values[stack_top] = calcLeaf(_leaves[leave_index]);
                stack_top++;
                leave_index++;
            }else if(uint256(_proofs[proof_index]) == 0x50){
                proof_index++;
                if(stack_top==0){
                    revert();
                }
                if(proof_index + 2>_proofs.length){
                    revert();
                }
                uint256 height = uint256(_proofs[proof_index++]);
                bytes32 current_proof = _proofs[proof_index++];
                if(getBit(stack_keys[stack_top-1],height)==1){
                    stack_values[stack_top-1] = merge(current_proof,stack_values[stack_top-1]);
                }else{
                    stack_values[stack_top-1] = merge(stack_values[stack_top-1],current_proof);
                }
                stack_keys[stack_top-1] = parentPath(stack_keys[stack_top-1],height);

            }else if(uint256(_proofs[proof_index]) == 0x48){
                proof_index++;
                if(stack_top < 2){
                    revert();
                }
                if(proof_index >= _proofs.length){
                    revert();
                }
                uint256 height = uint256(_proofs[proof_index++]);
                uint256 a_set = getBit(stack_keys[stack_top - 2],height);
                uint256 b_set = getBit(stack_keys[stack_top - 1],height);
                stack_keys[stack_top - 2] = parentPath(stack_keys[stack_top - 2],height);
                stack_keys[stack_top - 1] = parentPath(stack_keys[stack_top - 1],height);
                require(stack_keys[stack_top - 2] == stack_keys[stack_top - 1]&&a_set != b_set);

                if(a_set == 1){
                    stack_values[stack_top - 2] = merge(stack_values[stack_top - 1],stack_values[stack_top - 2]);
                }else{
                    stack_values[stack_top - 2] = merge(stack_values[stack_top - 2],stack_values[stack_top - 1]);
                }
                stack_top -= 1;
            }else{
                revert();
            }
        }
        if(leave_index != _leafs.length){
            revert();
        }
        if(stack_top != 1){
            revert();
        }
        return stack_values[0]; 
    }

}

contract SMTTEST{
    bytes32 public root_hash;
    SMT.Mode public mode;
    constructor () public{
        root_hash = SMT.init();
        mode = SMT.Mode.BlackList;
    }
    function test() public returns(bytes32){
        address B = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
        address A = 0x0ef47A239b19d35614B5358A1b9B8870BBc1EEc8;
        SMT.Leaf memory a = SMT.Leaf({key: A, value: 1});
        SMT.Leaf memory b = SMT.Leaf({key: B, value: 1});
        return SMT.merge(SMT.calcLeaf(a),SMT.calcLeaf(b));
    }
    function test1() public returns (bytes32){
        bytes32 root_test1;
        address B = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
        address A = 0x0ef47A239b19d35614B5358A1b9B8870BBc1EEc8;
        bytes32[] memory proofA = new bytes32[](1);
        proofA[0] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        root_test1 = SMT.insert(proofA,A,root_hash);
        // height = 0x9e
        bytes32[] memory proofB = new bytes32[](4);
        proofB[0] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proofB[1] = 0x0000000000000000000000000000000000000000000000000000000000000050;
        proofB[2] = 0x000000000000000000000000000000000000000000000000000000000000009e;
        proofB[3] = 0xc900f070e856257e6229f01632ed3eb7117f32834209f831c24e464c9ab81eaf;
        root_test1 = SMT.insert(proofB,B,root_test1);
        return root_test1;
    }
    function test2() public returns (bytes32){
        address B = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
        address A = 0x0ef47A239b19d35614B5358A1b9B8870BBc1EEc8;
        SMT.Leaf memory oldA = SMT.Leaf({key: A, value: 0});
        SMT.Leaf memory oldB = SMT.Leaf({key: B, value: 0});
        SMT.Leaf memory newA = SMT.Leaf({key: A, value: 1});
        SMT.Leaf memory newB = SMT.Leaf({key: B, value: 1});
        SMT.Leaf[] memory newleafs = new SMT.Leaf[](2);
        SMT.Leaf[] memory oldleafs = new SMT.Leaf[](2);
        newleafs[0] = newA;
        newleafs[1] = newB;
        oldleafs[0] = oldA;
        oldleafs[1] = oldB;
        bytes32[] memory proof = new bytes32[](4);
        proof[0] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[1] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[2] = 0x0000000000000000000000000000000000000000000000000000000000000048;
        proof[3] = 0x000000000000000000000000000000000000000000000000000000000000009e;
        root_hash = SMT.update(proof,newleafs,oldleafs,root_hash);
        return root_hash;
    }
    function exp() public returns(bool){
        address B = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
        address[] memory target = new address[](1);
        target[0] = B;
        bytes32[] memory proof = new bytes32[](7);
        proof[0] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[1] = 0x0000000000000000000000000000000000000000000000000000000000000050;
        proof[2] = 0x0000000000000000000000000000000000000000000000000000000000000001;
        proof[3] = 0x36306db541fd1551fd93a60031e8a8c89d69ddef41d6249f5fdc265dbc8fffa2;
        proof[4] = 0x0000000000000000000000000000000000000000000000000000000000000050;
        proof[5] = 0x000000000000000000000000000000000000000000000000000000000000009e;
        proof[6] = 0xc900f070e856257e6229f01632ed3eb7117f32834209f831c24e464c9ab81eaf;
        return SMT.verifyByMode(proof,target,root_hash,mode);
    }
    //leaf a = 0xc900f070e856257e6229f01632ed3eb7117f32834209f831c24e464c9ab81eaf
    // leaf b = 0x36306db541fd1551fd93a60031e8a8c89d69ddef41d6249f5fdc265dbc8fffa2
    /*
    function testinsert() public{
        
        address B = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
        address A = 0x0ef47A239b19d35614B5358A1b9B8870BBc1EEc8;
    }
    */

}

