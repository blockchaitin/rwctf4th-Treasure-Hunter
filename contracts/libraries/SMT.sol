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
    function verifySingleTargetByMode(
        bytes32[] memory _proofs,
        address target,
        bytes32 _expectedRoot,
        Mode _mode) internal pure returns (bool){
        address[] memory targets = new address[](1);
        targets[0] = target;
        return verifyByMode(_proofs,targets,_expectedRoot,_mode);
    }
    function verifyByMode(
        bytes32[] memory _proofs,
        address[] memory _targets,
        bytes32 _expectedRoot,
        Mode _mode
    ) internal pure returns (bool) {
        Leaf[] memory leaves = new Leaf[](_targets.length);
        for (uint256 i = 0; i < _targets.length; i++) {
            leaves[i] = Leaf({key: _targets[i], value: uint8(_mode)});
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
    ) internal pure returns (bytes32) {
        Leaf memory nextLeaf = Leaf({key: _target, value: 0});
        Leaf memory prevLeaf = Leaf({key: _target, value: 1});
        Leaf[] memory nextLeaves = new Leaf[](1);
        Leaf[] memory prevLeaves = new Leaf[](1);
        nextLeaves[0] = nextLeaf;
        prevLeaves[0] = prevLeaf;
        return update(_proofs, nextLeaves, prevLeaves, _prevRoot);
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

    function checkGroupSorted(Leaf[] memory _leaves)
        internal
        pure
        returns (bool)
    {
        require(_leaves.length >= 1);
        uint160 temp = 0;
        for (uint256 i = 0; i < _leaves.length; i++) {
            if (temp >= uint160(_leaves[i].key)) {
                return false;
            }
            temp = uint160(_leaves[i].key);
        }
        return true;
    }

    function getBit(uint160 key, uint256 height)
        internal
        pure
        returns (uint256)
    {
        if (height >= 160) {
            revert();
        }
        return (key >> height) & 1;
    }

    function parentPath(uint160 key, uint256 height)
        internal
        pure
        returns (uint160)
    {
        if (height >= 160) {
            revert();
        }
        return copyBit(key, height + 1);
    }

    function copyBit(uint160 key, uint256 height)
        internal
        pure
        returns (uint160)
    {
        if (height >= 160) {
            revert();
        }
        return ((key >> height) << height);
    }

    function calcRoot(bytes32[] memory _proofs, Leaf[] memory _leaves)
        internal
        pure
        returns (bytes32)
    {
        require(checkGroupSorted(_leaves));
        uint160[] memory stackKeys = new uint160[](SMT_STACK_SIZE);
        bytes32[] memory stackValues = new bytes32[](SMT_STACK_SIZE);
        uint256 proofIndex = 0;
        uint256 leaveIndex = 0;
        uint256 stackTop = 0;

        while (proofIndex < _proofs.length) {
            if (uint256(_proofs[proofIndex]) == 0x4c) {
                proofIndex++;
                if (stackTop >= SMT_STACK_SIZE) {
                    revert();
                }
                if (leaveIndex >= _leaves.length) {
                    revert();
                }
                stackKeys[stackTop] = uint160(_leaves[leaveIndex].key);
                stackValues[stackTop] = calcLeaf(_leaves[leaveIndex]);
                stackTop++;
                leaveIndex++;
            } else if (uint256(_proofs[proofIndex]) == 0x50) {
                proofIndex++;
                if (stackTop == 0) {
                    revert();
                }
                if (proofIndex + 2 > _proofs.length) {
                    revert();
                }
                uint256 height = uint256(_proofs[proofIndex++]);
                bytes32 currentProof = _proofs[proofIndex++];
                if (getBit(stackKeys[stackTop - 1], height) == 1) {
                    stackValues[stackTop - 1] = merge(
                        currentProof,
                        stackValues[stackTop - 1]
                    );
                } else {
                    stackValues[stackTop - 1] = merge(
                        stackValues[stackTop - 1],
                        currentProof
                    );
                }
                stackKeys[stackTop - 1] = parentPath(
                    stackKeys[stackTop - 1],
                    height
                );
            } else if (uint256(_proofs[proofIndex]) == 0x48) {
                proofIndex++;
                if (stackTop < 2) {
                    revert();
                }
                if (proofIndex >= _proofs.length) {
                    revert();
                }
                uint256 height = uint256(_proofs[proofIndex++]);
                uint256 aSet = getBit(stackKeys[stackTop - 2], height);
                uint256 bSet = getBit(stackKeys[stackTop - 1], height);
                stackKeys[stackTop - 2] = parentPath(
                    stackKeys[stackTop - 2],
                    height
                );
                stackKeys[stackTop - 1] = parentPath(
                    stackKeys[stackTop - 1],
                    height
                );
                require(
                    stackKeys[stackTop - 2] == stackKeys[stackTop - 1] &&
                        aSet != bSet
                );

                if (aSet == 1) {
                    stackValues[stackTop - 2] = merge(
                        stackValues[stackTop - 1],
                        stackValues[stackTop - 2]
                    );
                } else {
                    stackValues[stackTop - 2] = merge(
                        stackValues[stackTop - 2],
                        stackValues[stackTop - 1]
                    );
                }
                stackTop -= 1;
            } else {
                revert();
            }
        }
        if (leaveIndex != _leaves.length) {
            revert();
        }
        if (stackTop != 1) {
            revert();
        }
        return stackValues[0];
    }
}
