pragma solidity >=0.8.0 <0.9.0;

uint256 constant SMT_STACK_SIZE = 32;
uint256 constant DEPTH = 20;
uint256 constant SIZE = 2**160-1;

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

    function verifyByMode(
        bytes32[] memory _proofs,
        uint160 _bits,
        address _target,
        bytes32 _expectedRoot,
        Mode _mode
    ) internal pure returns (bool) {
        Leaf memory leaf = Leaf({key: _target, value: uint8(_mode)});
        return verify(_proofs, _bits, leaf, _expectedRoot);
    }

    function verify(
        bytes32[] memory _proofs,
        uint160 _bits,
        Leaf memory _leaf,
        bytes32 _expectedRoot
    ) internal pure returns (bool) {
        return (calcRoot(_proofs, _bits, _leaf) == _expectedRoot);
    }

    function insert(
        bytes32[] memory _proofs,
        uint160 _bits,
        address _target,
        bytes32 _prevRoot
    ) internal pure returns (bytes32) {
        Leaf memory nextLeaf = Leaf({key: _target, value: 1});
        Leaf memory prevLeaf = Leaf({key: _target, value: 0});
        return update(_proofs, _bits, nextLeaf, prevLeaf, _prevRoot);
    }

    function update(
        bytes32[] memory _proofs,
        uint160 _bits,
        Leaf memory _nextLeaf,
        Leaf memory _prevLeaf,
        bytes32 _prevRoot
    ) internal pure returns (bytes32) {
        require(
            verify(_proofs, _bits, _prevLeaf, _prevRoot),
            "update proof not valid"
        );
        return calcRoot(_proofs, _bits, _nextLeaf);
    }

    function calcRoot(
        bytes32[] memory _proofs,
        uint160 _bits,
        Leaf memory _leaf
    ) internal pure returns (bytes32) {
        uint160 _index = uint160(_leaf.key);
        bytes32 rootHash = calcLeaf(_leaf);

        require(_index < SIZE, "_index bigger than tree size");
        require(_proofs.length <= DEPTH, "Invalid _proofs length");

        for (uint256 d = 0; d < DEPTH; d++) {
            if ((_index & 1) == 1) {
                if ((_bits & 1) == 1) {
                    rootHash = merge(_proofs[d], rootHash);
                } else {
                    rootHash = merge(0, rootHash);
                }
            } else {
                if ((_bits & 1) == 1) {
                    rootHash = merge(rootHash, _proofs[d]);
                } else {
                    rootHash = merge(rootHash, 0);
                }
            }

            _bits = _bits >> 1;
            _index = _index >> 1;
        }
        return rootHash;
    }

    function checkGroupSorted(Leaf[] memory _leafs)
        internal
        pure
        returns (bool)
    {
        require(_leafs.length >= 1);
        uint160 temp = 0;
        for (uint256 i = 0; i < _leafs.length; i++) {
            if (temp >= uint160(_leafs[i].key)) {
                return false;
            }
            temp = uint160(_leafs[i].key);
        }
        return true;
    }

    function calcRoot2(bytes32[] memory _proofs, Leaf[] memory _leafs)
        internal
        pure
        returns (bytes32)
    {
        require(checkGroupSorted(_leafs));
        uint160[] memory stack_keys = new uint160[](SMT_STACK_SIZE);
        bytes32[] memory stack_values = new bytes32[](SMT_STACK_SIZE);
        uint256 proof_index = 0;
        uint256 leave_index = 0;
        uint256 stack_top = 0;

        while (proof_index < _proofs.length) {
            if (uint256(_proofs[proof_index]) == 0x4c) {
                proof_index++;
                if (stack_top >= SMT_STACK_SIZE) {
                    revert();
                }
                if (leave_index >= _leafs.length) {
                    revert();
                }
                stack_keys[stack_top] = uint160(_leafs[leave_index].key);
                stack_values[stack_top] = calcLeaf(_leafs[leave_index]);
                stack_top++;
                leave_index++;
            } else if (uint256(_proofs[proof_index]) == 0x50) {
                proof_index++;
                if (stack_top == 0) {
                    revert();
                }
                if (proof_index + 1 > _proofs.length) {
                    revert();
                }
                bytes32 current_proof = _proofs[proof_index++];
                if (stack_keys[stack_top - 1] & 1 == 1) {
                    stack_values[stack_top - 1] = merge(
                        current_proof,
                        stack_values[stack_top - 1]
                    );
                } else {
                    stack_values[stack_top - 1] = merge(
                        stack_values[stack_top - 1],
                        current_proof
                    );
                }
                stack_keys[stack_top - 1] = stack_keys[stack_top - 1] >> 1;
            } else if (uint256(_proofs[proof_index]) == 0x48) {
                proof_index++;
                if (stack_top < 2) {
                    revert();
                }
                if (proof_index > _proofs.length) {
                    revert();
                }
                uint160 a_set = stack_keys[stack_top - 2] & 1;
                uint160 b_set = stack_keys[stack_top - 1] & 1;
                stack_keys[stack_top - 2] = stack_keys[stack_top - 2] >> 1;
                stack_keys[stack_top - 1] = stack_keys[stack_top - 1] >> 1;
                if (
                    stack_keys[stack_top - 2] != stack_keys[stack_top - 1] ||
                    a_set == b_set
                ) {
                    revert();
                }
                if (a_set == 1) {
                    stack_values[stack_top - 2] = merge(
                        stack_values[stack_top - 1],
                        stack_values[stack_top - 2]
                    );
                } else {
                    stack_values[stack_top - 2] = merge(
                        stack_values[stack_top - 2],
                        stack_values[stack_top - 1]
                    );
                }
                stack_top -= 1;
            } else {
                revert();
            }
        }
        if (leave_index != _leafs.length) {
            revert();
        }
        if (stack_top != 1) {
            revert();
        }
        return stack_values[0];
    }
}
