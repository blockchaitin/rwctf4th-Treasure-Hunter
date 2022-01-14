pragma solidity ^0.8.6;

uint256 constant SIZE = 255;
uint256 constant BUFFER_LENGTH = 1;
uint256 constant DEPTH = 20;

library SMT {
    struct smt_leaf {
        address key;
        uint8 value;
    }

    function smt_init() internal pure returns (bytes32) {
        return 0;
    }

    function calc_leaf(smt_leaf memory a) internal pure returns (bytes32) {
        if (a.value == 0) {
            return 0;
        } else {
            return keccak256(abi.encode(a.key, a.value));
        }
    }

    function smt_merge(bytes32 lhs, bytes32 rhs)
        internal
        pure
        returns (bytes32)
    {
        if (lhs == 0) {
            return rhs;
        } else if (rhs == 0) {
            return lhs;
        } else {
            return keccak256(abi.encode(lhs, rhs));
        }
    }

    function black_white_list_verify(
        bytes32[] memory _proofs,
        uint160 _bits,
        address _target,
        bytes32 _expectedRoot,
        bool is_white_list
    ) internal pure returns (bool) {
        if (is_white_list) {
            smt_leaf memory leaf = smt_leaf({key: _target, value: 1});
            return smt_verify(_proofs, _bits, leaf, _expectedRoot);
        } else {
            smt_leaf memory leaf = smt_leaf({key: _target, value: 0});
            return smt_verify(_proofs, _bits, leaf, _expectedRoot);
        }
    }

    function smt_verify(
        bytes32[] memory _proofs,
        uint160 _bits,
        smt_leaf memory _leaf,
        bytes32 _expectedRoot
    ) internal pure returns (bool) {
        return (smt_calculate_root(_proofs, _bits, _leaf) == _expectedRoot);
    }

    function smt_update(
        bytes32[] memory _proofs,
        uint160 _bits,
        smt_leaf memory _nextleaf,
        smt_leaf memory _prevleaf,
        bytes32 _prevroot
    ) internal pure returns (bytes32) {
        require(
            smt_verify(_proofs, _bits, _prevleaf, _prevroot),
            "update proof not valid"
        );
        return smt_calculate_root(_proofs, _bits, _nextleaf);
    }

    function smt_calculate_root(
        bytes32[] memory _proofs,
        uint160 _bits,
        smt_leaf memory _leaf
    ) internal pure returns (bytes32) {
        uint160 _index = uint160(_leaf.key);
        bytes32 root_hash = calc_leaf(_leaf);

        require(_index < SIZE, "_index bigger than tree size");
        require(_proofs.length <= DEPTH, "Invalid _proofs length");

        for (uint256 d = 0; d < DEPTH; d++) {
            if ((_index & 1) == 1) {
                if ((_bits & 1) == 1) {
                    root_hash = smt_merge(_proofs[d], root_hash);
                } else {
                    root_hash = smt_merge(0, root_hash);
                }
            } else {
                if ((_bits & 1) == 1) {
                    root_hash = smt_merge(root_hash, _proofs[d]);
                } else {
                    root_hash = smt_merge(root_hash, 0);
                }
            }

            _bits = _bits >> 1;
            _index = _index >> 1;
        }
        return root_hash;
    }
}
