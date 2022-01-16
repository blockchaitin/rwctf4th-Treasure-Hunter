pragma solidity >=0.8.0 <0.9.0;

uint256 constant SIZE = 255;
uint256 constant DEPTH = 20;

library SMT {
    struct smtLeaf {
        address key;
        uint8 value;
    }

    function smtInit() internal pure returns (bytes32) {
        return 0;
    }

    function calcLeaf(smtLeaf memory a) internal pure returns (bytes32) {
        if (a.value == 0) {
            return 0;
        } else {
            return keccak256(abi.encode(a.key, a.value));
        }
    }

    function smtMerge(bytes32 l, bytes32 r)
        internal
        pure
        returns (bytes32)
    {
        if (l == 0) {
            return r;
        } else if (r == 0) {
            return l;
        } else {
            return keccak256(abi.encode(l, r));
        }
    }

    function smtVerifyByMode(
        bytes32[] memory _proofs,
        uint160 _bits,
        address _target,
        bytes32 _expectedRoot,
        bool _isWhiteListMode
    ) internal pure returns (bool) {
        smtLeaf memory leaf = smtLeaf({key: _target, value: 0});
        if (_isWhiteListMode) {
            leaf.value = 1;
        }

        return smtVerify(_proofs, _bits, leaf, _expectedRoot);
    }

    function smtVerify(
        bytes32[] memory _proofs,
        uint160 _bits,
        smtLeaf memory _leaf,
        bytes32 _expectedRoot
    ) internal pure returns (bool) {
        return (smtCalculateRoot(_proofs, _bits, _leaf) == _expectedRoot);
    }

    function smtUpdate(
        bytes32[] memory _proofs,
        uint160 _bits,
        smtLeaf memory _nextLeaf,
        smtLeaf memory _prevLeaf,
        bytes32 _prevRoot
    ) internal pure returns (bytes32) {
        require(
            smtVerify(_proofs, _bits, _prevLeaf, _prevRoot),
            "update proof not valid"
        );
        return smtCalculateRoot(_proofs, _bits, _nextLeaf);
    }

    function smtCalculateRoot(
        bytes32[] memory _proofs,
        uint160 _bits,
        smtLeaf memory _leaf
    ) internal pure returns (bytes32) {
        uint160 _index = uint160(_leaf.key);
        bytes32 root_hash = calcLeaf(_leaf);

        require(_index < SIZE, "_index bigger than tree size");
        require(_proofs.length <= DEPTH, "Invalid _proofs length");

        for (uint256 d = 0; d < DEPTH; d++) {
            if ((_index & 1) == 1) {
                if ((_bits & 1) == 1) {
                    root_hash = smtMerge(_proofs[d], root_hash);
                } else {
                    root_hash = smtMerge(0, root_hash);
                }
            } else {
                if ((_bits & 1) == 1) {
                    root_hash = smtMerge(root_hash, _proofs[d]);
                } else {
                    root_hash = smtMerge(root_hash, 0);
                }
            }

            _bits = _bits >> 1;
            _index = _index >> 1;
        }
        return root_hash;
    }
}
