pragma solidity >=0.8.0 <0.9.0;

uint256 constant SIZE = 255;
uint256 constant DEPTH = 20;

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
                    rootHash = smtMerge(_proofs[d], rootHash);
                } else {
                    rootHash = smtMerge(0, rootHash);
                }
            } else {
                if ((_bits & 1) == 1) {
                    rootHash = smtMerge(rootHash, _proofs[d]);
                } else {
                    rootHash = smtMerge(rootHash, 0);
                }
            }

            _bits = _bits >> 1;
            _index = _index >> 1;
        }
        return rootHash;
    }
}
