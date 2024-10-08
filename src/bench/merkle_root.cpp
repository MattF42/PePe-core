// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bench.h"

#include "uint256.h"
#include "random.h"
#include "consensus/merkle.h"

static void MerkleRoot(benchmark::State& state)
{
    seed_insecure_rand(true);
    std::vector<uint256> leaves;
    leaves.resize(9001);
    for (auto& item : leaves) {
        item = GetRandHash();
    }
    while (state.KeepRunning()) {
        bool mutation = false;
        uint256 hash = ComputeMerkleRoot(leaves, &mutation);
        leaves[mutation] = hash;
    }
}

BENCHMARK(MerkleRoot/*, 800*/);

