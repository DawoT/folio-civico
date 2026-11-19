// R1.13 RESEARCH ONLY: numeric boundaries for pinned Poppler source helpers.
// This is NOT a parser test, CVE proof, compiled runtime, or release gate.
#include <cassert>
#include <climits>
#include "goo/GooCheckedOps.h"

int main()
{
    // BitsPerSample contract from Poppler's SampledFunction (1..32).
    for (int sampleBits = 1; sampleBits <= 32; ++sampleBits) {
        const unsigned int mask = static_cast<unsigned int>((1ULL << sampleBits) - 1);
        const unsigned int expected = sampleBits == 32 ? UINT_MAX : ((1U << sampleBits) - 1U);
        assert(mask == expected);
    }

    int result = 0;
    assert(!checkedAdd(41, 1, &result) && result == 42);
    assert(checkedAdd(INT_MAX, 1, &result));
    assert(checkedSubtraction(INT_MIN, 1, &result));
    assert(!checkedSubtraction(INT_MIN + 1, 1, &result) && result == INT_MIN);
    assert(checkedMultiply(INT_MAX, 4, &result));
    assert(!checkedMultiply(5, 4, &result) && result == 20);
    return 0;
}
