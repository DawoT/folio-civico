// R1.16 defensive arithmetic *analogues*, not Poppler parser executions.
// The corresponding source statements are SHA-pinned and independently
// inspected; this harness intentionally DOES NOT prove a CVE fix.
#include <climits>
#include <cstring>
#include <cstdio>
#include "goo/GooCheckedOps.h"

int main(int argc, char **argv)
{
    if (argc != 3) {
        return 2;
    }
    const bool patched = std::strcmp(argv[1], "patched") == 0;
    if (!patched && std::strcmp(argv[1], "original") != 0) {
        return 2;
    }
    volatile int result = 0;
    if (std::strcmp(argv[2], "sampled32") == 0) {
        volatile int sampleBits = 32;
        if (patched) {
            result = static_cast<unsigned int>((1ULL << sampleBits) - 1);
            return result == -1 ? 0 : 3;
        }
        result = (1 << sampleBits) - 1; // original Function.cc mechanism
        return result == -1 ? 0 : 3;
    }
    if (std::strcmp(argv[2], "jbig2_intmin") == 0) {
        volatile int lowVal = INT_MIN;
        if (patched) {
            int lowValMinusOne = 0;
            return checkedSubtraction(lowVal, 1, &lowValMinusOne) ? 0 : 3;
        }
        result = lowVal - 1; // original JBIG2Stream.cc mechanism
        return result == INT_MAX ? 0 : 3;
    }
    if (std::strcmp(argv[2], "splash_ymin") == 0) {
        volatile int yMinI = INT_MAX / 4 + 5;
        volatile int splashAASize = 4;
        if (patched) {
            int yMinAA = 0;
            return checkedMultiply(yMinI, splashAASize, &yMinAA) ? 0 : 3;
        }
        result = yMinI * splashAASize; // original SplashClip.cc mechanism
        return result == 0 ? 3 : 0;
    }
    if (std::strcmp(argv[2], "truetype_glyph_length") == 0) {
        volatile int length = INT_MAX - 2;
        volatile int glyphLength = 8;
        if (patched) {
            int next = 0;
            return checkedAdd(length, glyphLength, &next) ? 0 : 3;
        }
        result = length + glyphLength; // original FoFiTrueType.cc mechanism
        return result == 0 ? 3 : 0;
    }
    if (std::strcmp(argv[2], "splash_ymax_residual") == 0) {
        // Deliberately UNCHANGED by the selected Debian patch / prototype:
        volatile int yMaxI = INT_MAX - 1;
        volatile int splashAASize = 4;
        result = (yMaxI + 1) * splashAASize - 1;
        return result == 0 ? 3 : 0;
    }
    if (std::strcmp(argv[2], "truetype_alignment_residual") == 0) {
        // Also remains unchecked after the direct Debian glyph-length patch.
        volatile int length = INT_MAX;
        result = (length += 4 - (length & 3));
        return result == 0 ? 3 : 0;
    }
    std::fprintf(stderr, "Unsupported bounded research case\n");
    return 2;
}
