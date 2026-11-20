// R1.21: real SplashClip public test() API, source-only negative UBSan case.
// This is NOT a PDF parser exploit, a CVE verdict, or a runtime patch.
#include <climits>
#include <cstdio>
#include <cstring>
#include "splash/SplashClip.h"

int main(int argc, char **argv)
{
    if (argc != 2) {
        return 2;
    }

    // This is deliberately a valid, finite and bounded integer clip rectangle
    // with xMax > (INT_MAX / splashAASize), without allocating a huge bitmap.
    SplashClip clip(0, 0, 600000000, 10, true);
    if (std::strcmp(argv[1], "normal") == 0) {
        if (!clip.test(3, 3)) {
            return 3;
        }
        std::puts("normal_public_test_passed");
        return 0;
    }
    if (std::strcmp(argv[1], "x_aa_overflow") == 0) {
        // x=INT_MAX/4+8 is inside this clip but x*4 exceeds INT_MAX.
        // UBSan should diagnose the actual SplashClip::testClipPaths() code.
        // Do NOT replace this with a checked arithmetic *analogue*.
        if (!clip.test(INT_MAX / 4 + 8, 1)) {
            return 4;
        }
        std::puts("unexpected_unchecked_coordinate_accepted");
        return 0;
    }
    return 2;
}
