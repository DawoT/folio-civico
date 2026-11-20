// R1.24: Actual SplashClip::testSpan call; not a PDF parser exploit.
#include <climits>
#include <cstdio>
#include <cstring>
#include "splash/SplashClip.h"
#include "splash/SplashPath.h"
#include "splash/SplashErrorCodes.h"

int main(int argc, char **argv)
{
    if (argc != 2) return 2;

    // Large finite clip rectangle. No large image allocation.
    SplashClip clip(0, 0, 600000000, 10, true);
    if (std::strcmp(argv[1], "no_path_extreme") == 0) {
        if (clip.testSpan(INT_MAX / 4 + 8, INT_MAX / 4 + 8, 1)
            != splashClipAllInside) return 3;
        std::puts("without_path_inside");
        return 0;
    }

    SplashPath path;
    if (path.moveTo(0, 0) != splashOk
        || path.lineTo(10, 2) != splashOk
        || path.lineTo(2, 8) != splashOk
        || path.close() != splashOk) return 4;

    SplashCoord transform[6] = { 1, 0, 0, 1, 0, 0 };
    if (clip.clipToPath(&path, transform, 1.0, false) != splashOk
        || clip.getNumPaths() != 1) return 5;

    if (std::strcmp(argv[1], "normal") == 0) {
        if (clip.testSpan(1, 2, 1) != splashClipAllInside) return 6;
        std::puts("normal_span_inside");
        return 0;
    }
    if (std::strcmp(argv[1], "outside_guard") == 0) {
        if (clip.testSpan(600000010, 600000010, 1)
            != splashClipAllOutside) return 7;
        std::puts("outside_guard_rejected");
        return 0;
    }
    if (std::strcmp(argv[1], "span_x_aa_overflow") == 0) {
        // Inside the rectangular bounds. With a path present,
        // x * splashAASize is evaluated before scanner::testSpan.
        (void)clip.testSpan(INT_MAX / 4 + 8, INT_MAX / 4 + 8, 1);
        return 8;  // Unsafe result must never be treated as success.
    }
    return 2;
}
