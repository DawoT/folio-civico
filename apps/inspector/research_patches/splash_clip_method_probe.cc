// R1.17: Call the ACTUAL SplashClip::clipToPath compiled from pinned Poppler.
// This is a direct C++ method probe, NOT a PDF parser exploit or CVE verdict.
#include <climits>
#include <cstdio>
#include <cstring>
#include "splash/SplashClip.h"
#include "splash/SplashPath.h"
#include "splash/SplashErrorCodes.h"

int main(int argc, char **argv)
{
    if (argc != 2) {
        return 2;
    }
    SplashCoord y0 = 0;
    SplashCoord y1 = 10;
    enum Expected { normal, blocked_ymin, unchecked_ymax } expected;
    if (std::strcmp(argv[1], "normal") == 0) {
        expected = normal;
    } else if (std::strcmp(argv[1], "ymin_overflow") == 0) {
        // splashAASize = 4: yMinI * 4 exceeds INT_MAX.
        y0 = static_cast<SplashCoord>(INT_MAX / 4 + 8);
        y1 = y0 + 24;
        expected = blocked_ymin;
    } else if (std::strcmp(argv[1], "ymax_residual") == 0) {
        // yMin is safe but (yMaxI + 1) * 4 exceeds INT_MAX.
        y1 = static_cast<SplashCoord>(INT_MAX / 4 + 8);
        expected = unchecked_ymax;
    } else {
        return 2;
    }
    SplashPath path;
    if (path.moveTo(0, 0) != splashOk
        || path.lineTo(10, 2) != splashOk
        || path.lineTo(2, 8) != splashOk
        || path.close() != splashOk) {
        return 3;
    }
    SplashCoord ctm[6] = { 1, 0, 0, 1, 0, 0 };
    SplashClip clip(0, y0, 10, y1, true);
    const SplashError err = clip.clipToPath(&path, ctm, 1.0, false);
    if (expected == normal && err == splashOk && clip.getNumPaths() == 1) {
        std::puts("normal_path_accepted");
        return 0;
    }
    if (expected == blocked_ymin && err == splashErrGeneric) {
        std::puts("splash_ymin_checked_rejected");
        return 0;
    }
    // Deliberately never claim the residual yMax case is guarded.
    std::fprintf(stderr, "Unexpected SplashClip result (%d, %d)\n", err,
                 clip.getNumPaths());
    return 4;
}
