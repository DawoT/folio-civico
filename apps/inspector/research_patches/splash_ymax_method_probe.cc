// R1.19: call actual SplashClip::clipToPath from exact, isolated Poppler source.
// Numerical method test only. NOT an end-to-end PDF exploit or CVE adjudication.
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
    enum Test { normal, ymin_overflow, ymax_overflow } which;
    if (std::strcmp(argv[1], "normal") == 0) {
        which = normal;
    } else if (std::strcmp(argv[1], "ymin_overflow") == 0) {
        y0 = static_cast<SplashCoord>(INT_MAX / 4 + 8);
        y1 = y0 + 24;
        which = ymin_overflow;
    } else if (std::strcmp(argv[1], "ymax_overflow") == 0) {
        y1 = static_cast<SplashCoord>(INT_MAX / 4 + 8);
        which = ymax_overflow;
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
    const SplashError result = clip.clipToPath(&path, ctm, 1.0, false);
    if (which == normal && result == splashOk && clip.getNumPaths() == 1) {
        std::puts("normal_path_accepted");
        return 0;
    }
    if (which == ymin_overflow && result == splashErrGeneric
        && clip.getNumPaths() == 0) {
        std::puts("splash_ymin_checked_rejected");
        return 0;
    }
    if (which == ymax_overflow && result == splashErrGeneric
        && clip.getNumPaths() == 0) {
        std::puts("splash_ymax_checked_rejected");
        return 0;
    }
    std::fprintf(stderr, "Unanticipated clipToPath outcome (%d, paths=%d)\n",
                 result, clip.getNumPaths());
    return 4;
}
