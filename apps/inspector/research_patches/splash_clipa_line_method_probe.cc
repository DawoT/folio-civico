// R1.26: real SplashClip::clipAALine and real, tiny SplashBitmap.
// Source-method precondition probes only; NOT an end-to-end PDF reproduction.
#include <climits>
#include <cstdio>
#include <cstring>
#include "splash/SplashBitmap.h"
#include "splash/SplashClip.h"

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    // This is an antialias scratch buffer: 64 subpixels x 4 rows = 32 bytes.
    // The bitmap is constructed by the real, SHA-pinned Poppler library.
    SplashBitmap aaBuf(64, 4, 1, splashModeMono1, false);
    if (aaBuf.getDataPtr() == nullptr || aaBuf.getWidth() != 64
        || aaBuf.getHeight() != 4 || aaBuf.getRowSize() != 8) return 3;

    SplashClip clip(0, 0, 8, 4, true);
    int x0 = 0, x1 = 0;
    if (std::strcmp(argv[1], "normal_origin") == 0) {
        // Keep both x coordinates inside the pixel/clip bounds.
    } else if (std::strcmp(argv[1], "normal_in_bounds") == 0) {
        x1 = 3;
    } else if (std::strcmp(argv[1], "invalid_x0") == 0) {
        // Deliberately VIOLATES the renderer's expected bitmap bounds.
        x0 = INT_MAX / 4 + 8;
        x1 = x0;
    } else if (std::strcmp(argv[1], "invalid_x1") == 0) {
        // Deliberately VIOLATES the renderer's expected bitmap bounds.
        x1 = INT_MAX / 4 + 8;
    } else {
        return 2;
    }

    clip.clipAALine(&aaBuf, &x0, &x1, 1);
    if (std::strcmp(argv[1], "normal_origin") == 0
        && x0 == 0 && x1 == 0) {
        std::puts("tiny_real_bitmap_origin_ok");
        return 0;
    }
    if (std::strcmp(argv[1], "normal_in_bounds") == 0
        && x0 == 0 && x1 == 3) {
        std::puts("tiny_real_bitmap_in_bounds_ok");
        return 0;
    }
    // An unchecked return on invalid inputs is *not* accepted as safe.
    return 4;
}
