// R1.27: actual Splash C++ constructors, not synthetic arithmetic stand-ins.
// A single-row Mono1 bitmap allocates ~64 MiB even at 536870919 pixels.
// This is a real allocated bitmap, but not a proven PDF/renderer input.
#include <climits>
#include <cstdio>
#include <cstring>
#include "splash/Splash.h"
#include "splash/SplashBitmap.h"
#include "splash/SplashScreen.h"

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    const char *name = argv[1];
    const bool useScreen = std::strncmp(name, "screen_", 7) == 0;
    const bool useParams = std::strncmp(name, "params_", 7) == 0;
    if (!useParams && !useScreen) return 2;
    const char *scenario = name + (useParams ? 7 : 7);
    const bool wide = std::strcmp(scenario, "wide_aa") == 0
        || std::strcmp(scenario, "wide_noaa") == 0;
    const bool aa = std::strcmp(scenario, "normal_aa") == 0
        || std::strcmp(scenario, "wide_aa") == 0;
    const bool normal = std::strcmp(scenario, "normal_aa") == 0
        || std::strcmp(scenario, "normal_noaa") == 0;
    if (!wide && !normal) return 2;
    const int width = wide ? INT_MAX / 4 + 8 : 8;
    SplashBitmap bitmap(width, 1, 1, splashModeMono1, false);
    // This single-row bitmap must really be allocated (not an empty metadata
    // stand-in). Its maximum actual storage is 64 MiB + 1 byte.
    const int rowSize = (width + 7) >> 3;
    if (bitmap.getDataPtr() == nullptr) return 3;
    if (bitmap.getWidth() != width || bitmap.getHeight() != 1
        || bitmap.getRowSize() != rowSize) return 4;

    if (useScreen) {
        SplashScreen screen(static_cast<const SplashScreenParams *>(nullptr));
        Splash splash(&bitmap, aa, &screen);
    } else {
        Splash splash(&bitmap, aa, static_cast<SplashScreenParams *>(nullptr));
    }
    if (wide) {
        std::puts("wide_allocated_bitmap_without_antialias_constructed");
        return aa ? 5 : 0;
    }
    std::puts(aa ? "normal_with_antialias_constructed"
                 : "normal_without_antialias_constructed");
    return 0;
}
