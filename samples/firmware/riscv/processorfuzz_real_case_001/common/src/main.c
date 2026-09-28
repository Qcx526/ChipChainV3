#include "firmware.h"

Controller g_controller;

int main(void)
{
    platform_init();
    pager_init();
    controller_init(&g_controller);
    app_run();
    return g_controller.rejected != 0U;
}
