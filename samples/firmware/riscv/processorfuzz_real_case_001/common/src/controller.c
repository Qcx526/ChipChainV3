#include "firmware.h"

#define MAX_IDLE_POLLS 32U

static void controller_reject(Controller *controller, uint32_t reason)
{
    controller->rejected++;
    platform_publish(STATUS_REJECTED, (uint64_t)reason);
}

static int controller_dispatch(Controller *controller, const Command *command)
{
    uint64_t result = 0U;
    int outcome;

    switch (command->opcode) {
    case CMD_MAP:
    case CMD_UNMAP:
    case CMD_QUERY:
        outcome = pager_apply(command, &result);
        if (outcome != 0) {
            return outcome;
        }
        controller->last_page = command->virtual_address;
        platform_publish(STATUS_APPLIED, result);
        return 0;
    case CMD_HEALTH:
        platform_publish(STATUS_APPLIED,
                         ((uint64_t)controller->processed << 32) | arch_hart_id());
        return 0;
    case CMD_STOP:
        controller->phase = STATUS_DONE;
        platform_publish(STATUS_DONE, controller->processed);
        return 0;
    default:
        return -1;
    }
}

void controller_init(Controller *controller)
{
    controller->phase = STATUS_READY;
    controller->processed = 0U;
    controller->rejected = 0U;
    controller->last_sequence = 0U;
    controller->last_page = 0U;
    platform_publish(STATUS_READY, 0U);
}

int controller_step(Controller *controller)
{
    Command command;
    int outcome;
    int polled;

    if (controller->phase == STATUS_DONE) {
        return 0;
    }
    polled = platform_poll(&command);
    if (polled == 0) {
        return 0;
    }
    if (polled < 0) {
        controller_reject(controller, UINT32_C(0xffff0001));
        return -1;
    }
    if (!command_validate(&command) ||
        command.sequence <= controller->last_sequence) {
        controller_reject(controller, command.sequence);
        return -1;
    }
    controller->last_sequence = command.sequence;
    outcome = controller_dispatch(controller, &command);
    if (outcome != 0) {
        controller_reject(controller, (uint32_t)(-outcome));
        return outcome;
    }
    controller->processed++;
    return 1;
}

void app_run(void)
{
    uint32_t idle_polls = 0U;

    while (g_controller.phase != STATUS_DONE && idle_polls < MAX_IDLE_POLLS) {
        int progressed = controller_step(&g_controller);
        if (progressed == 0) {
            idle_polls++;
        } else {
            idle_polls = 0U;
        }
    }
    if (g_controller.phase != STATUS_DONE) {
        platform_publish(STATUS_REJECTED, g_controller.last_sequence);
    }
    platform_idle();
}
