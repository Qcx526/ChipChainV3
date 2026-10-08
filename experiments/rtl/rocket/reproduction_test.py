"""One explicit input, using the inspected upstream ProcessorFuzz TileLink host.

Loaded only by the explicit research smoke, never by ordinary pytest.
"""
import json
import os
from pathlib import Path
import random

import cocotb
from cocotb.triggers import RisingEdge

from RTLSim.host import rvRTLhost, rtlInput


@cocotb.test()
async def reproduce(dut):
    config = json.loads(Path(os.environ["CHIPCHAIN_ROCKET_INPUT"]).read_text())
    raw = Path(config["raw_directory"])
    random.seed(config['random_seed'])
    # Explicitly declared testbench inputs; no external UART/customer input.
    applied=[]
    for name in config['zero_initial_inputs']:
        if hasattr(dut, name):
            getattr(dut, name).value = 0
            applied.append(name)
    host = rvRTLhost(dut, config["top"], str(raw / "rtl-signature.txt"))
    (raw / 'driver-started.json').write_text(json.dumps({'input_elf_sha256':config['elf_sha256'],
                                                       'testbench_initialized':True,
                                                       'zero_initial_inputs_applied':applied})+'\n')
    ticks = 0

    async def count_cycles():
        nonlocal ticks
        while True:
            await RisingEdge(dut.clock)
            ticks += 1
            if ticks in (10,100,config['max_cycles']):
                (raw/'driver-progress.json').write_text(json.dumps({'clock_rising_edges':ticks,
                    'simulation_time_ns':float(cocotb.utils.get_sim_time(units='ns'))})+'\n')

    counter = cocotb.start_soon(count_cycles())
    inp = rtlInput(config["hex_path"], None, config["data"],
                   config["symbols"], config["max_cycles"])
    result, coverage = await host.run_test(inp, False, 0)
    counter.kill()
    summary = {"driver_started": True, "driver_return_code": int(result),
               "clock_rising_edges": ticks, "coverage_counter": int(coverage),
               "simulation_time_ns": float(cocotb.utils.get_sim_time(units="ns")),
               "input_elf_sha256": config["elf_sha256"],
               "stop_reason": {0: "tohost_observed_and_adapter_drained",
                               1: "rtl_assertion", 2: "cycle_limit",
                               -1: "illegal_memory_access"}.get(int(result), "unknown_driver_result")}
    (raw / "driver-result.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    assert result == 0, summary["stop_reason"]
