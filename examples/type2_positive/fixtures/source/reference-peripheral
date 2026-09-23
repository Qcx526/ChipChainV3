// Synthetic, controlled methodology apparatus. Not a real Ibex vulnerability.
module synthetic_mmio (
  input logic clk_i, rst_ni,
  input logic req_i, we_i,
  input logic [3:0] be_i,
  input logic [31:0] addr_i, wdata_i,
  output logic rvalid_o, err_o,
  output logic [31:0] rdata_o,
  input logic stop_i, result_valid_i,
  input logic [31:0] result_data_i
);
  logic [31:0] enable_q, command_q, status_q;
  logic legal;
  assign legal = (be_i == 4'hf) && (addr_i[1:0] == 2'b00) &&
      ((addr_i == 32'h00040000) || (addr_i == 32'h00040004) ||
       ((addr_i == 32'h00040008) && !we_i));

  // Identical one-cycle response protocol to the pinned Simple System slaves.
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      enable_q <= 0;
      command_q <= 0;
      status_q <= 0;
      rvalid_o <= 0;
      rdata_o <= 0;
      err_o <= 0;
    end else begin
      rvalid_o <= req_i;
      err_o <= req_i && !legal;
      rdata_o <= 0;
      if (req_i && legal) begin
        if (we_i) begin
          case (addr_i)
            32'h00040000: enable_q <= wdata_i;
            32'h00040004: begin
              command_q <= wdata_i;
              // STATUS_NEXT_STATE: reference retains its reset value.
            end
            default: ;
          endcase
        end else begin
          case (addr_i)
            32'h00040000: rdata_o <= enable_q;
            32'h00040004: rdata_o <= command_q;
            32'h00040008: rdata_o <= status_q;
            default: ;
          endcase
        end
      end
    end
  end

  /* verilator lint_off BLKSEQ */
  // Testbench bookkeeping is intentionally blocking; not synthesizable state.
  // Observation only: common to both RTL trees, no case labels or result oracle.
  // Posedge records pre-NBA request/previous response; negedge samples stable state.
  integer fd;
  integer cycle = 0;
  integer epoch = 0;
  integer seq = 0;
  integer next_id = 1;
  integer pending_id = 0;
  integer stop_cycle = -1;
  bit in_reset = 0;
  logic [31:0] pending_addr = 0, pending_data = 0;
  logic [3:0] pending_be = 0;
  bit pending_we = 0;

  task automatic event_record(input string phase, input integer tid,
      input logic [31:0] address, input bit we, input logic [3:0] be,
      input logic [31:0] wd, rd, input bit error, request_valid, response_valid);
    $fwrite(fd, "{\"schema\":\"syn-mmio-event/v1\",\"sequence\":%0d,\"cycle\":%0d,\"reset_epoch\":%0d,\"phase\":\"%s\",\"transaction_id\":%0d,\"address\":%0d,\"write_enable\":%0d,\"byte_enable\":%0d,\"write_data\":%0d,\"read_data\":%0d,\"error\":%0d,\"request_valid\":%0d,\"response_valid\":%0d,\"reset_n\":%0d,\"enable_value\":%0d,\"command_value\":%0d,\"status_value\":%0d}\n",
      seq, cycle, epoch, phase, tid, address, we, be, wd, rd, error,
      request_valid, response_valid, rst_ni, enable_q, command_q, status_q);
    seq = seq + 1;
  endtask

  initial begin
    fd = $fopen("synthetic-mmio.jsonl", "w");
    if (fd == 0) $fatal(1, "Cannot open apparatus trace");
    $fwrite(fd, "{\"schema\":\"syn-mmio-trace/v1\",\"phase\":\"header\"}\n");
  end

  always @(posedge clk_i) begin
    cycle = cycle + 1;
    if (!rst_ni) begin
      if (!in_reset) begin
        epoch = epoch + 1;
        event_record("reset_assert", 0, 0, 0, 0, 0, 0, 0, 0, 0);
      end
      in_reset = 1;
      pending_id = 0;
    end else if (epoch > 0) begin
      if (in_reset) event_record("reset_release", 0, 0, 0, 0, 0, 0, 0, 0, 0);
      in_reset = 0;
      if (rvalid_o) begin
        event_record("response", pending_id, pending_addr, pending_we, pending_be,
                     pending_data, rdata_o, err_o, 0, 1);
        pending_id = 0;
      end
      if (req_i) begin
        pending_id = next_id;
        next_id = next_id + 1;
        pending_addr = addr_i;
        pending_we = we_i;
        pending_be = be_i;
        pending_data = wdata_i;
        event_record("request", pending_id, addr_i, we_i, be_i, wdata_i, 0, 0, 1, 0);
      end
      if (result_valid_i)
        event_record("ram_write", 0, 32'h00101000, 1, 4'hf, result_data_i, 0, 0, 1, 0);
      if (stop_i && (stop_cycle < 0)) begin
        stop_cycle = cycle;
        event_record("software_stop", 0, 32'h00020008, 1, 4'hf, 1, 0, 0, 1, 0);
      end
    end
  end

  always @(negedge clk_i) begin
    if (epoch > 0)
      event_record("status_sample", 0, 0, 0, 0, 0, 0, 0, 0, 0);
  end

  final begin
    $fwrite(fd, "{\"schema\":\"syn-mmio-footer/v1\",\"phase\":\"footer\",\"complete\":%0d,\"event_count\":%0d,\"last_cycle\":%0d,\"reset_epoch_count\":%0d,\"normal_sim_exit\":%0d}\n",
      (stop_cycle >= 0) && (cycle >= stop_cycle + 2) && (pending_id == 0) && !in_reset,
      seq, cycle, epoch, (stop_cycle >= 0) && (cycle >= stop_cycle + 2));
    $fclose(fd);
  end
  /* verilator lint_on BLKSEQ */
endmodule
