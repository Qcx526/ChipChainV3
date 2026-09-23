// Architecture-neutral headless exporter. The ELF remains the authority for bytes.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ExportFirmwareFacts extends GhidraScript {
    private static Map<String, Object> object(Object... pairs) {
        Map<String, Object> value = new LinkedHashMap<>();
        for (int index = 0; index < pairs.length; index += 2) {
            value.put((String) pairs[index], pairs[index + 1]);
        }
        return value;
    }

    private static String escape(String input) {
        StringBuilder output = new StringBuilder("\"");
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            switch (ch) {
                case '\\': output.append("\\\\"); break;
                case '"': output.append("\\\""); break;
                case '\n': output.append("\\n"); break;
                case '\r': output.append("\\r"); break;
                case '\t': output.append("\\t"); break;
                default:
                    if (ch < 0x20) output.append(String.format("\\u%04x", (int) ch));
                    else output.append(ch);
            }
        }
        return output.append('"').toString();
    }

    private static String json(Object value) {
        if (value == null) return "null";
        if (value instanceof String) return escape((String) value);
        if (value instanceof Number || value instanceof Boolean) return value.toString();
        if (value instanceof Map<?, ?> map) {
            List<String> entries = new ArrayList<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                entries.add(escape((String) entry.getKey()) + ":" + json(entry.getValue()));
            }
            return "{" + String.join(",", entries) + "}";
        }
        if (value instanceof List<?> list) {
            List<String> entries = new ArrayList<>();
            for (Object entry : list) entries.add(json(entry));
            return "[" + String.join(",", entries) + "]";
        }
        throw new IllegalArgumentException("Cannot serialize " + value.getClass());
    }

    private static long offset(Address address) {
        return address.getOffset();
    }

    private String bytes(Instruction instruction) throws MemoryAccessException {
        byte[] raw = instruction.getBytes();
        StringBuilder result = new StringBuilder();
        for (byte value : raw) result.append(String.format("%02x", value & 0xff));
        return result.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Expected output JSON path");
        List<Object> functions = new ArrayList<>();
        List<Object> blocks = new ArrayList<>();
        List<Object> instructions = new ArrayList<>();
        List<Object> edges = new ArrayList<>();
        List<Object> calls = new ArrayList<>();
        List<Object> references = new ArrayList<>();

        FunctionIterator functionIterator = currentProgram.getFunctionManager().getFunctions(true);
        while (functionIterator.hasNext()) {
            Function function = functionIterator.next();
            List<Object> ranges = new ArrayList<>();
            var rangeIterator = function.getBody().getAddressRanges();
            while (rangeIterator.hasNext()) {
                var range = rangeIterator.next();
                ranges.add(object("start", offset(range.getMinAddress()),
                                  "end", offset(range.getMaxAddress())));
            }
            functions.add(object("id", "function:0x" + Long.toHexString(offset(function.getEntryPoint())),
                                 "entry", offset(function.getEntryPoint()), "name", function.getName(),
                                 "ranges", ranges, "thunk", function.isThunk(),
                                 "external", function.isExternal()));
        }

        BasicBlockModel model = new BasicBlockModel(currentProgram);
        CodeBlockIterator blockIterator = model.getCodeBlocks(monitor);
        while (blockIterator.hasNext()) {
            CodeBlock block = blockIterator.next();
            long start = offset(block.getFirstStartAddress());
            List<Object> ranges = new ArrayList<>();
            var rangeIterator = block.getAddressRanges();
            while (rangeIterator.hasNext()) {
                var range = rangeIterator.next();
                ranges.add(object("start", offset(range.getMinAddress()),
                                  "end", offset(range.getMaxAddress())));
            }
            blocks.add(object("id", "block:0x" + Long.toHexString(start),
                              "start", start, "end", offset(block.getMaxAddress()),
                              "ranges", ranges));
            CodeBlockReferenceIterator destinations = block.getDestinations(monitor);
            while (destinations.hasNext()) {
                CodeBlockReference destination = destinations.next();
                edges.add(object("source", start,
                                 "target", offset(destination.getDestinationAddress()),
                                 "type", destination.getFlowType().toString()));
            }
        }

        InstructionIterator instructionIterator = currentProgram.getListing().getInstructions(true);
        while (instructionIterator.hasNext()) {
            Instruction instruction = instructionIterator.next();
            Address address = instruction.getAddress();
            Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
            List<Object> operands = new ArrayList<>();
            for (int index = 0; index < instruction.getNumOperands(); index++) {
                operands.add(instruction.getDefaultOperandRepresentation(index));
            }
            Long firstBlock = blockStart(model, address);
            instructions.add(object("pc", offset(address), "bytes", bytes(instruction),
                                    "mnemonic", instruction.getMnemonicString(),
                                    "operands", operands, "text", instruction.toString(),
                                    "function_entry", function == null ? null : offset(function.getEntryPoint()),
                                    "function_id", function == null ? null :
                                        "function:0x" + Long.toHexString(offset(function.getEntryPoint())),
                                    "block_start", firstBlock,
                                    "block_id", firstBlock == null ? null :
                                        "block:0x" + Long.toHexString(firstBlock)));
            if (instruction.getFlowType().isCall()) {
                Address[] flows = instruction.getFlows();
                calls.add(object("pc", offset(address),
                                 "caller", function == null ? null : offset(function.getEntryPoint()),
                                 "direct", flows.length == 1 && !instruction.getFlowType().isComputed(),
                                 "target", flows.length == 1 && !instruction.getFlowType().isComputed()
                                         ? offset(flows[0]) : null));
            }
            for (Reference reference : currentProgram.getReferenceManager().getReferencesFrom(address)) {
                references.add(object("source", offset(address),
                                      "target", reference.getToAddress().isMemoryAddress()
                                              ? offset(reference.getToAddress()) : null,
                                      "type", reference.getReferenceType().toString(),
                                      "operand", reference.getOperandIndex()));
            }
        }
        Comparator<Object> byEntry = Comparator.comparingLong(value -> ((Number) ((Map<?, ?>) value).get("entry")).longValue());
        functions.sort(byEntry);
        blocks.sort(Comparator.comparingLong(value -> ((Number) ((Map<?, ?>) value).get("start")).longValue()));
        instructions.sort(Comparator.comparingLong(value -> ((Number) ((Map<?, ?>) value).get("pc")).longValue()));
        edges.sort(Comparator.comparing(value -> json(value)));
        calls.sort(Comparator.comparingLong(value -> ((Number) ((Map<?, ?>) value).get("pc")).longValue()));
        references.sort(Comparator.comparing(value -> json(value)));
        Map<String, Object> result = object(
            "schema", "ghidra-firmware-facts/v1",
            "language", currentProgram.getLanguageID().getIdAsString(),
            "compiler", currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString(),
            "image_base", offset(currentProgram.getImageBase()),
            "functions", functions, "blocks", blocks, "instructions", instructions,
            "edges", edges, "calls", calls, "references", references);
        Files.writeString(Path.of(args[0]), json(result) + "\n", StandardCharsets.UTF_8);
        println("Exported " + instructions.size() + " instructions to " + args[0]);
    }

    private Long blockStart(BasicBlockModel model, Address address) throws Exception {
        CodeBlock block = model.getFirstCodeBlockContaining(address, monitor);
        return block == null ? null : offset(block.getFirstStartAddress());
    }
}
