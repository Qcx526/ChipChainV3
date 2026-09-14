// ChipChain static extraction v1; no decompiler, external source loading or GUI.
// @category ChipChain
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class ExportFirmwareStructure extends HeadlessScript {
    private Map<String,Object> obj(Object... pairs) {
        Map<String,Object> m = new TreeMap<>();
        for (int i=0;i<pairs.length;i+=2) m.put((String)pairs[i],pairs[i+1]);
        return m;
    }
    private String id(Function f) { return f == null ? null : "f"+Long.toHexString(f.getEntryPoint().getOffset()); }
    private String json(Object v) {
        if (v==null) return "null";
        if (v instanceof Number || v instanceof Boolean) return v.toString();
        if (v instanceof Map) {
            List<String> parts=new ArrayList<>();
            for (Object e0:((Map<?,?>)v).entrySet()) {
                Map.Entry<?,?> e=(Map.Entry<?,?>)e0;
                parts.add(json(e.getKey().toString())+":"+json(e.getValue()));
            }
            return "{"+String.join(",",parts)+"}";
        }
        if (v instanceof Collection) {
            List<String> parts=new ArrayList<>();
            for (Object x:(Collection<?>)v) parts.add(json(x));
            return "["+String.join(",",parts)+"]";
        }
        StringBuilder b=new StringBuilder("\"");
        for (char c:v.toString().toCharArray()) {
            if(c=='"'||c=='\\') b.append('\\').append(c);
            else if(c<32) b.append(String.format("\\u%04x",(int)c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
    protected void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length==1 && args[0].equals("configure")) {
            // Explicitly disable analysis which could use source/debug files or
            // decompiler inference. Call Convention ID also uses the decompiler
            // in 10.1.4 despite lacking "Decompiler" in its display name.
            // Other versioned installation defaults remain.
            for(Map.Entry<String,String> e:getCurrentAnalysisOptionsAndValues(currentProgram).entrySet()) {
                String k=e.getKey().toLowerCase(Locale.ROOT);
                if ((e.getValue().equals("true") || e.getValue().equals("false")) &&
                    (k.contains("decompiler") || k.contains("dwarf") || k.contains("pdb") || k.contains("external") || k.equals("call convention id")))
                    setAnalysisOption(currentProgram,e.getKey(),"false");
            }
            return;
        }
        if(args.length!=1 || analysisTimeoutOccurred()) throw new IllegalStateException("Incomplete headless analysis");
        Map<String,Object> options=new TreeMap<>();
        for(Map.Entry<String,String> e:getCurrentAnalysisOptionsAndValues(currentProgram).entrySet())
            if(e.getValue().equals("true") || e.getValue().equals("false")) options.put(e.getKey(),e.getValue());
        List<Object> memory=new ArrayList<>(), functions=new ArrayList<>(), calls=new ArrayList<>(), entries=new ArrayList<>();
        // ELF metadata overlays and Ghidra's artificial EXTERNAL block are not
        // target memory. Preserve only the default target address space here.
        for(MemoryBlock b:currentProgram.getMemory().getBlocks())
            if(b.getStart().getAddressSpace().equals(currentProgram.getAddressFactory().getDefaultAddressSpace())
                    && !b.getName().equals("EXTERNAL")) memory.add(obj("name",b.getName(),"start",b.getStart().getOffset(),"end",b.getEnd().getOffset()+1,
                           "initialized",b.isInitialized(),"execute",b.isExecute()));
        AddressIterator eit=currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while(eit.hasNext()) entries.add(eit.next().getOffset());
        FunctionManager fm=currentProgram.getFunctionManager();
        FunctionIterator fit=fm.getFunctions(true);
        while(fit.hasNext()) {
            Function f=fit.next();
            List<Object> ranges=new ArrayList<>(), symbols=new ArrayList<>();
            AddressRangeIterator rit=f.getBody().getAddressRanges();
            while(rit.hasNext()) { AddressRange r=rit.next(); ranges.add(obj("start",r.getMinAddress().getOffset(),"end",r.getMaxAddress().getOffset()+1)); }
            for(Symbol s:currentProgram.getSymbolTable().getSymbols(f.getEntryPoint()))
                symbols.add(obj("name",s.getName(),"source_type",s.getSource().toString()));
            functions.add(obj("function_id",id(f),"entry_address",f.getEntryPoint().getOffset(),"name",f.getName(),
                "ranges",ranges,"size_bytes",f.getBody().getNumAddresses(),"source_type",f.getSymbol().getSource().toString(),
                "symbols",symbols,"is_thunk",f.isThunk(),"is_external",f.isExternal()));
        }
        InstructionIterator iit=currentProgram.getListing().getInstructions(true);
        while(iit.hasNext()) {
            Instruction ins=iit.next();
            if(!ins.getFlowType().isCall()) continue;
            SortedSet<Long> targets=new TreeSet<>();
            for(Reference r:currentProgram.getReferenceManager().getReferencesFrom(ins.getAddress()))
                if(r.getReferenceType().isCall() && r.getToAddress().isMemoryAddress()) targets.add(r.getToAddress().getOffset());
            Long target=targets.size()==1 ? targets.first() : null;
            Function callee=target==null ? null : fm.getFunctionAt(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(target));
            StringBuilder bytes=new StringBuilder();
            for(byte b:ins.getBytes()) bytes.append(String.format("%02x",b & 255));
            calls.add(obj("call_site_address",ins.getAddress().getOffset(),"caller_function_id",id(fm.getFunctionContaining(ins.getAddress())),
                "callee_function_id",id(callee),"target_address",target,"computed",ins.getFlowType().isComputed(),
                "target_count",targets.size(),"raw_encoding",bytes.toString(),"instruction_size",ins.getLength()));
        }
        Map<String,Object> result=obj("schema_version","ghidra-export/v1","ghidra_version",Application.getApplicationVersion(),
            "java_runtime_version",System.getProperty("java.runtime.version"),"java_vendor",System.getProperty("java.vendor"),
            "language_id",currentProgram.getLanguageID().toString(),"compiler_spec_id",currentProgram.getCompilerSpec().getCompilerSpecID().toString(),
            "processor",currentProgram.getLanguage().getProcessor().toString(),"word_size_bits",currentProgram.getDefaultPointerSize()*8,
            "endianness",currentProgram.getLanguage().isBigEndian()?"big":"little", "image_base",currentProgram.getImageBase().getOffset(),
            "executable_sha256",currentProgram.getExecutableSHA256(),"entry_points",entries,"analysis_options",options,
            "memory",memory,"functions",functions,"call_sites",calls);
        Files.write(Paths.get(args[0]),(json(result)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
    }
}
