// Ghidra post-script used only by the fixed headless adapter command.
// @category ReversingLab

import java.io.FileWriter;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class RLabDecompile extends GhidraScript {
    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\r", "\\r").replace("\n", "\\n");
    }

    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 2) {
            throw new IllegalArgumentException("Expected address and output path.");
        }
        Address address = currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress(arguments[0]);
        Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
        if (function == null) {
            throw new IllegalArgumentException("No Ghidra function contains the requested address.");
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        DecompileResults results = decompiler.decompileFunction(function, 25, monitor);
        if (!results.decompileCompleted()) {
            throw new IllegalStateException(results.getErrorMessage());
        }
        String code = results.getDecompiledFunction().getC();
        String returnType = function.getReturnType().getDisplayName();
        String json = "{\"function_name\":\"" + escape(function.getName())
            + "\",\"return_type\":\"" + escape(returnType)
            + "\",\"code\":\"" + escape(code)
            + "\",\"warnings\":[\"Ghidra output is estimated C-like code, not original source.\"],"
            + "\"source_map\":[]}";
        try (FileWriter writer = new FileWriter(arguments[1])) {
            writer.write(json);
        }
        decompiler.dispose();
    }
}
