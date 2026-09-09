//@category CTF
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.Set;

public class ExportCTFAgent extends GhidraScript {
    private static String safeName(String name) {
        return name.replaceAll("[^A-Za-z0-9_$.-]", "_");
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("Usage: ExportCTFAgent.java <output-directory>");
        }
        File outputDir = new File(args[0]);
        File decompiledDir = new File(outputDir, "decompiled");
        if (!outputDir.exists() && !outputDir.mkdirs()) {
            throw new RuntimeException("Cannot create output directory: " + outputDir);
        }
        if (!decompiledDir.exists() && !decompiledDir.mkdirs()) {
            throw new RuntimeException("Cannot create decompiled directory: " + decompiledDir);
        }

        PrintWriter csv = new PrintWriter(new FileWriter(new File(outputDir, "functions.csv")));
        csv.println("address,name,parameter_count,return_type,decompiled_file");
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.setOptions(new DecompileOptions());
            decompiler.openProgram(currentProgram);
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            Set<String> usedNames = new LinkedHashSet<>();
            while (iterator.hasNext()) {
                if (monitor.isCancelled()) {
                    break;
                }
                Function function = iterator.next();
                String baseName = safeName(function.getName());
                String fileName = baseName;
                int suffix = 1;
                while (!usedNames.add(fileName)) {
                    fileName = baseName + "_" + suffix++;
                }
                File sourceFile = new File(decompiledDir, fileName + ".c");
                DecompileResults results = decompiler.decompileFunction(function, 45, monitor);
                String code = "";
                if (results != null && results.getDecompiledFunction() != null) {
                    code = results.getDecompiledFunction().getC();
                }
                try (PrintWriter out = new PrintWriter(new FileWriter(sourceFile))) {
                    out.println("// Function: " + function.getName());
                    out.println("// Address: " + function.getEntryPoint());
                    out.println();
                    out.println(code == null ? "" : code);
                }
                csv.println(
                    function.getEntryPoint() + "," +
                    function.getName().replace(',', '_') + "," +
                    function.getParameterCount() + "," +
                    function.getReturnType().toString().replace(',', '_') + "," +
                    "decompiled/" + sourceFile.getName()
                );
            }
        } finally {
            decompiler.dispose();
            csv.close();
        }
        println("Exported Ghidra functions to " + outputDir.getAbsolutePath());
    }
}
