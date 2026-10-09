rule Suspicious_ML_Pickle_Code_Execution {
    meta:
        description = "Detects malicious Python pickle objects commonly used to poison ML models (e.g., PyTorch .pt or .bin files) leading to Arbitrary Code Execution (ACE) upon loading."
        author = "ZlightkunZ"
        date = "2026-10-09"
        reference = "https://hiddenlayer.com/research/models-are-code/"
        mitre_technique = "T1202" // Indirect Command Execution
        target = "Machine Learning Models"
    strings:
        // Pickle opcodes for global imports
        $c = "c__builtin__"
        $posix = "cposix"
        $os = "cos"
        
        // Risky functions often abused in __reduce__ payloads
        $system = "system"
        $exec = "exec"
        $eval = "eval"
        $popen = "popen"
        
        // Reduce opcode which reconstructs objects
        $reduce = "R" 
    condition:
        // Look for global imports of OS/Posix followed by execution functions and the reduce opcode
        ($c or $posix or $os) and (any of ($system, $exec, $eval, $popen)) and $reduce
}
