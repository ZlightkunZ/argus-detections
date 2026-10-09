rule Suspicious_PHP_Webshell_Eval {
    meta:
        description = "Detects basic PHP webshells utilizing eval() and base64_decode"
        author = "Your Name (@yourhandle)"
        date = "2026-10-09"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
        hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // Replace with real test hash
    strings:
        $php_start = "<?php"
        $eval_func = "eval"
        $decode_func = "base64_decode"
        $post_req = "$_POST"
    condition:
        $php_start at 0 and 2 of ($eval_func, $decode_func, $post_req)
}
