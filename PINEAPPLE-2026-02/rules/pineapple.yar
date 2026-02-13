// PINEAPPLE - Pyramid C2 / JeffreyEpstein YARA Rules
// Author: cchopin
// Date: 2026-02-13
// Reference: ../rapport.md
//
// NOTE: IPs are defanged with [.] notation for safe sharing.
// Re-fang before deploying (replace [.] with . )

rule PINEAPPLE_JeffreyEpstein_Loader {
    meta:
        description = "Detecte le loader JeffreyEpstein du groupe PINEAPPLE"
        author = "cchopin"
        date = "2026-02-13"
        hash = "36a6af23c42a0cc7d42a483c494199ab0ac966b68e96356c29f9386fde18beb7"

    strings:
        $group = "PINEAPPLE" ascii
        $name1 = "JeffreyEpstein" ascii
        $func1 = "execute_script" ascii
        $func2 = "monitor_logs" ascii
        $func3 = "keep_alive" ascii
        $b64_prefix1 = "ABCDEeNq" ascii
        $b64_prefix2 = "FGHIJeNq" ascii
        $decode = "encoded_script[5:]" ascii
        $target = "pythonmemorymodule" ascii
        $zlib = "zlib.decompress" ascii

    condition:
        3 of them
}

rule PINEAPPLE_Pyramid_Cradle {
    meta:
        description = "Detecte un cradle Pyramid C2 configure pour l'infra PINEAPPLE"
        author = "cchopin"
        date = "2026-02-13"

    strings:
        $pyramid1 = "pyramid_server=" ascii
        $pyramid2 = "pyramid_user=" ascii
        $pyramid3 = "pyramid_pass=" ascii
        $pyramid4 = "encode_encrypt_url=" ascii
        $pyramid5 = "encrypt_wrapper" ascii
        $ip1 = "158.94.210.160" ascii
        $ip2 = "178.16.53.173" ascii
        $user1 = "u02a7057892" ascii
        $user2 = "Sfs@3asdAdqwe" ascii
        $module = "pythonmemorymodule" ascii

    condition:
        (3 of ($pyramid*)) or (any of ($ip*) and any of ($user*)) or ($module and 2 of ($pyramid*))
}

rule PINEAPPLE_Chisel_Payload {
    meta:
        description = "Detecte le payload chisel.exe servi par le C2 PINEAPPLE"
        author = "cchopin"
        date = "2026-02-13"
        hash = "5d10b66e95cec6e2e5b5709ce546df7c2bb27c26e1c732ada98a4bc118179ae3"

    strings:
        $mz = { 4D 5A }
        $s1 = "CoSetProxyBlanket" ascii
        $s2 = "HttpOpenRequestW" ascii
        $s3 = "HttpSendRequestW" ascii
        $s4 = "cmd.exe" ascii

    condition:
        $mz at 0 and 3 of ($s*) and filesize < 1MB
}
