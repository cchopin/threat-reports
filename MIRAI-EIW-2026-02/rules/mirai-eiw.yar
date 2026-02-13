// Mirai.EIW Variant - YARA Rules
// Author: cchopin
// Date: 2026-02-06
// Reference: ../02_threat_intelligence.md

rule Mirai_EIW_Variant {
    meta:
        description = "Detects Mirai.EIW variant"
        author = "cchopin"
        date = "2026-02-06"
        hash = "833bca151dc3ff83cbed22b6e7e849f0ee752bac55f68e156660e4d33d17caad"
        tlp = "CLEAR"

    strings:
        $s1 = "/info.json" ascii
        $s2 = "/client" ascii
        $s3 = "udhcpc" ascii
        $s4 = ".kok" ascii

    condition:
        uint32(0) == 0x464C457F and 2 of them
}

rule Mirai_EIW_Dropper {
    meta:
        description = "Detects Mirai.EIW dropper script (logic.sh / logicdr.sh)"
        author = "cchopin"
        date = "2026-02-06"
        hash = "bf5a1e8b25d6ef368f11028fc492cc5e4a7e623a5b603a505828ae1c2e62fa3d"
        tlp = "CLEAR"

    strings:
        $dl1 = "wget" ascii
        $dl2 = "curl" ascii
        $dl3 = "tftp" ascii
        $ext = ".kok" ascii
        $arch1 = "x86_64" ascii
        $arch2 = "x86_32" ascii
        $arch3 = "arm7" ascii
        $arch4 = "mips" ascii
        $monitor = ".monitor" ascii
        $shebang = "#!/bin/bash" ascii

    condition:
        $shebang at 0 and $ext and 2 of ($dl*) and 2 of ($arch*)
}
