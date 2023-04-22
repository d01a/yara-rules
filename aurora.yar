rule aurora_stealer{
    meta:
    malware = "Aurora stealer"
    hash = "29339458f4a33ee922f25d36b83f19797a15a279634e9c44ebd3816866a541cb"
    reference = "https://d01a.github.io/"
    Author = "d01a"
    description = "detect Aurora stealer"

    strings:
    $is_go = "Go build" ascii

    $a1 = "C:\\Windows.old\\Users\\" ascii
    $a2 = "\\AppData\\Roaming\\" ascii
    $a3 = "wmic csproduct get uuid" ascii
    $a4 = "wmic cpu get name" ascii
    $a5 = "systeminfo" ascii
    $a6 = "coNNNECTIONGWQFGQW"  ascii

    $fun1 = "main.Grab"  ascii
    $fun2 = "main.getMasterKey"  ascii
    $fun3 = "main.SendToServer_NEW"  ascii
    $fun4 = "main.ConnectToServer"  ascii
    $fun5 = "main.xDecrypt" ascii
    $fun6 = "main.GetDisplayBounds" ascii


    condition:
    uint16(0) == 0x5a4d and ( $is_go and (4 of ($a*)) and (4 of ($fun*)) )
}

rule aurora_stealer_builder_new{
    meta:
    malware = "Aurora stealer Builder new version 2023"
    hash1 = "ebd1368979b5adb9586ce512b63876985a497e1727ffbd54732cd42eef992b81"
    hash2 = "e7aa0529d4412a8cee5c20c4b7c817337fabb1598b44efbf639f4a7dac4292ad"
    reference = "https://d01a.github.io/"
    Author = "d01a"
    description = "detect Aurora stealer Builder new version 2023"

    strings:
    $is_go = "Go build" ascii

    $s1 = "_Aurora_2023_Technology_"    ascii
    $s2 = "AURORA_TECHNOLOGY"  ascii
    $s3 = "scr_n_f.png" ascii
    $s4 = "EXTERNAL_RUN_PE_X64" ascii
    $s5 = "[Aurora]" ascii//log messages begin with [Aurora] __LOGMSG__

    $fun1 = "main.Server" ascii
    $fun2 = "main.GetAcess" ascii
    $fun3 = "main.AddCommand" ascii
    $fun4 = "main.GetGeoList" ascii
    $fun5 = "main.GiveMeBuild" ascii

    condition:
    uint16(0) == 0x5a4d and ( $is_go and (2 of ($s*)) and (2 of ($fun*)) )
}

rule aurora_stealer_builder_old{
    meta:
    malware = "Aurora stealer Builder old version 2022"
    hash1 = "33fc61e81efa609df51277aef261623bb291e2dd5359362d50070f7a441df0ad"
    reference = "https://d01a.github.io/"
    Author = "d01a"
    description = "detect Aurora stealer Builder old version 2022"

    strings:
    $is_go = "Go build" ascii

    $s1 = "ATX.Aurora"    ascii
    $s2 = "Aurora_Stealer_2033"  ascii
    $s3 = "Aurora_Stealer_SERVER" ascii
    $s4 = "[Aurora Stealer]" ascii//log messages

    $fun1 = "main.DecryptLog" ascii
    $fun2 = "main.CreateDB" ascii
    $fun3 = "main.GenerateKey" ascii
    $fun4 = "main.TGParce" ascii

    condition:
    uint16(0) == 0x5a4d and ( $is_go and (2 of ($s*)) and (2 of ($fun*)) )
}