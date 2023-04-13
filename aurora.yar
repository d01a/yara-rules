rule aurora_stealer{
    meta:
    malware = "Aurora stealer"
    hash = "29339458f4a33ee922f25d36b83f19797a15a279634e9c44ebd3816866a541cb"
    reference = "https://d01a.github.io/"
    Author = "d01a"
    description = "detect Aurora stealer"

    strings:
    $is_go = "Go build" ascii

    $a1 = "8081" ascii
    $a2 = "C:\\Windows.old\\Users\\" ascii
    $a3 = "\\AppData\\Roaming\\" ascii
    $a4 = "wmic csproduct get uuid" ascii
    $a5 = "wmic cpu get name" ascii
    $a6 = "systeminfo" ascii
    $a7 = "wmic path win32_VideoController get name" ascii
    $a8 = "\\AppData\\Local\\" ascii
    $a9 = "\\Opera Stable\\Local State" ascii
    $a10 = "coNNNECTIONGWQFGQW"  ascii

    $fun1 = "main.Grab"  ascii
    $fun2 = "main.getMasterKey"  ascii
    $fun3 = "main.SendToServer_NEW"  ascii
    $fun4 = "main.ConnectToServer"  ascii
    $fun5 = "main.xDecrypt" ascii
    $fun6 = "main.GetDisplayBounds" ascii


    condition:
    uint16(0) == 0x5a4d and ( $is_go and (8 of ($a*)) and (4 of ($fun*)) )
}