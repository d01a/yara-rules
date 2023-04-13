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