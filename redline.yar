rule RedLine_Stealer {
    meta:
        malware = "Redline Stealer"
        author = "d01a"
        description = "detect RedLine Stealer (old version. I don't remember the date)"

    strings:
        $s0 = {
            72 ?? ?? ?? 70      // IL_0007: ldstr "Hj0tHSAtXRsfKkAQIDowVR4tOVshFCRe" /* 70000424 */
            7D ?? ?? ?? 04      // IL_000c: stfld string EntryPoint::IP /* 0400000C */
            02                  // IL_0011: ldarg.0
            72 ?? ?? ?? 70      // IL_0012: ldstr "NSEmHDY5ERU1LRNV" /* 70000466 */
            7D ?? ?? ?? 04      // IL_0017: stfld string EntryPoint::ID /* 0400000D */
            02                  // IL_001c: ldarg.0
            72 ?? ?? ?? 70      // IL_001d ldstr "" /* 70000422 */
            7D ?? ?? ?? 04      // IL_0022: stfld string EntryPoint::Message /* 0400000E */
            02                  // IL_0027: ldarg.0
            72 ?? ?? ?? 70      // IL_0028: ldstr "Pythonic" /* 70000488 */
            7D ?? ?? ?? 04      // IL_002d: stfld string EntryPoint::Key /* 0400000F */
        }

        $s1 = "Yandex\\YaAddon" wide
        $s2 = "Recoursive" ascii 
        $s3 = "GameLauncherRule" ascii
        $s4 = "FileScannerRule" ascii
        $s5 = "SystemInfoHelper" ascii
        $s6 = "ResultFactory" ascii
        $s7 = "get_encrypted_key" ascii
        $s8 = "ChromeGetLocalName" ascii

    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and 5 of them
}