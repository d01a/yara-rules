rule pikabot{
    meta:
        malware = "Pikabot"
        hash = "59f42ecde152f78731e54ea27e761bba748c9309a6ad1c2fd17f0e8b90f8aed1"
        reference = "https://d01a.github.io/"
        author = "d01a"
        description = "detect pikabot loader and core module"

    strings:
        $s1 = {
			8A 44 0D C0
			34 ??
			88 84 0D ?? ?? ?? ??
			4?
			83 ?? ??
			7C ??
		}
        $s2 = {
            83 ?? ??
			74 ??
			4?
			83 ?? ??
			7C ??
        }
    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and any of them
}