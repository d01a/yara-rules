rule pikabot{
    meta:
        malware = "Pikabot"
        hash = "11cbb0233aff83d54e0d9189d3a08d02a6bbb0ffa5c3b161df462780e0ee2d2d"
        reference = "https://d01a.github.io/"
        author = "d01a"
        description = "detect pikabot loader and core module"

    strings:
        $s1 = {
			8A 44 0D C0
			?? ?? 
			88 84 0D ?? ?? FF FF 
			4?
			83 ?? ??
			7C ??
			[0-16]
			(C7 45 | 88 95)
		}
		
    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and all of them
}
