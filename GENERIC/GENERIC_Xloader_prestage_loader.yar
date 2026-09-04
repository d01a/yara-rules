rule GENERIC_Xloader_PS_prestage_loader {
    meta:
        malware = "GENERIC Loader"
        author = "d01a"
        description = "Hunt for GENERIC script loader that used to deliver multiuple malware families. This is NOT a good detection rule at all! but it it's helpful to hunt for similar script header"
        date = "2026-08-31"
        sha256 = "8e60280c59b760a2e8c88d51e9fc8cb68c9ebe55b15106bd127cfdabab740bfc"
        
        
    strings:
        $s0 = "# AES-256 Decryption System" ascii
        $s1 = "# =========================" ascii
        $s2 = "# Encrypted Data" ascii
        
        
    condition:
        all of them
}



rule GENERIC_Xloader_prestage_NET_Loader {
    meta:
        malware = "GENERIC_Xloader_prestage_NET_Loader_obf"
        author = "d01a"
        description = "detect GENERIC Xloader-prestage .NET Loader - obfuscated with confuser"
        date = "2026-08-31"
        sha256 = "d324cee32a91d3761dbcd3a442088f130ad1a30a30590b24bfa1b52a7b212968"
        sha256 = "c729348afbf9e37bc065f755570699ca3579417579adef5a11ad0fdbe3977a29"

    strings:
    
        $s1 = "Confuser.Core 1.6.0" ascii
        $s2 = "COR_ENABLE_PROFILING" wide
        
        $s3 = "Failed to resume thread" wide
        $s4 = "Failed to write section" wide
        $s5 = "Failed to unmap section" wide
        $s6 = "Failed to get thread context" wide
        $s7 = "Failed to update PEB" wide
        
    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and 5 of them
}
