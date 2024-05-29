rule ALPHV_BlackCat_Ransomware {
    meta:
        malware = "ALPHV/BlackCat Ransomware"
        hash = "ecea6b772742758a2240898ef772ca11aa9d870aec711cffab8994c23044117c"
        author = "d01a"
        description = "detect ALPHV/BlackCat Ransomware (old version. I don't remember the date)"

    strings:
        $alphv1 = "No Access Token Provided" ascii
        $alphv2 = "locker::core::os::windows" ascii
        $alphv3 = "locker::core::pipeline" ascii
        $alphv4 = "\\\\.\\pipe\\__rust_anonymous_pipe1__." ascii
        $alphv5 = "src/bin/encrypt_app/app.rs" ascii
        $alphv6 = "src/core/os/windows/privilege_escalation.rs" ascii
        $alphv7 = "rc/bin/encrypt_app/windows.rs" ascii
        $alphv8 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii
        $alphv9 = "bcdedit /set {default} recoveryenabled No" ascii
        $alphv10 = "vssadmin.exe Delete Shadows /all /quiet" ascii
        $alphv11 = "wmic.exe Shadowcopy Delete" ascii
        $alphv12 = "wmic csproduct get UUID" ascii

    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and 7 of them
}