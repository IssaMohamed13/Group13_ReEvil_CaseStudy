rule MyFirstREvilRule {
    meta:
        description = "Looking for REvil ransomware strings for my assignment"
        author = "Student"

    strings:
        //based off identifiers foudn in reports
        $mutex_id = "C19C0A84-FA11-3F9C-C3BC-0BCB16922ABF"
        $black_lives_matter = "BlackLivesMatter"
        $registry_1 = "Krdfp"
        $registry_2 = "XFx41h1r"
        
        // JSON keys used by the malware
        $json1 = "\"pk\":"
        $json2 = "\"pid\":"

    condition:
        // Match if the file has at least some of these strings
        ($mutex_id or $black_lives_matter or $json1 or $json2)
}
