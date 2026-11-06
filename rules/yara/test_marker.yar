// Harmless marker for testing the pipeline on the host. Must be at the start of a small
// file, so it can't match this rule file or the test code.
rule ThreatPulse_Test_Marker
{
    meta:
        signature = "TEST-MARKER"
        description = "ThreatPulse harmless test marker"

    strings:
        $marker = "THREATPULSE-TEST-MARKER" ascii

    condition:
        $marker at 0 and filesize <= 1024
}
