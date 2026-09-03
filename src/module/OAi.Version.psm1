#
# OAi.Version.psm1 - single source of truth for the kit version.
#
# Every user-visible banner, log header and restore-point description reads
# from here. Before this module the version was hardcoded as "v2.3" in eight
# places, so the tool kept announcing itself as v2.3 long after the manifest
# had moved on - a run log said "0AI v2.3 Apply starting" while actually
# executing v2.9.1 policies. Bump the string below and every surface follows.
#

$script:OAI_VERSION = 'v2.11.0'

function Get-OAiVersion {
    [CmdletBinding()]
    param()
    return $script:OAI_VERSION
}

Export-ModuleMember -Function Get-OAiVersion
