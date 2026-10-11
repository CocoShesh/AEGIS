rule RS_YARA_REMOTE_SHELL_PIPE {
 meta:
  description = "Remote content piped into a shell"
 strings:
  $curl = /curl[^\r\n]{0,160}\|[ \t]*(ba)?sh/
  $wget = /wget[^\r\n]{0,160}\|[ \t]*(ba)?sh/
 condition: any of them
}
rule RS_YARA_POWERSHELL_ENCODED {
 meta:
  description = "PowerShell encoded-command reference"
 strings:
  $cmd = /powershell[^\r\n]{0,100}-(enc|encodedcommand)[ \t]+[A-Za-z0-9+\/=]{20,}/ nocase
 condition: $cmd
}
rule RS_YARA_PYTHON_PICKLE_LOAD {
 meta:
  description = "Python pickle deserialization reference"
 strings:
  $cmd = "pickle.loads(" ascii
 condition: $cmd
}
