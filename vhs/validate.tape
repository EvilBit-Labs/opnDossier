# Validate command — config structure verification
Output vhs/gif/validate.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 600
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set WindowBar Colorful
Set WindowBarSize 40

Type "./vhs/opnDossier validate testdata/sample.config.1.xml"
Sleep 500ms
Enter
Sleep 2s

Type "./vhs/opnDossier validate --json-output testdata/sample.config.1.xml"
Sleep 500ms
Enter
Sleep 3s
Screenshot vhs/screenshots/validate.png
