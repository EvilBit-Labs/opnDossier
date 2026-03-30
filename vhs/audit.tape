# Audit command — blue team compliance assessment
Output vhs/gif/audit.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 800
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set WindowBar Colorful
Set WindowBarSize 40

Type "./vhs/opnDossier audit --mode blue --plugins stig testdata/sample.config.1.xml"
Sleep 500ms
Enter
Sleep 6s
Screenshot vhs/screenshots/audit.png
