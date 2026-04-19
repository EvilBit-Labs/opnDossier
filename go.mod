module github.com/EvilBit-Labs/opnDossier

go 1.26

toolchain go1.26.2

require (
	github.com/charmbracelet/bubbles v1.0.0
	github.com/charmbracelet/fang v1.0.0
	github.com/charmbracelet/glamour v1.0.0
	github.com/charmbracelet/lipgloss v1.1.1-0.20250404203927-76690c660834
	github.com/charmbracelet/log v1.0.0
	github.com/clbanning/mxj v1.8.4
	github.com/go-playground/validator/v10 v10.30.2
	github.com/k3a/html2text v1.4.0
	github.com/nao1215/markdown v0.13.0
	github.com/sebdah/goldie/v2 v2.8.0
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	github.com/spf13/viper v1.21.0
	github.com/stretchr/testify v1.11.1
	github.com/yuin/goldmark v1.8.2
	github.com/yuin/goldmark-emoji v1.0.6
	go.uber.org/automaxprocs v1.6.0
	golang.org/x/term v0.42.0
	golang.org/x/text v0.36.0
	gopkg.in/yaml.v3 v3.0.1
)

// Pseudo-version survivors (v0.0.0-YYYYMMDDHHMMSS-<commit>) — tracked here for
// supply-chain auditability. Each is retained because no tagged upstream release
// exists as of 2026-04-19. Criterion for keeping a pseudo-version: (1) module is
// a transitive dep we cannot drop without removing a first-class feature, (2)
// upstream has published zero semver tags or the package is explicitly
// experimental. Re-evaluate when upstream tags a release.
//
//   - github.com/charmbracelet/ultraviolet         — no tagged releases; transitive of charmbracelet/fang
//   - github.com/charmbracelet/x/exp/charmtone     — charmbracelet experimental pkg; no tagged release
//   - github.com/charmbracelet/x/exp/slice         — charmbracelet experimental pkg; no tagged release
//   - github.com/erikgeiser/coninput               — no tagged releases; transitive of bubbletea
//   - github.com/muesli/ansi                       — no tagged releases; transitive of bubbletea/bubbles
//   - github.com/olekukonko/cat                    — no tagged releases; transitive of olekukonko/tablewriter
//   - github.com/xo/terminfo                       — no tagged releases; transitive of charmbracelet/colorprofile
//   - golang.org/x/exp                             — upstream policy: x/exp ships only as pseudo-versions
//   - gopkg.in/check.v1                            — test-only transitive of gopkg.in/yaml.v3; upstream ships pseudo-versions
require (
	charm.land/lipgloss/v2 v2.0.3 // indirect
	github.com/alecthomas/chroma/v2 v2.23.1 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/charmbracelet/bubbletea v1.3.10 // indirect
	github.com/charmbracelet/colorprofile v0.4.3 // indirect
	github.com/charmbracelet/harmonica v0.2.0 // indirect
	github.com/charmbracelet/ultraviolet v0.0.0-20260416161146-9c68a866306c // indirect; no tagged release (transitive of charm.land/lipgloss/v2 via charmbracelet/fang)
	github.com/charmbracelet/x/ansi v0.11.7 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.15 // indirect
	github.com/charmbracelet/x/exp/charmtone v0.0.0-20260419004333-9332b2225b80 // indirect; charmbracelet experimental pkg; no tagged release
	github.com/charmbracelet/x/exp/slice v0.0.0-20260419004333-9332b2225b80 // indirect; charmbracelet experimental pkg; no tagged release
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/charmbracelet/x/termios v0.1.1 // indirect
	github.com/charmbracelet/x/windows v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dlclark/regexp2 v1.12.0 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect; no tagged release (transitive of charmbracelet/bubbletea)
	github.com/fatih/color v1.19.0 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.13 // indirect
	github.com/go-logfmt/logfmt v0.6.1 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/gorilla/css v1.0.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/karrick/godirwalk v1.17.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.4.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.21 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.23 // indirect
	github.com/microcosm-cc/bluemonday v1.0.27 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect; no tagged release (transitive of charmbracelet/bubbletea)
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/mango v0.2.0 // indirect
	github.com/muesli/mango-cobra v1.3.0 // indirect
	github.com/muesli/mango-pflag v0.2.0 // indirect
	github.com/muesli/reflow v0.3.0 // indirect
	github.com/muesli/roff v0.1.0 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/olekukonko/cat v0.0.0-20250911104152-50322a0618f6 // indirect; no tagged release (transitive of olekukonko/tablewriter via nao1215/markdown)
	github.com/olekukonko/errors v1.3.0 // indirect
	github.com/olekukonko/ll v0.1.8 // indirect
	github.com/olekukonko/tablewriter v1.1.4 // indirect
	github.com/pelletier/go-toml/v2 v2.3.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sagikazarmark/locafero v0.12.0 // indirect
	github.com/sergi/go-diff v1.4.0 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect; no tagged release (transitive of charmbracelet/colorprofile via fang)
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f // indirect; upstream policy: x/exp ships only as pseudo-versions
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect; no tagged release (test-only transitive of gopkg.in/yaml.v3)
)
