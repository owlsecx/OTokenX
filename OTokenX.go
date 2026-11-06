// OTokenX — Windows Token/Privilege Analyzer
// OWL Batch-3 offensive security toolkit.
// Author : khaled.s.haddad    Website : owlsec.org
// Language: Go (standard library only; static, CGO-free build).
// AUTHORIZED TESTING ONLY. See --howto for the legal & ethical warning.

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ---- OWL UI KIT (red/black) — stdlib only. Paste into each tool's main.go ----
const (
	R   = "\033[91m"
	DR  = "\033[96m"
	GRN = "\033[92m"
	YLW = "\033[93m"
	CY  = "\033[96m"
	W   = "\033[97m"
	B   = "\033[1m"
	X   = "\033[0m"
	MG  = "\033[95m"
	DIM = "\033[2m"
	OR  = "\033[38;5;208m"
	GY  = "\033[90m"
)

const (
	SUITE   = "Owl Windows Suite"
	AUTHOR  = "khaled.s.haddad"
	WEBSITE = "owlsec.org"
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear() {
	if !noColor {
		fmt.Print("\033[H\033[2J")
	}
}
func rule()            { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func line(w int)       { fmt.Println(col(strings.Repeat("─", w), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }
func header(title string) {
	fmt.Println()
	rule()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	rule()
	fmt.Println()
}

var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, err := stdin.ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	stdin.ReadString('\n')
}
func stripANSI(s string) string {
	out := []rune{}
	esc := false
	for _, r := range s {
		if r == '\033' {
			esc = true
			continue
		}
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
func visw(s string) int { return len([]rune(stripANSI(s))) }
func pad(s string, n int) string {
	if visw(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visw(s))
}
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = visw(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && visw(c) > w[i] {
				w[i] = visw(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), B+CY))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DIM))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DIM))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DIM))
			}
		}
		fmt.Println("  " + rb.String())
	}
}
func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(TAGLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	rule()
	fmt.Println()
}
func menu(title string, items []string) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for i, it := range items {
		fmt.Println("  " + col(pad(fmt.Sprintf("[%d]", i+1), 4), CY+B) + "  " + col(it, W))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col("Help & Usage", W))
	fmt.Println("  " + col(pad("[0]", 4), R+B) + "  " + col("Exit", W))
	fmt.Println()
	rule()
	return prompt("Select option")
}

// ---- OWL house help (shared layout) ----
type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	out := []string{}
	cur := ""
	for _, w := range words {
		if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
			out = append(out, cur)
			cur = w
		} else if cur == "" {
			cur = w
		} else {
			cur += " " + w
		}
	}
	out = append(out, cur)
	return out
}
func owlHelpTitle(t string) { fmt.Println(); fmt.Println("  " + col("▸ "+t, B+CY)) }
func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}
func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}
func tuiHelp() {
	clear()
	banner()
	rule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	rule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	rule()
	fmt.Println("  " + col("Next page: command-line flags & examples", DIM))
	pause()
	clear()
	usage()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

const APPNAME = "OTokenX"
const TAGLINE = "Windows Token/Privilege Analyzer"
const VERSION = "1.0.0"
const CATEGORY = "OAttack"

const BANNER = `
 ██████╗ ████████╗ ██████╗ ██╗  ██╗███████╗███╗   ██╗██╗  ██╗
██╔═══██╗╚══██╔══╝██╔═══██╗██║ ██╔╝██╔════╝████╗  ██║╚██╗██╔╝
██║   ██║   ██║   ██║   ██║█████╔╝ █████╗  ██╔██╗ ██║ ╚███╔╝ 
██║   ██║   ██║   ██║   ██║██╔═██╗ ██╔══╝  ██║╚██╗██║ ██╔██╗ 
╚██████╔╝   ██║   ╚██████╔╝██║  ██╗███████╗██║ ╚████║██╔╝ ██╗
 ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝
`

// ============================================================================
//  SHARED ENGINE  —  types, CLI, export (txt/md/json/csv/sarif), grading,
//  HOW TO USE renderer, interactive red/black TUI, and domain utilities.
//  This block is identical across every OWL Batch-3 tool; each tool supplies
//  its own deep domain engine (catalogs, parsers, generators, scoring) that
//  plugs into the hooks declared at the bottom of this file.
// ============================================================================

// Finding is a single analysis result with MITRE ATT&CK mapping and a score.
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Detail      string   `json:"detail"`
	Evidence    string   `json:"evidence"`
	Remediation string   `json:"remediation"`
	Mitre       []string `json:"mitre"`
	Score       int      `json:"score"`
	Ref         string   `json:"ref,omitempty"`
}

// Section is a titled block of lines used by HOW TO USE and catalog views.
type Section struct {
	Title string
	Lines []string
}

// MenuItem is one interactive action in the TUI.
type MenuItem struct {
	Label  string
	Action func()
}

// AnalysisResult is the full output of a domain analysis or demo run.
type AnalysisResult struct {
	Target   string            `json:"target"`
	Tool     string            `json:"tool"`
	When     string            `json:"when"`
	Findings []Finding         `json:"findings"`
	Stats    map[string]string `json:"stats"`
	Grade    string            `json:"grade"`
	Notes    []string          `json:"notes,omitempty"`
}

// ---------------------------------------------------------------------------
//  Severity model
// ---------------------------------------------------------------------------

const (
	SevCrit = "CRITICAL"
	SevHigh = "HIGH"
	SevMed  = "MEDIUM"
	SevLow  = "LOW"
	SevInfo = "INFO"
)

func sevRank(s string) int {
	switch strings.ToUpper(s) {
	case SevCrit:
		return 5
	case SevHigh:
		return 4
	case SevMed:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

func sevWeight(s string) int {
	switch strings.ToUpper(s) {
	case SevCrit:
		return 40
	case SevHigh:
		return 25
	case SevMed:
		return 12
	case SevLow:
		return 5
	case SevInfo:
		return 1
	}
	return 0
}

func sevColor(s string) string {
	switch strings.ToUpper(s) {
	case SevCrit:
		return R + B
	case SevHigh:
		return R
	case SevMed:
		return YLW
	case SevLow:
		return W
	default:
		return GY
	}
}

// sarifLevel maps a severity to a SARIF result level.
func sarifLevel(s string) string {
	switch strings.ToUpper(s) {
	case SevCrit, SevHigh:
		return "error"
	case SevMed:
		return "warning"
	case SevLow, SevInfo:
		return "note"
	}
	return "none"
}

// ---------------------------------------------------------------------------
//  Grading — convert a set of findings into an A+..F posture grade.
// ---------------------------------------------------------------------------

func gradeFromFindings(fs []Finding) string {
	risk := 0
	for _, f := range fs {
		risk += sevWeight(f.Severity)
	}
	switch {
	case risk == 0:
		return "A+"
	case risk <= 5:
		return "A"
	case risk <= 15:
		return "B"
	case risk <= 30:
		return "C"
	case risk <= 60:
		return "D"
	case risk <= 100:
		return "E"
	default:
		return "F"
	}
}

func gradeMeaning(g string) string {
	switch g {
	case "A+":
		return "no material exposure detected"
	case "A":
		return "minimal exposure; strong posture"
	case "B":
		return "minor issues; generally solid"
	case "C":
		return "moderate exposure; remediation advised"
	case "D":
		return "significant exposure; prioritize fixes"
	case "E":
		return "severe exposure; urgent remediation"
	default:
		return "critical exposure; immediate action required"
	}
}

func gradeColor(g string) string {
	switch g {
	case "A+", "A":
		return GRN + B
	case "B", "C":
		return YLW + B
	default:
		return R + B
	}
}

// ---------------------------------------------------------------------------
//  Global flags / state
// ---------------------------------------------------------------------------

var (
	flHelp    = flag.Bool("help", false, "show rich usage help and exit")
	flH       = flag.Bool("h", false, "alias for --help")
	flVersion = flag.Bool("version", false, "print version and exit")
	flHowto   = flag.Bool("howto", false, "show the HOW TO USE screen and exit")
	flDemo    = flag.Bool("demo", false, "run a self-contained synthetic demonstration")
	flInput   = flag.String("input", "", "path to an input file to analyze")
	flPath    = flag.String("path", "", "alias for --input (subject path/file)")
	flTarget  = flag.String("target", "", "logical target name/label for the report")
	flFormat  = flag.String("format", "txt", "export format: txt|md|json|csv|sarif")
	flOutput  = flag.String("output", "", "write export to FILE instead of stdout")
	flNoColor = flag.Bool("no-color", false, "disable ANSI colors")
	flSelf    = flag.Bool("selftest", false, "run internal self-test and exit")
	flCatalog = flag.Bool("catalog", false, "print the built-in reference catalog and exit")
	flList    = flag.Bool("list", false, "alias for --catalog")
	flQuiet   = flag.Bool("quiet", false, "suppress banner in CLI export mode")
)

var lastResult *AnalysisResult

// ---------------------------------------------------------------------------
//  main
// ---------------------------------------------------------------------------

func main() {
	flag.Usage = usage
	flag.Parse()

	if *flNoColor {
		noColor = true
	}

	switch {
	case *flHelp || *flH:
		usage()
		return
	case *flVersion:
		fmt.Printf("%s %s  (author khaled.s.haddad, owlsec.org)\n", APPNAME, VERSION)
		return
	case *flSelf:
		os.Exit(runSelfTest())
	case *flHowto:
		printHowto()
		return
	case *flCatalog || *flList:
		printCatalog()
		return
	case *flDemo:
		res := domainDemoResult()
		finalize(&res)
		lastResult = &res
		if !*flQuiet {
			renderResult(&res)
		}
		if *flOutput != "" || *flFormat != "txt" {
			emitExport(&res)
		}
		return
	}

	in := firstNonEmpty(*flInput, *flPath)
	if in != "" {
		res, err := domainAnalyze(in)
		if err != nil {
			errMsg("analysis failed: " + err.Error())
			os.Exit(1)
		}
		finalize(&res)
		lastResult = &res
		if !*flQuiet {
			renderResult(&res)
		}
		emitExport(&res)
		return
	}

	// No actionable flags -> interactive TUI.
	interactive()
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// finalize fills defaulted fields (timestamp, tool, grade) on a result.
func finalize(r *AnalysisResult) {
	if r.When == "" {
		r.When = time.Now().Format("2006-01-02 15:04:05 -0700")
	}
	if r.Tool == "" {
		r.Tool = APPNAME
	}
	if r.Stats == nil {
		r.Stats = map[string]string{}
	}
	if r.Grade == "" {
		r.Grade = gradeFromFindings(r.Findings)
	}
	sortFindings(r.Findings)
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if sevRank(fs[i].Severity) != sevRank(fs[j].Severity) {
			return sevRank(fs[i].Severity) > sevRank(fs[j].Severity)
		}
		return fs[i].ID < fs[j].ID
	})
}

// ---------------------------------------------------------------------------
//  Usage / help
// ---------------------------------------------------------------------------

func usage() {
	if !*flQuiet {
		banner()
	}
	fmt.Println("  " + col("USAGE", R+B))
	fmt.Printf("    %s [flags]\n", strings.ToLower(APPNAME))
	fmt.Println()
	fmt.Println("  " + col("DESCRIPTION", R+B))
	for _, ln := range wrap(domainSummary(), 68) {
		fmt.Println("    " + ln)
	}
	fmt.Println()
	fmt.Println("  " + col("CORE FLAGS", R+B))
	helpRow("-h, --help", "show this rich usage help")
	helpRow("--version", "print version and exit")
	helpRow("--howto", "show the HOW TO USE screen (legal, steps, nav)")
	helpRow("--demo", "run a self-contained synthetic demonstration")
	helpRow("--catalog, --list", "print the built-in reference catalog")
	helpRow("--input FILE", "analyze FILE (also --path)")
	helpRow("--target NAME", "label the engagement/target in the report")
	helpRow("--format FMT", "export format: txt|md|json|csv|sarif")
	helpRow("--output FILE", "write export to FILE (default stdout)")
	helpRow("--no-color", "disable ANSI colors")
	helpRow("--quiet", "suppress banner in export mode")
	fmt.Println()
	fmt.Println("  " + col("EXAMPLES", R+B))
	fmt.Printf("    %s                      # interactive red/black TUI\n", strings.ToLower(APPNAME))
	fmt.Printf("    %s --demo                # synthetic walkthrough\n", strings.ToLower(APPNAME))
	fmt.Printf("    %s --howto               # how-to-use + legal warning\n", strings.ToLower(APPNAME))
	fmt.Printf("    %s --input data --format sarif --output out.sarif\n", strings.ToLower(APPNAME))
	fmt.Println()
	fmt.Println("  " + col("MITRE ATT&CK", R+B))
	fmt.Println("    primary: " + MITRE_PRIMARY + "  (" + mitreName(MITRE_PRIMARY) + ")")
	fmt.Println("    " + strings.Join(MITRE_TAGS, ", "))
	fmt.Println()
	line(64)
	fmt.Println("  " + col("Authorized testing only. See --howto for the legal warning.", GY))
}

func helpRow(a, b string) {
	fmt.Printf("    %s %s\n", col(pad(a, 22), W), col(b, GY))
}

// ---------------------------------------------------------------------------
//  HOW TO USE screen  (MANDATORY — menu item + --howto flag)
// ---------------------------------------------------------------------------

func howtoSections() []Section {
	var secs []Section
	secs = append(secs, Section{
		Title: "LEGAL & ETHICAL WARNING",
		Lines: []string{
			APPNAME + " is an offensive-security tool for AUTHORIZED testing only.",
			"Use it solely on systems and data you own or have EXPLICIT, WRITTEN",
			"permission to assess. Unauthorized access, interception, or attack is",
			"illegal in most jurisdictions (e.g. CFAA, Computer Misuse Act, GDPR).",
			"This build performs OFFLINE analysis, parsing, planning and lab",
			"generation only; it does not attack third parties. You are solely",
			"responsible for staying within the scope of your engagement and law.",
			"Keep all artifacts, hashes and credentials in your authorized vault.",
		},
	})
	steps := domainHowtoSteps()
	secs = append(secs, Section{Title: "HOW TO USE", Lines: numbered(steps)})
	secs = append(secs, Section{
		Title: "NAVIGATION",
		Lines: []string{
			"Launch with no arguments for the interactive red/black TUI.",
			"At each menu type the [NN] number of an option and press Enter.",
			"[00] exits the current menu or the program.",
			"HOW TO USE is always available from the main menu and via --howto.",
			"Every result view can be exported (txt/md/json/csv/sarif).",
			"Use --input FILE for non-interactive (CLI) analysis and export.",
		},
	})
	secs = append(secs, Section{Title: "REQUIREMENTS", Lines: domainRequirements()})
	secs = append(secs, domainHowtoNotes()...)
	secs = append(secs, Section{
		Title: "EXPORT & REPORTING",
		Lines: []string{
			"Formats: txt (console report), md (Markdown), json (machine),",
			"csv (spreadsheet), sarif (SARIF 2.1.0 for CI/code-scanning).",
			"Findings carry MITRE ATT&CK technique IDs and an A+..F grade.",
			"Example: --input data --format sarif --output report.sarif",
		},
	})
	return secs
}

func printHowto() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  HOW TO USE — "+APPNAME, B+CY))
	fmt.Println()
	renderSections(howtoSections())
}

func renderSections(secs []Section) {
	for _, s := range secs {
		fmt.Println("  " + col("⬡ "+s.Title, B+CY))
		line(64)
		for _, ln := range s.Lines {
			fmt.Println("   " + col(ln, W))
		}
		fmt.Println()
	}
}

func numbered(items []string) []string {
	out := make([]string, 0, len(items))
	for i, it := range items {
		out = append(out, fmt.Sprintf("%2d. %s", i+1, it))
	}
	return out
}

// ---------------------------------------------------------------------------
//  Catalog printing (CLI)
// ---------------------------------------------------------------------------

func printCatalog() {
	if !*flQuiet {
		clear()
		banner()
	}
	fmt.Println("  " + col("⬡  REFERENCE CATALOG — "+APPNAME, B+CY))
	fmt.Println()
	renderSections(domainCatalogSections())
}

// ---------------------------------------------------------------------------
//  Result rendering (console)
// ---------------------------------------------------------------------------

func renderResult(r *AnalysisResult) {
	clear()
	banner()
	fmt.Println("  " + col("⬡  RESULT — "+r.Tool, B+CY))
	fmt.Println("  " + col("target : ", DIM) + col(nz(r.Target, "(none)"), W))
	fmt.Println("  " + col("time   : ", DIM) + col(r.When, W))
	gc := gradeColor(r.Grade)
	fmt.Println("  " + col("grade  : ", DIM) + col(r.Grade, gc) + col("  ("+gradeMeaning(r.Grade)+")", GY))
	fmt.Println()
	if len(r.Stats) > 0 {
		fmt.Println("  " + col("⬡ STATISTICS", B+CY))
		keys := make([]string, 0, len(r.Stats))
		for k := range r.Stats {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("   %s %s\n", col(pad(k+":", 22), GY), col(r.Stats[k], W))
		}
		fmt.Println()
	}
	renderSevHistogram(r.Findings)
	if len(r.Findings) == 0 {
		okMsg("no findings")
	} else {
		fmt.Println("  " + col(fmt.Sprintf("⬡ FINDINGS (%d)", len(r.Findings)), B+CY))
		line(64)
		for _, f := range r.Findings {
			renderFinding(f)
		}
	}
	if tm := topMitre(r.Findings, 6); len(tm) > 0 {
		fmt.Println()
		fmt.Println("  " + col("⬡ TOP MITRE ATT&CK", B+CY))
		for _, m := range tm {
			info(m)
		}
	}
	if len(r.Notes) > 0 {
		fmt.Println()
		fmt.Println("  " + col("⬡ NOTES", B+CY))
		for _, n := range r.Notes {
			info(n)
		}
	}
}

func renderFinding(f Finding) {
	tag := col("["+f.Severity+"]", sevColor(f.Severity))
	fmt.Printf("  %s %s %s\n", tag, col(f.ID, DR), col(f.Title, W+B))
	if f.Category != "" {
		fmt.Println("      " + col("category : ", GY) + col(f.Category, W))
	}
	for _, ln := range wrap(f.Detail, 60) {
		fmt.Println("      " + col(ln, W))
	}
	if f.Evidence != "" {
		for _, ln := range wrap("evidence: "+f.Evidence, 60) {
			fmt.Println("      " + col(ln, GY))
		}
	}
	if f.Remediation != "" {
		for _, ln := range wrap("fix: "+f.Remediation, 60) {
			fmt.Println("      " + col(ln, GRN))
		}
	}
	if len(f.Mitre) > 0 {
		fmt.Println("      " + col("mitre: "+strings.Join(f.Mitre, ", "), R))
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
//  Export engine — TXT / MD / JSON / CSV / SARIF 2.1.0
// ---------------------------------------------------------------------------

func emitExport(r *AnalysisResult) {
	format := strings.ToLower(strings.TrimSpace(*flFormat))
	var data string
	switch format {
	case "", "txt":
		data = exportTXT(r)
	case "md", "markdown":
		data = exportMD(r)
	case "json":
		data = exportJSON(r)
	case "csv":
		data = exportCSV(r)
	case "sarif":
		data = exportSARIF(r)
	default:
		errMsg("unknown format: " + format + " (use txt|md|json|csv|sarif)")
		return
	}
	if *flOutput == "" {
		if format != "txt" {
			fmt.Println(data)
		}
		return
	}
	if err := os.WriteFile(*flOutput, []byte(data), 0644); err != nil {
		errMsg("write failed: " + err.Error())
		return
	}
	okMsg(fmt.Sprintf("wrote %s (%d bytes, %s)", *flOutput, len(data), format))
}

func exportTXT(r *AnalysisResult) string {
	var b strings.Builder
	b.WriteString("OWL " + APPNAME + " — " + TAGLINE + "\n")
	b.WriteString("author khaled.s.haddad  owlsec.org\n")
	b.WriteString(strings.Repeat("=", 64) + "\n")
	b.WriteString("target : " + nz(r.Target, "(none)") + "\n")
	b.WriteString("time   : " + r.When + "\n")
	b.WriteString("grade  : " + r.Grade + " (" + gradeMeaning(r.Grade) + ")\n")
	b.WriteString("mitre  : " + MITRE_PRIMARY + " " + strings.Join(MITRE_TAGS, " ") + "\n\n")
	if len(r.Stats) > 0 {
		b.WriteString("STATISTICS\n" + strings.Repeat("-", 64) + "\n")
		for _, k := range sortedKeys(r.Stats) {
			b.WriteString("  " + pad(k+":", 24) + r.Stats[k] + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString(fmt.Sprintf("FINDINGS (%d)\n", len(r.Findings)))
	b.WriteString(strings.Repeat("-", 64) + "\n")
	for _, f := range r.Findings {
		b.WriteString(fmt.Sprintf("[%s] %s  %s\n", f.Severity, f.ID, f.Title))
		if f.Category != "" {
			b.WriteString("    category   : " + f.Category + "\n")
		}
		if f.Detail != "" {
			b.WriteString("    detail     : " + f.Detail + "\n")
		}
		if f.Evidence != "" {
			b.WriteString("    evidence   : " + f.Evidence + "\n")
		}
		if f.Remediation != "" {
			b.WriteString("    remediation: " + f.Remediation + "\n")
		}
		if len(f.Mitre) > 0 {
			b.WriteString("    mitre      : " + strings.Join(f.Mitre, ", ") + "\n")
		}
		b.WriteString("    score      : " + strconv.Itoa(f.Score) + "\n\n")
	}
	for _, n := range r.Notes {
		b.WriteString("note: " + n + "\n")
	}
	return b.String()
}

func exportMD(r *AnalysisResult) string {
	var b strings.Builder
	b.WriteString("# OWL " + APPNAME + " — " + TAGLINE + "\n\n")
	b.WriteString("*author khaled.s.haddad · owlsec.org*\n\n")
	b.WriteString("| field | value |\n|---|---|\n")
	b.WriteString("| target | " + mdEsc(nz(r.Target, "(none)")) + " |\n")
	b.WriteString("| time | " + mdEsc(r.When) + " |\n")
	b.WriteString("| grade | **" + r.Grade + "** (" + gradeMeaning(r.Grade) + ") |\n")
	b.WriteString("| mitre | " + MITRE_PRIMARY + " " + strings.Join(MITRE_TAGS, " ") + " |\n\n")
	if len(r.Stats) > 0 {
		b.WriteString("## Statistics\n\n| metric | value |\n|---|---|\n")
		for _, k := range sortedKeys(r.Stats) {
			b.WriteString("| " + mdEsc(k) + " | " + mdEsc(r.Stats[k]) + " |\n")
		}
		b.WriteString("\n")
	}
	b.WriteString(fmt.Sprintf("## Findings (%d)\n\n", len(r.Findings)))
	for _, f := range r.Findings {
		b.WriteString("### [" + f.Severity + "] " + mdEsc(f.Title) + " `" + f.ID + "`\n\n")
		if f.Category != "" {
			b.WriteString("- **category:** " + mdEsc(f.Category) + "\n")
		}
		if f.Detail != "" {
			b.WriteString("- **detail:** " + mdEsc(f.Detail) + "\n")
		}
		if f.Evidence != "" {
			b.WriteString("- **evidence:** `" + f.Evidence + "`\n")
		}
		if f.Remediation != "" {
			b.WriteString("- **remediation:** " + mdEsc(f.Remediation) + "\n")
		}
		if len(f.Mitre) > 0 {
			b.WriteString("- **mitre:** " + strings.Join(f.Mitre, ", ") + "\n")
		}
		b.WriteString("- **score:** " + strconv.Itoa(f.Score) + "\n\n")
	}
	return b.String()
}

func exportJSON(r *AnalysisResult) string {
	payload := map[string]interface{}{
		"tool":         APPNAME,
		"tagline":      TAGLINE,
		"version":      VERSION,
		"author":       "khaled.s.haddad",
		"website":      "owlsec.org",
		"mitrePrimary": MITRE_PRIMARY,
		"mitreTags":    MITRE_TAGS,
		"result":       r,
	}
	buf, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "{\"error\":\"" + err.Error() + "\"}"
	}
	return string(buf)
}

func exportCSV(r *AnalysisResult) string {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"id", "severity", "category", "title", "detail", "evidence", "remediation", "mitre", "score"})
	for _, f := range r.Findings {
		w.Write([]string{
			f.ID, f.Severity, f.Category, f.Title, f.Detail, f.Evidence,
			f.Remediation, strings.Join(f.Mitre, " "), strconv.Itoa(f.Score),
		})
	}
	w.Flush()
	return buf.String()
}

func exportSARIF(r *AnalysisResult) string {
	rules := map[string]bool{}
	var ruleList []map[string]interface{}
	var results []map[string]interface{}
	for _, f := range r.Findings {
		if !rules[f.ID] {
			rules[f.ID] = true
			ruleList = append(ruleList, map[string]interface{}{
				"id":               f.ID,
				"name":             f.Title,
				"shortDescription": map[string]string{"text": f.Title},
				"fullDescription":  map[string]string{"text": nz(f.Detail, f.Title)},
				"helpUri":          "https://owlsec.org",
				"properties": map[string]interface{}{
					"category": f.Category,
					"mitre":    f.Mitre,
				},
			})
		}
		results = append(results, map[string]interface{}{
			"ruleId": f.ID,
			"level":  sarifLevel(f.Severity),
			"message": map[string]string{
				"text": f.Title + ". " + f.Detail + nzPrefix(" Evidence: ", f.Evidence),
			},
			"properties": map[string]interface{}{
				"severity": f.Severity,
				"score":    f.Score,
				"mitre":    f.Mitre,
			},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]string{"uri": nz(r.Target, APPNAME)},
					},
				},
			},
		})
	}
	sarif := map[string]interface{}{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           APPNAME,
						"fullName":       "OWL " + APPNAME + " — " + TAGLINE,
						"version":        VERSION,
						"informationUri": "https://owlsec.org",
						"organization":   "owlsec.org / khaled.s.haddad",
						"rules":          ruleList,
					},
				},
				"results": results,
				"properties": map[string]interface{}{
					"grade":        r.Grade,
					"mitrePrimary": MITRE_PRIMARY,
					"target":       r.Target,
				},
			},
		},
	}
	buf, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return "{\"error\":\"" + err.Error() + "\"}"
	}
	return string(buf)
}

// ---------------------------------------------------------------------------
//  Interactive TUI
// ---------------------------------------------------------------------------

func interactive() {
	for {
		items := []string{
			"Run DEMO (synthetic walkthrough)",
			"Analyze an input file",
			"Reference catalog",
		}
		dm := domainMenuItems()
		for _, m := range dm {
			items = append(items, m.Label)
		}
		items = append(items,
			"View last result",
			"Export last result",
			"HOW TO USE",
			"About / MITRE mapping",
		)
		choice := menu("MAIN MENU — "+TAGLINE, items)
		switch strings.ToLower(choice) {
		case "h", "help", "?":
			tuiHelp()
		case "0", "00", "q", "exit":
			clear()
			okMsg("Stay authorized. Goodbye.")
			return
		case "1":
			res := domainDemoResult()
			finalize(&res)
			lastResult = &res
			renderResult(&res)
			pause()
		case "2":
			actionAnalyze()
		case "3":
			clear()
			banner()
			fmt.Println("  " + col("⬡  REFERENCE CATALOG", B+CY))
			fmt.Println()
			renderSections(domainCatalogSections())
			pause()
		default:
			handleDynamicChoice(choice, dm)
		}
	}
}

// handleDynamicChoice resolves menu numbers for domain items and trailing items.
func handleDynamicChoice(choice string, dm []MenuItem) {
	n, err := strconv.Atoi(choice)
	if err != nil {
		errMsg("invalid selection")
		pause()
		return
	}
	base := 3 // first three fixed items
	if n > base && n <= base+len(dm) {
		dm[n-base-1].Action()
		return
	}
	idx := n - base - len(dm)
	switch idx {
	case 1: // view last
		if lastResult == nil {
			warnMsg("no result yet — run DEMO or analyze a file first")
			pause()
			return
		}
		renderResult(lastResult)
		pause()
	case 2: // export last
		actionExport()
	case 3: // howto
		printHowto()
		pause()
	case 4: // about
		actionAbout()
	default:
		errMsg("invalid selection")
		pause()
	}
}

func actionAnalyze() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  ANALYZE INPUT", B+CY))
	fmt.Println()
	p := prompt("path to input file")
	if p == "" {
		warnMsg("cancelled")
		pause()
		return
	}
	res, err := domainAnalyze(p)
	if err != nil {
		errMsg(err.Error())
		pause()
		return
	}
	finalize(&res)
	lastResult = &res
	renderResult(&res)
	pause()
}

func actionExport() {
	if lastResult == nil {
		warnMsg("no result yet — run DEMO or analyze a file first")
		pause()
		return
	}
	clear()
	banner()
	fmt.Println("  " + col("⬡  EXPORT LAST RESULT", B+CY))
	fmt.Println()
	f := prompt("format txt|md|json|csv|sarif")
	if f == "" {
		f = "txt"
	}
	o := prompt("output file (blank = screen)")
	*flFormat = f
	*flOutput = o
	if o == "" {
		var data string
		switch strings.ToLower(f) {
		case "md":
			data = exportMD(lastResult)
		case "json":
			data = exportJSON(lastResult)
		case "csv":
			data = exportCSV(lastResult)
		case "sarif":
			data = exportSARIF(lastResult)
		default:
			data = exportTXT(lastResult)
		}
		fmt.Println()
		fmt.Println(data)
	} else {
		emitExport(lastResult)
	}
	pause()
}

func actionAbout() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  ABOUT", B+CY))
	fmt.Println()
	for _, ln := range wrap(domainSummary(), 64) {
		fmt.Println("   " + col(ln, W))
	}
	fmt.Println()
	fmt.Println("  " + col("⬡ MITRE ATT&CK", B+CY))
	fmt.Println("   primary : " + col(MITRE_PRIMARY+"  "+mitreName(MITRE_PRIMARY), W))
	for _, t := range MITRE_TAGS {
		fmt.Println("   " + col(pad(t, 12), R) + col(mitreName(t), GY))
	}
	fmt.Println()
	fmt.Println("  " + col("author khaled.s.haddad  ·  owlsec.org  ·  "+VERSION, GY))
	pause()
}

// ---------------------------------------------------------------------------
//  MITRE reference table (subset relevant to Batch-3 offensive tooling)
// ---------------------------------------------------------------------------

var mitreTable = map[string]string{
	"T1027":     "Obfuscated Files or Information",
	"T1027.009": "Embedded Payloads",
	"T1027.010": "Command Obfuscation",
	"T1059":     "Command and Scripting Interpreter",
	"T1059.001": "PowerShell",
	"T1059.003": "Windows Command Shell",
	"T1059.004": "Unix Shell",
	"T1059.005": "Visual Basic",
	"T1059.006": "Python",
	"T1059.007": "JavaScript",
	"T1105":     "Ingress Tool Transfer",
	"T1090":     "Proxy",
	"T1087":     "Account Discovery",
	"T1087.002": "Domain Account Discovery",
	"T1110":     "Brute Force",
	"T1110.003": "Password Spraying",
	"T1134":     "Access Token Manipulation",
	"T1134.001": "Token Impersonation/Theft",
	"T1134.002": "Create Process with Token",
	"T1134.005": "SID-History Injection",
	"T1135":     "Network Share Discovery",
	"T1548":     "Abuse Elevation Control Mechanism",
	"T1548.002": "Bypass User Account Control",
	"T1548.003": "Sudo and Sudo Caching",
	"T1558":     "Steal or Forge Kerberos Tickets",
	"T1558.003": "Kerberoasting",
	"T1558.004": "AS-REP Roasting",
	"T1611":     "Escape to Host",
	"T1210":     "Exploitation of Remote Services",
	"T1021":     "Remote Services",
	"T1021.002": "SMB/Windows Admin Shares",
	"T1069":     "Permission Groups Discovery",
	"T1482":     "Domain Trust Discovery",
	"T1078":     "Valid Accounts",
	"T1003":     "OS Credential Dumping",
	"TA0001":    "Initial Access",
	"TA0002":    "Execution",
	"TA0003":    "Persistence",
	"TA0004":    "Privilege Escalation",
	"TA0005":    "Defense Evasion",
	"TA0006":    "Credential Access",
	"TA0007":    "Discovery",
	"TA0008":    "Lateral Movement",
	"TA0010":    "Exfiltration",
	"TA0011":    "Command and Control",
}

func mitreName(id string) string {
	if n, ok := mitreTable[id]; ok {
		return n
	}
	return "technique"
}

// ---------------------------------------------------------------------------
//  Domain utilities shared by every tool (entropy, hashing, encoders, text)
// ---------------------------------------------------------------------------

// shannonEntropy returns bits/byte (0..8) for a byte slice.
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	ent := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent
}

func entropyVerdict(e float64) string {
	switch {
	case e >= 7.5:
		return "very high (encrypted/packed/compressed)"
	case e >= 6.5:
		return "high (encoded/compressed)"
	case e >= 5.0:
		return "moderate (mixed/base64-ish)"
	case e >= 3.0:
		return "low (plain text/code)"
	default:
		return "very low (repetitive/structured)"
	}
}

func b64Encode(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
func b64Decode(s string) (string, error) {
	d, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	return string(d), err
}
func hexEncode(s string) string { return hex.EncodeToString([]byte(s)) }

func gzipB64(s string) string {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write([]byte(s))
	w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func md5Hex(s string) string    { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }
func sha1Hex(s string) string   { h := sha1.Sum([]byte(s)); return hex.EncodeToString(h[:]) }
func sha256Hex(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// utf16leB64 encodes a string as UTF-16LE then base64 (PowerShell -EncodedCommand).
func utf16leB64(s string) string {
	var buf bytes.Buffer
	for _, r := range s {
		if r < 0x10000 {
			buf.WriteByte(byte(r))
			buf.WriteByte(byte(r >> 8))
		} else {
			r -= 0x10000
			hi := 0xD800 + (r >> 10)
			lo := 0xDC00 + (r & 0x3FF)
			buf.WriteByte(byte(hi))
			buf.WriteByte(byte(hi >> 8))
			buf.WriteByte(byte(lo))
			buf.WriteByte(byte(lo >> 8))
		}
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func xorBytes(data []byte, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

// classifyCharset reports character-class composition of a string.
func classifyCharset(s string) (lower, upper, digit, space, punct int) {
	for _, r := range s {
		switch {
		case unicode.IsLower(r):
			lower++
		case unicode.IsUpper(r):
			upper++
		case unicode.IsDigit(r):
			digit++
		case unicode.IsSpace(r):
			space++
		default:
			punct++
		}
	}
	return
}

func randHex(n int) string {
	const h = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = h[rand.Intn(16)]
	}
	return string(b)
}

func randID(prefix string) string {
	return prefix + "-" + randHex(6)
}

// ---------------------------------------------------------------------------
//  Small text/formatting helpers
// ---------------------------------------------------------------------------

func nz(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func nzPrefix(prefix, s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return prefix + s
}

func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func wrap(s string, width int) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	words := strings.Fields(s)
	var lines []string
	cur := ""
	for _, w := range words {
		if cur == "" {
			cur = w
		} else if len(cur)+1+len(w) <= width {
			cur += " " + w
		} else {
			lines = append(lines, cur)
			cur = w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

func readFileLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

func readFileString(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}

func baseName(p string) string { return filepath.Base(p) }

func mustInt(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func reFind(pattern, s string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return re.FindStringSubmatch(s)
}

func reAll(pattern, s string) [][]string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return re.FindAllStringSubmatch(s, -1)
}

func contains(hay, needle string) bool {
	return strings.Contains(strings.ToLower(hay), strings.ToLower(needle))
}

func titleOf(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func mkFinding(id, title, sev, cat, detail string, mitre []string) Finding {
	return Finding{
		ID:       id,
		Title:    title,
		Severity: sev,
		Category: cat,
		Detail:   detail,
		Mitre:    mitre,
		Score:    sevWeight(sev),
	}
}

// ---------------------------------------------------------------------------
//  Binary read helpers (little/big endian) for protocol parsers.
// ---------------------------------------------------------------------------

func u16LE(b []byte, off int) uint16 {
	if off < 0 || off+2 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint16(b[off : off+2])
}

func u32LE(b []byte, off int) uint32 {
	if off < 0 || off+4 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint32(b[off : off+4])
}

func u16BE(b []byte, off int) uint16 {
	if off < 0 || off+2 > len(b) {
		return 0
	}
	return binary.BigEndian.Uint16(b[off : off+2])
}

func u32BE(b []byte, off int) uint32 {
	if off < 0 || off+4 > len(b) {
		return 0
	}
	return binary.BigEndian.Uint32(b[off : off+4])
}

func hexDump(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		sb.WriteString(fmt.Sprintf("%08x  ", i))
		for j := i; j < i+16; j++ {
			if j < end {
				sb.WriteString(fmt.Sprintf("%02x ", b[j]))
			} else {
				sb.WriteString("   ")
			}
		}
		sb.WriteString(" |")
		for j := i; j < end; j++ {
			c := b[j]
			if c >= 32 && c < 127 {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
//  Severity analytics (used by result rendering and stats)
// ---------------------------------------------------------------------------

func sevHistogram(fs []Finding) map[string]int {
	h := map[string]int{SevCrit: 0, SevHigh: 0, SevMed: 0, SevLow: 0, SevInfo: 0}
	for _, f := range fs {
		k := strings.ToUpper(f.Severity)
		if _, ok := h[k]; ok {
			h[k]++
		} else {
			h[SevInfo]++
		}
	}
	return h
}

func renderSevHistogram(fs []Finding) {
	if len(fs) == 0 {
		return
	}
	h := sevHistogram(fs)
	order := []string{SevCrit, SevHigh, SevMed, SevLow, SevInfo}
	max := 1
	for _, k := range order {
		if h[k] > max {
			max = h[k]
		}
	}
	fmt.Println("  " + col("⬡ SEVERITY BREAKDOWN", B+CY))
	for _, k := range order {
		n := h[k]
		barLen := (n * 30) / max
		if n > 0 && barLen == 0 {
			barLen = 1
		}
		bar := strings.Repeat("█", barLen)
		fmt.Printf("   %s %s %s\n", col(pad(k, 9), sevColor(k)), col(pad(strconv.Itoa(n), 3), W), col(bar, sevColor(k)))
	}
	fmt.Println()
}

// mitreTally counts technique IDs across findings.
func mitreTally(fs []Finding) map[string]int {
	t := map[string]int{}
	for _, f := range fs {
		for _, m := range f.Mitre {
			t[m]++
		}
	}
	return t
}

func topMitre(fs []Finding, n int) []string {
	t := mitreTally(fs)
	type kv struct {
		k string
		v int
	}
	var arr []kv
	for k, v := range t {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].v != arr[j].v {
			return arr[i].v > arr[j].v
		}
		return arr[i].k < arr[j].k
	})
	var out []string
	for i, e := range arr {
		if i >= n {
			break
		}
		out = append(out, fmt.Sprintf("%s x%d (%s)", e.k, e.v, mitreName(e.k)))
	}
	return out
}

// ---------------------------------------------------------------------------
//  Generic parsing & text helpers (shared by domain engines)
// ---------------------------------------------------------------------------

func parseKVLine(line, sep string) (string, string, bool) {
	i := strings.Index(line, sep)
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+len(sep):]), true
}

// tokenizeArgs splits a command line honoring simple single/double quotes.
func tokenizeArgs(s string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	inTok := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
			inTok = true
		case r == '\'' || r == '"':
			quote = r
			inTok = true
		case r == ' ' || r == '\t':
			if inTok {
				out = append(out, cur.String())
				cur.Reset()
				inTok = false
			}
		default:
			cur.WriteRune(r)
			inTok = true
		}
	}
	if inTok {
		out = append(out, cur.String())
	}
	return out
}

func splitList(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t'
	})
	var out []string
	for _, x := range f {
		x = strings.TrimSpace(x)
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

func atoiOr(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func pct(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) * 100.0 / float64(total)
}

func trimQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func rot13(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(b)
}

const b32alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

func base32Encode(data []byte) string {
	var sb strings.Builder
	var buf uint64
	var bits int
	for _, b := range data {
		buf = (buf << 8) | uint64(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			sb.WriteByte(b32alpha[(buf>>uint(bits))&0x1f])
		}
	}
	if bits > 0 {
		sb.WriteByte(b32alpha[(buf<<uint(5-bits))&0x1f])
	}
	for sb.Len()%8 != 0 {
		sb.WriteByte('=')
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
//  Generic directed graph with weighted BFS/Dijkstra shortest path.
//  Used by attack-path / reachability domains.
// ---------------------------------------------------------------------------

type GraphEdge struct {
	To     string
	Label  string
	Weight int
}

type Graph struct {
	Adj   map[string][]GraphEdge
	Nodes map[string]bool
}

func NewGraph() *Graph {
	return &Graph{Adj: map[string][]GraphEdge{}, Nodes: map[string]bool{}}
}

func (g *Graph) AddNode(n string) {
	if n == "" {
		return
	}
	g.Nodes[n] = true
	if _, ok := g.Adj[n]; !ok {
		g.Adj[n] = nil
	}
}

func (g *Graph) AddEdge(from, to, label string, weight int) {
	g.AddNode(from)
	g.AddNode(to)
	g.Adj[from] = append(g.Adj[from], GraphEdge{To: to, Label: label, Weight: weight})
}

// ShortestPath returns the min-weight path and total cost, or nil if none.
func (g *Graph) ShortestPath(src, dst string) ([]string, []string, int) {
	const inf = int(^uint(0) >> 1)
	dist := map[string]int{}
	prev := map[string]string{}
	prevLabel := map[string]string{}
	for n := range g.Nodes {
		dist[n] = inf
	}
	if _, ok := g.Nodes[src]; !ok {
		return nil, nil, -1
	}
	dist[src] = 0
	visited := map[string]bool{}
	for {
		u := ""
		best := inf
		for n, d := range dist {
			if !visited[n] && d < best {
				best = d
				u = n
			}
		}
		if u == "" {
			break
		}
		if u == dst {
			break
		}
		visited[u] = true
		for _, e := range g.Adj[u] {
			nd := dist[u] + e.Weight
			if nd < dist[e.To] {
				dist[e.To] = nd
				prev[e.To] = u
				prevLabel[e.To] = e.Label
			}
		}
	}
	if dist[dst] == inf {
		return nil, nil, -1
	}
	var path []string
	var labels []string
	cur := dst
	for cur != src {
		path = append([]string{cur}, path...)
		labels = append([]string{prevLabel[cur]}, labels...)
		p, ok := prev[cur]
		if !ok {
			return nil, nil, -1
		}
		cur = p
	}
	path = append([]string{src}, path...)
	return path, labels, dist[dst]
}

// ReachableFrom returns all nodes reachable from src (BFS).
func (g *Graph) ReachableFrom(src string) []string {
	seen := map[string]bool{src: true}
	queue := []string{src}
	var out []string
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		for _, e := range g.Adj[u] {
			if !seen[e.To] {
				seen[e.To] = true
				out = append(out, e.To)
				queue = append(queue, e.To)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
//  SID / RID helpers (Windows / AD domains)
// ---------------------------------------------------------------------------

// parseSIDString validates and splits an SDDL-style SID string.
func parseSIDString(s string) (parts []string, ok bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "S-") {
		return nil, false
	}
	parts = strings.Split(s, "-")
	if len(parts) < 3 {
		return nil, false
	}
	for i := 1; i < len(parts); i++ {
		if _, err := strconv.ParseUint(parts[i], 10, 64); err != nil {
			return nil, false
		}
	}
	return parts, true
}

func sidRID(s string) (uint64, bool) {
	parts, ok := parseSIDString(s)
	if !ok || len(parts) < 3 {
		return 0, false
	}
	n, err := strconv.ParseUint(parts[len(parts)-1], 10, 64)
	return n, err == nil
}

func wellKnownRID(rid uint64) string {
	switch rid {
	case 500:
		return "Administrator"
	case 501:
		return "Guest"
	case 502:
		return "KRBTGT"
	case 512:
		return "Domain Admins"
	case 513:
		return "Domain Users"
	case 514:
		return "Domain Guests"
	case 515:
		return "Domain Computers"
	case 516:
		return "Domain Controllers"
	case 518:
		return "Schema Admins"
	case 519:
		return "Enterprise Admins"
	case 520:
		return "Group Policy Creator Owners"
	case 544:
		return "Administrators (builtin)"
	case 545:
		return "Users (builtin)"
	case 546:
		return "Guests (builtin)"
	case 547:
		return "Power Users (builtin)"
	case 548:
		return "Account Operators"
	case 549:
		return "Server Operators"
	case 550:
		return "Print Operators"
	case 551:
		return "Backup Operators"
	case 552:
		return "Replicator"
	case 553:
		return "RAS and IAS Servers"
	case 554:
		return "Pre-Windows 2000 Compatible Access"
	case 555:
		return "Remote Desktop Users"
	case 556:
		return "Network Configuration Operators"
	case 557:
		return "Incoming Forest Trust Builders"
	case 558:
		return "Performance Monitor Users"
	case 559:
		return "Performance Log Users"
	case 560:
		return "Windows Authorization Access Group"
	case 561:
		return "Terminal Server License Servers"
	case 562:
		return "Distributed COM Users"
	case 568:
		return "IIS_IUSRS"
	case 569:
		return "Cryptographic Operators"
	case 573:
		return "Event Log Readers"
	case 574:
		return "Certificate Service DCOM Access"
	case 575:
		return "RDS Remote Access Servers"
	case 576:
		return "RDS Endpoint Servers"
	case 577:
		return "RDS Management Servers"
	case 578:
		return "Hyper-V Administrators"
	case 579:
		return "Access Control Assistance Operators"
	case 580:
		return "Remote Management Users"
	}
	return ""
}

func isPrivilegedRID(rid uint64) bool {
	switch rid {
	case 500, 512, 518, 519, 520, 544, 548, 549, 550, 551, 578:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
//  Hash format detectors (NTLM / Kerberos / Unix)
// ---------------------------------------------------------------------------

type hashKind struct {
	Name   string
	Mode   string // hashcat mode
	Sample string
	Re     *regexp.Regexp
}

var hashKinds = []hashKind{
	{"NTLM", "1000", "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", regexp.MustCompile(`(?i)^[0-9a-f]{32}:[0-9a-f]{32}$`)},
	{"NTLM-hash-only", "1000", "31d6cfe0d16ae931b73c59d7e0c089c0", regexp.MustCompile(`(?i)^[0-9a-f]{32}$`)},
	{"NetNTLMv1", "5500", "user::domain:LMRESP:NTRESP:challenge", regexp.MustCompile(`^[^:]+:[^:]*:[^:]*:[0-9a-fA-F]{48}:[0-9a-fA-F]{48}:[0-9a-fA-F]+$`)},
	{"NetNTLMv2", "5600", "user::domain:challenge:response:blob", regexp.MustCompile(`^[^:]+:[^:]*:[^:]*:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:.+`)},
	{"Kerberos-23-TGS", "13100", "$krb5tgs$23$*user$realm$spn*$checksum$edata", regexp.MustCompile(`(?i)^\$krb5tgs\$23\$`)},
	{"Kerberos-18-TGS", "19700", "$krb5tgs$18$user$realm$*spn*$checksum$edata", regexp.MustCompile(`(?i)^\$krb5tgs\$18\$`)},
	{"Kerberos-17-TGS", "19600", "$krb5tgs$17$user$realm$*spn*$checksum$edata", regexp.MustCompile(`(?i)^\$krb5tgs\$17\$`)},
	{"Kerberos-23-ASREP", "18200", "$krb5asrep$23$user@realm$hash", regexp.MustCompile(`(?i)^\$krb5asrep\$23\$`)},
	{"Kerberos-18-ASREP", "19800", "$krb5asrep$18$user@realm$hash", regexp.MustCompile(`(?i)^\$krb5asrep\$18\$`)},
	{"md5crypt", "500", "$1$salt$hash", regexp.MustCompile(`^\$1\$[^$]+\$[./0-9A-Za-z]{22}$`)},
	{"sha256crypt", "7400", "$5$salt$hash", regexp.MustCompile(`^\$5\$(rounds=\d+\$)?[^$]+\$[./0-9A-Za-z]{43}$`)},
	{"sha512crypt", "1800", "$6$salt$hash", regexp.MustCompile(`^\$6\$(rounds=\d+\$)?[^$]+\$[./0-9A-Za-z]{86}$`)},
	{"bcrypt", "3200", "$2y$10$...", regexp.MustCompile(`^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$`)},
	{"yescrypt", "n/a", "$y$j9T$...", regexp.MustCompile(`^\$y\$`)},
	{"LM", "3000", "aad3b435b51404eeaad3b435b51404ee", regexp.MustCompile(`(?i)^[0-9a-f]{32}$`)},
	{"mscash2", "2100", "$DCC2$10240#user#hash", regexp.MustCompile(`(?i)^\$DCC2\$\d+#.+#[0-9a-f]{32}$`)},
	{"krb5pa-23", "7500", "$krb5pa$23$user$realm$salt$hash", regexp.MustCompile(`(?i)^\$krb5pa\$23\$`)},
	{"krb5pa-18", "19900", "$krb5pa$18$user$realm$salt$hash", regexp.MustCompile(`(?i)^\$krb5pa\$18\$`)},
}

func detectHash(line string) *hashKind {
	line = strings.TrimSpace(line)
	for i := range hashKinds {
		if hashKinds[i].Re.MatchString(line) {
			return &hashKinds[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
//  Minimal LDIF parser (shared by AD/LDAP tools)
// ---------------------------------------------------------------------------

type LDIFEntry struct {
	DN     string
	Attrs  map[string][]string
	Object string // first objectClass
}

func parseLDIF(text string) []LDIFEntry {
	var out []LDIFEntry
	var cur *LDIFEntry
	flush := func() {
		if cur != nil && cur.DN != "" {
			out = append(out, *cur)
		}
		cur = nil
	}
	lines := strings.Split(text, "\n")
	var cont string
	for _, raw := range lines {
		if strings.HasPrefix(raw, " ") && cont != "" {
			cont += strings.TrimPrefix(raw, " ")
			continue
		}
		if cont != "" {
			applyLDIFLine(&cur, cont)
			cont = ""
		}
		if strings.TrimSpace(raw) == "" {
			flush()
			continue
		}
		if strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "version:") {
			continue
		}
		cont = strings.TrimRight(raw, "\r")
	}
	if cont != "" {
		applyLDIFLine(&cur, cont)
	}
	flush()
	return out
}

func applyLDIFLine(cur **LDIFEntry, line string) {
	if strings.HasPrefix(line, "dn:") {
		if *cur == nil {
			*cur = &LDIFEntry{Attrs: map[string][]string{}}
		}
		(*cur).DN = strings.TrimSpace(strings.TrimPrefix(line, "dn:"))
		if strings.HasPrefix((*cur).DN, ":") { // base64 dn
			(*cur).DN = strings.TrimSpace(strings.TrimPrefix((*cur).DN, ":"))
			if d, err := base64.StdEncoding.DecodeString((*cur).DN); err == nil {
				(*cur).DN = string(d)
			}
		}
		return
	}
	if *cur == nil {
		*cur = &LDIFEntry{Attrs: map[string][]string{}}
	}
	i := strings.Index(line, ":")
	if i < 0 {
		return
	}
	attr := strings.TrimSpace(line[:i])
	val := strings.TrimSpace(line[i+1:])
	if strings.HasPrefix(val, ":") { // base64
		val = strings.TrimSpace(strings.TrimPrefix(val, ":"))
		if d, err := base64.StdEncoding.DecodeString(val); err == nil {
			val = string(d)
		}
	} else if strings.HasPrefix(val, "<") {
		// URL reference; keep as-is
	}
	(*cur).Attrs[attr] = append((*cur).Attrs[attr], val)
	if strings.EqualFold(attr, "objectClass") && (*cur).Object == "" {
		(*cur).Object = val
	}
}

func (e LDIFEntry) HasClass(c string) bool {
	for _, v := range e.Attrs["objectClass"] {
		if strings.EqualFold(v, c) {
			return true
		}
	}
	return false
}

func (e LDIFEntry) Attr(name string) string {
	vs := e.Attrs[name]
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}

// ---------------------------------------------------------------------------
//  CSV helpers
// ---------------------------------------------------------------------------

func parseCSVText(text string) (headers []string, rows [][]string, err error) {
	r := csv.NewReader(strings.NewReader(text))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	all, err := r.ReadAll()
	if err != nil {
		return nil, nil, err
	}
	if len(all) == 0 {
		return nil, nil, nil
	}
	return all[0], all[1:], nil
}

func rowMap(headers, row []string) map[string]string {
	m := map[string]string{}
	for i, h := range headers {
		if i < len(row) {
			m[h] = row[i]
		}
	}
	return m
}

// ---------------------------------------------------------------------------
//  Score helpers used by graders
// ---------------------------------------------------------------------------

func riskBucket(score int) string {
	switch {
	case score >= 100:
		return "CRITICAL"
	case score >= 60:
		return "HIGH"
	case score >= 30:
		return "MEDIUM"
	case score >= 10:
		return "LOW"
	default:
		return "INFO"
	}
}

func combineGrades(gs ...string) string {
	worst := "A+"
	order := map[string]int{"A+": 0, "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6}
	for _, g := range gs {
		if order[g] > order[worst] {
			worst = g
		}
	}
	return worst
}

// ============================================================================
//  DOMAIN ENGINE — OTokenX : Windows Access-Token / Privilege Analyzer
//  Offline analysis of token dumps, privilege lists, impersonation paths,
//  SID history, and delegation. MITRE T1134
// ============================================================================

var MITRE_PRIMARY = "T1134"
var MITRE_TAGS = []string{"T1134", "T1134.001", "T1134.002", "T1134.003", "T1134.005", "T1134.004", "TA0004", "TA0005"}

func domainSummary() string {
	return "OTokenX is an offline Windows access-token and privilege-model analyzer for " +
		"AUTHORIZED assessments. It parses token dumps / whoami / privilege inventories, " +
		"maps dangerous privileges (SeDebug, SeImpersonate, SeAssignPrimaryToken, …), " +
		"flags impersonation/delegation levels, SID history injection indicators, and " +
		"plans privilege-abuse paths for lab reporting. It does not call OpenProcessToken " +
		"on live systems — bring exported token/privilege data."
}

// ---------------------------------------------------------------------------
//  Privilege catalog
// ---------------------------------------------------------------------------

type privInfo struct {
	Name       string
	Alias      string
	Severity   string
	Abuse      string
	Mitigation string
	Mitre      []string
}

var privilegeCatalog = []privInfo{
	{"SeDebugPrivilege", "Debug programs", SevCrit,
		"Read/write any process memory; inject; dump LSASS; bypass many controls.",
		"Remove from non-Tier0; monitor privilege use (4673/4674).",
		[]string{"T1134", "T1003"}},
	{"SeImpersonatePrivilege", "Impersonate a client after authentication", SevCrit,
		"Potato-family / RogueWinRM / print-spooler impersonation to SYSTEM.",
		"Remove from service accounts that do not need it; harden Print Spooler.",
		[]string{"T1134.001", "T1134.003"}},
	{"SeAssignPrimaryTokenPrivilege", "Replace a process-level token", SevCrit,
		"Assign stolen primary token to child process (parent of Potato variants).",
		"Restrict to Local System / essential services only.",
		[]string{"T1134.002"}},
	{"SeTcbPrivilege", "Act as part of the operating system", SevCrit,
		"Create tokens for arbitrary users; nearly equivalent to SYSTEM.",
		"Never grant to non-system principals.",
		[]string{"T1134", "TA0004"}},
	{"SeLoadDriverPrivilege", "Load and unload device drivers", SevHigh,
		"Load vulnerable/unsigned drivers for kernel exploit / BYOVD.",
		"Restrict; enable HVCI/code integrity; monitor 1125/driver loads.",
		[]string{"T1547.006", "T1068"}},
	{"SeBackupPrivilege", "Back up files and directories", SevHigh,
		"Read any file ignoring ACL (copy SAM/SECURITY/SYSTEM hives).",
		"Limit membership; audit use; prefer dedicated backup agents.",
		[]string{"T1003.002", "T1003"}},
	{"SeRestorePrivilege", "Restore files and directories", SevHigh,
		"Write any file ignoring ACL; plant service binaries / DLL hijacks.",
		"Limit membership; audit; protect service paths.",
		[]string{"T1049", "TA0004"}},
	{"SeTakeOwnershipPrivilege", "Take ownership of files or other objects", SevHigh,
		"Take ownership then rewrite DACL on sensitive objects.",
		"Restrict; audit 4670/4674.",
		[]string{"T1134", "TA0004"}},
	{"SeCreateTokenPrivilege", "Create a token object", SevCrit,
		"Mint arbitrary tokens (rare; extremely powerful).",
		"Should only exist on SYSTEM context.",
		[]string{"T1134"}},
	{"SeSecurityPrivilege", "Manage auditing and security log", SevMed,
		"Clear/alter audit policy; cover tracks.",
		"Restrict; monitor audit policy changes 4719.",
		[]string{"T1562.002", "TA0005"}},
	{"SeSystemEnvironmentPrivilege", "Modify firmware environment values", SevHigh,
		"Tamper with firmware/boot vars (Secure Boot etc.).",
		"Restrict; enable Secure Boot + measured boot.",
		[]string{"T1542"}},
	{"SeManageVolumePrivilege", "Perform volume maintenance tasks", SevMed,
		"Volume access that can expose raw disk data.",
		"Limit to storage admins.",
		[]string{"T1006"}},
	{"SeRelabelPrivilege", "Modify an object label", SevMed,
		"Change integrity labels (MIC) on objects.",
		"Rarely needed outside system components.",
		[]string{"T1134"}},
	{"SeDelegateSessionUserImpersonatePrivilege", "Obtain impersonation token for other session users", SevHigh,
		"Cross-session impersonation on RDS/terminal servers.",
		"Restrict on shared session hosts.",
		[]string{"T1134.001"}},
	{"SeEnableDelegationPrivilege", "Enable computer and user accounts to be trusted for delegation", SevHigh,
		"Configure unconstrained/constrained delegation on accounts.",
		"Tier 0 only; monitor directory changes.",
		[]string{"T1134", "T1558"}},
	{"SeTrustedCredManAccessPrivilege", "Access Credential Manager as trusted caller", SevHigh,
		"Read Credential Manager vault secrets.",
		"Extremely rare; investigate any grant.",
		[]string{"T1555.004"}},
	{"SeCreatePermanentPrivilege", "Create permanent shared objects", SevLow,
		"Create permanent kernel objects.",
		"Normally system-only.",
		[]string{"T1134"}},
	{"SeIncreaseQuotaPrivilege", "Adjust memory quotas for a process", SevLow,
		"Generally low abuse value alone.",
		"Default for some service accounts.",
		[]string{"T1134"}},
	{"SeChangeNotifyPrivilege", "Bypass traverse checking", SevInfo,
		"Default for Users; rarely an issue alone.",
		"Normal.",
		[]string{"T1134"}},
	{"SeShutdownPrivilege", "Shut down the system", SevLow,
		"DoS via shutdown/reboot.",
		"Limit on servers.",
		[]string{"T1529"}},
	{"SeRemoteShutdownPrivilege", "Force shutdown from a remote system", SevMed,
		"Remote DoS.",
		"Limit.",
		[]string{"T1529"}},
	{"SeAuditPrivilege", "Generate security audits", SevLow,
		"Write security log events.",
		"Normal for some services.",
		[]string{"T1134"}},
	{"SeIncreaseBasePriorityPrivilege", "Increase scheduling priority", SevLow,
		"Priority manipulation.",
		"Usually benign.",
		[]string{"T1134"}},
	{"SeCreatePagefilePrivilege", "Create a pagefile", SevLow,
		"Pagefile control.",
		"Admin-only.",
		[]string{"T1134"}},
	{"SeCreateGlobalPrivilege", "Create global objects", SevLow,
		"Create Global\\ namespace objects (some sandbox escapes historically).",
		"Default for SERVICES.",
		[]string{"T1134"}},
	{"SeTimeZonePrivilege", "Change the time zone", SevInfo,
		"Low impact.",
		"Normal for users.",
		[]string{"T1134"}},
	{"SeSystemTimePrivilege", "Change the system time", SevMed,
		"Time skew for auth bypass / log confusion.",
		"Restrict on DCs.",
		[]string{"T1134"}},
	{"SeProfileSingleProcessPrivilege", "Profile single process", SevLow,
		"Performance profiling.",
		"Usually fine.",
		[]string{"T1134"}},
	{"SeSystemProfilePrivilege", "Profile system performance", SevLow,
		"System profiling.",
		"Usually fine.",
		[]string{"T1134"}},
	{"SeUndockPrivilege", "Remove computer from docking station", SevInfo,
		"Physical undock.",
		"Irrelevant on servers.",
		[]string{"T1134"}},
}

var privByName map[string]privInfo

func init() {
	privByName = map[string]privInfo{}
	for _, p := range privilegeCatalog {
		privByName[strings.ToLower(p.Name)] = p
		privByName[strings.ToLower(p.Alias)] = p
	}
}

func lookupPriv(name string) (privInfo, bool) {
	p, ok := privByName[strings.ToLower(strings.TrimSpace(name))]
	return p, ok
}

// ---------------------------------------------------------------------------
//  Token model
// ---------------------------------------------------------------------------

type tokenPriv struct {
	Name    string
	Enabled bool
	Default bool
}

type tokenDump struct {
	User           string
	Integrity      string // Low/Medium/High/System
	Elevation      string // Limited/Full/Default
	AuthID         string
	SessionID      int
	TokenType      string // Primary / Impersonation
	Impersonation  string // Anonymous/Identification/Impersonation/Delegation
	Groups         []string
	Privileges     []tokenPriv
	SIDHistory     []string
	RestrictedSids []string
	AppContainer   bool
	UIAccess       bool
	Virtualized    bool
	Source         string
	Extra          map[string]string
}

type tokenReport struct {
	Tokens []tokenDump
}

// impersonation level rank
func impLevelRank(s string) int {
	switch strings.ToLower(s) {
	case "delegation":
		return 4
	case "impersonation":
		return 3
	case "identification":
		return 2
	case "anonymous":
		return 1
	}
	return 0
}

func integrityRank(s string) int {
	switch strings.ToLower(s) {
	case "system":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low", "untrusted":
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
//  Parsers
// ---------------------------------------------------------------------------

func parseTokenJSON(text string) (*tokenReport, error) {
	rep := &tokenReport{}
	var wrap struct {
		Tokens []tokenDump `json:"tokens"`
	}
	if json.Unmarshal([]byte(text), &wrap) == nil && len(wrap.Tokens) > 0 {
		rep.Tokens = wrap.Tokens
		return rep, nil
	}
	var one tokenDump
	if json.Unmarshal([]byte(text), &one) == nil && (one.User != "" || len(one.Privileges) > 0) {
		rep.Tokens = []tokenDump{one}
		return rep, nil
	}
	var arr []tokenDump
	if json.Unmarshal([]byte(text), &arr) == nil && len(arr) > 0 {
		rep.Tokens = arr
		return rep, nil
	}
	return nil, fmt.Errorf("json not recognized as token dump")
}

func parseTokenText(text string) *tokenReport {
	rep := &tokenReport{}
	cur := tokenDump{Extra: map[string]string{}, Privileges: nil, Groups: nil}
	flush := func() {
		if cur.User != "" || len(cur.Privileges) > 0 || len(cur.Groups) > 0 {
			rep.Tokens = append(rep.Tokens, cur)
		}
		cur = tokenDump{Extra: map[string]string{}}
	}
	rePriv := regexp.MustCompile(`(?i)^\s*(Se\w+Privilege)\s+(Enabled|Disabled|Enabled by default|Disabled by default|On|Off)`)
	rePriv2 := regexp.MustCompile(`(?i)Privilege Name:\s*(Se\w+Privilege).*State:\s*(\w+)`)
	reUser := regexp.MustCompile(`(?i)(?:User Name|Username|USER)\s*[:=]\s*(.+)$`)
	reIL := regexp.MustCompile(`(?i)(?:Mandatory Label|Integrity(?:\s*Level)?)\s*[:=]\s*(System|High|Medium|Low|Untrusted)`)
	reElev := regexp.MustCompile(`(?i)Elevated\s*[:=]\s*(True|False|Yes|No|Limited|Full)`)
	reImp := regexp.MustCompile(`(?i)Impersonation\s*Level\s*[:=]\s*(Anonymous|Identification|Impersonation|Delegation)`)
	reType := regexp.MustCompile(`(?i)Token\s*Type\s*[:=]\s*(Primary|Impersonation)`)
	reGroup := regexp.MustCompile(`(?i)^\s*(?:GROUPINFO|Group)\s*[:=]?\s*(.+)$`)
	reSIDH := regexp.MustCompile(`(?i)SID\s*History\s*[:=]\s*(S-\d[-\d]+)`)
	reWhoamiPriv := regexp.MustCompile(`(?i)^(Se\w+Privilege)\s+(\w+(?:\s+\w+)*)`)

	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		if strings.HasPrefix(trim, "===") || strings.HasPrefix(trim, "---") {
			flush()
			continue
		}
		if m := reUser.FindStringSubmatch(trim); len(m) > 1 {
			if cur.User != "" && (len(cur.Privileges) > 0 || len(cur.Groups) > 0) {
				flush()
			}
			cur.User = strings.TrimSpace(m[1])
			continue
		}
		if m := reIL.FindStringSubmatch(trim); len(m) > 1 {
			cur.Integrity = titleOf(strings.ToLower(m[1]))
			continue
		}
		if m := reElev.FindStringSubmatch(trim); len(m) > 1 {
			cur.Elevation = m[1]
			continue
		}
		if m := reImp.FindStringSubmatch(trim); len(m) > 1 {
			cur.Impersonation = m[1]
			continue
		}
		if m := reType.FindStringSubmatch(trim); len(m) > 1 {
			cur.TokenType = m[1]
			continue
		}
		if m := reSIDH.FindStringSubmatch(trim); len(m) > 1 {
			cur.SIDHistory = append(cur.SIDHistory, m[1])
			continue
		}
		if m := rePriv.FindStringSubmatch(trim); len(m) > 2 {
			en := contains(m[2], "enable") || strings.EqualFold(m[2], "on")
			cur.Privileges = append(cur.Privileges, tokenPriv{Name: m[1], Enabled: en})
			continue
		}
		if m := rePriv2.FindStringSubmatch(trim); len(m) > 2 {
			en := contains(m[2], "enable") || strings.EqualFold(m[2], "on")
			cur.Privileges = append(cur.Privileges, tokenPriv{Name: m[1], Enabled: en})
			continue
		}
		if m := reWhoamiPriv.FindStringSubmatch(trim); len(m) > 2 && strings.HasPrefix(m[1], "Se") {
			en := contains(m[2], "Enabled")
			cur.Privileges = append(cur.Privileges, tokenPriv{Name: m[1], Enabled: en})
			continue
		}
		if m := reGroup.FindStringSubmatch(trim); len(m) > 1 {
			g := strings.TrimSpace(m[1])
			if g != "" && !strings.HasPrefix(strings.ToLower(g), "group name") {
				cur.Groups = append(cur.Groups, g)
			}
			continue
		}
		// whoami /groups style: GROUP\Name  Type  SID  Attributes
		if strings.Contains(trim, "\\") && (strings.Contains(trim, "S-1-") || strings.Contains(strings.ToLower(trim), "group")) {
			parts := strings.Fields(trim)
			if len(parts) >= 1 && strings.Contains(parts[0], "\\") {
				cur.Groups = append(cur.Groups, parts[0])
			}
		}
	}
	flush()
	return rep
}

func parseTokenExport(text string) (*tokenReport, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return &tokenReport{}, nil
	}
	if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
		if r, err := parseTokenJSON(text); err == nil {
			return r, nil
		}
	}
	return parseTokenText(text), nil
}

// ---------------------------------------------------------------------------
//  Analysis
// ---------------------------------------------------------------------------

func analyzeTokens(rep *tokenReport, target string) AnalysisResult {
	res := AnalysisResult{Target: target, Tool: APPNAME, Stats: map[string]string{}}
	var findings []Finding
	n := 0
	dangerEnabled := 0
	impTokens := 0
	sidHist := 0
	highIL := 0

	for ti, t := range rep.Tokens {
		label := nz(t.User, fmt.Sprintf("token-%d", ti+1))

		if integrityRank(t.Integrity) >= 3 {
			highIL++
		}
		if impLevelRank(t.Impersonation) >= 3 {
			impTokens++
			n++
			sev := SevHigh
			if impLevelRank(t.Impersonation) >= 4 {
				sev = SevCrit
			}
			findings = append(findings, Finding{
				ID:       fmt.Sprintf("TOK-IMP-%03d", n),
				Title:    fmt.Sprintf("Impersonation level %s: %s", t.Impersonation, label),
				Severity: sev, Category: "impersonation",
				Detail:      "Token can be used for impersonation/delegation-style lateral abuse.",
				Evidence:    "type=" + t.TokenType + " level=" + t.Impersonation,
				Remediation: "Avoid Delegation-level network auth where possible; use Protected Users; disable unconstrained delegation.",
				Mitre:       []string{"T1134.001", "T1134.003"}, Score: sevWeight(sev),
			})
		}
		for _, sid := range t.SIDHistory {
			sidHist++
			n++
			sev := SevHigh
			if isPrivilegedRID(mustRID(sid)) {
				sev = SevCrit
			}
			findings = append(findings, Finding{
				ID:       fmt.Sprintf("TOK-SIDH-%03d", n),
				Title:    "SID History present: " + label + " → " + sid,
				Severity: sev, Category: "sid-history",
				Detail:      "SID history can carry privileged SIDs across trusts (T1134.005).",
				Evidence:    sid + " " + wellKnownRID(mustRID(sid)),
				Remediation: "Audit sidHistory attributes; remove unnecessary history; monitor trust attacks.",
				Mitre:       []string{"T1134.005"}, Score: sevWeight(sev),
			})
		}
		for _, tp := range t.Privileges {
			info, ok := lookupPriv(tp.Name)
			if !ok {
				continue
			}
			if !tp.Enabled && sevRank(info.Severity) < sevRank(SevHigh) {
				continue
			}
			sev := info.Severity
			if !tp.Enabled {
				// present but disabled still matters for SeDebug etc.
				if sevRank(sev) >= sevRank(SevHigh) {
					sev = SevMed
				} else {
					continue
				}
			} else {
				dangerEnabled++
			}
			n++
			state := "disabled"
			if tp.Enabled {
				state = "ENABLED"
			}
			findings = append(findings, Finding{
				ID:       fmt.Sprintf("TOK-PRIV-%03d", n),
				Title:    fmt.Sprintf("%s %s on %s", tp.Name, state, label),
				Severity: sev, Category: "privilege",
				Detail:      info.Abuse,
				Evidence:    info.Alias + " | integrity=" + nz(t.Integrity, "?"),
				Remediation: info.Mitigation,
				Mitre:       info.Mitre, Score: sevWeight(sev),
			})
		}
		// group-based hints
		for _, g := range t.Groups {
			gu := strings.ToUpper(g)
			if strings.Contains(gu, "ADMINISTRATORS") || strings.Contains(gu, "DOMAIN ADMINS") ||
				strings.Contains(gu, "ENTERPRISE ADMINS") || strings.Contains(gu, "BACKUP OPERATORS") {
				n++
				findings = append(findings, Finding{
					ID:       fmt.Sprintf("TOK-GRP-%03d", n),
					Title:    "Privileged group in token: " + g,
					Severity: SevHigh, Category: "group",
					Detail:      "Token carries privileged group SID — full admin capability if enabled.",
					Evidence:    label + " / " + g,
					Remediation: "Use filtered admin tokens / UAC; prefer just-enough-admin; PAW.",
					Mitre:       []string{"T1134", "T1078"}, Score: sevWeight(SevHigh),
				})
			}
		}
		// integrity vs elevation mismatch notes
		if strings.EqualFold(t.Integrity, "medium") && contains(t.Elevation, "true") {
			n++
			findings = append(findings, Finding{
				ID:       fmt.Sprintf("TOK-UAC-%03d", n),
				Title:    "Unusual elevation marker at Medium IL: " + label,
				Severity: SevLow, Category: "uac",
				Detail: "Review UAC filtering — may indicate split token quirks.",
				Mitre:  []string{"T1134", "T1548.002"}, Score: sevWeight(SevLow),
			})
		}
	}

	// Potato path planner summary
	hasImp := false
	hasAssign := false
	for _, t := range rep.Tokens {
		for _, tp := range t.Privileges {
			if strings.EqualFold(tp.Name, "SeImpersonatePrivilege") && tp.Enabled {
				hasImp = true
			}
			if strings.EqualFold(tp.Name, "SeAssignPrimaryTokenPrivilege") && tp.Enabled {
				hasAssign = true
			}
		}
	}
	if hasImp || hasAssign {
		n++
		findings = append(findings, Finding{
			ID: "TOK-PATH-POTATO", Title: "Impersonation privilege abuse path available (Potato-class)",
			Severity: SevCrit, Category: "abuse-path",
			Detail:      fmt.Sprintf("SeImpersonate=%v SeAssignPrimaryToken=%v — lab path: coerce auth → impersonate → SYSTEM.", hasImp, hasAssign),
			Evidence:    "privilege inventory",
			Remediation: "Remove SeImpersonate from service accounts; disable unnecessary spooler/HTTP.sys listeners; use gMSA.",
			Mitre:       []string{"T1134.001", "T1134.003", "TA0004"}, Score: sevWeight(SevCrit),
		})
	}

	if len(rep.Tokens) == 0 {
		findings = append(findings, Finding{
			ID: "TOK-EMPTY", Title: "No tokens parsed",
			Severity: SevInfo, Category: "parse",
			Detail: "Provide whoami /priv, token dump JSON, or privilege inventory.",
			Mitre:  []string{"T1134"}, Score: 1,
		})
	}

	res.Findings = findings
	res.Stats["tokens"] = strconv.Itoa(len(rep.Tokens))
	res.Stats["dangerous_privs_enabled"] = strconv.Itoa(dangerEnabled)
	res.Stats["impersonation_tokens"] = strconv.Itoa(impTokens)
	res.Stats["sid_history"] = strconv.Itoa(sidHist)
	res.Stats["high_integrity"] = strconv.Itoa(highIL)
	res.Grade = gradeFromFindings(findings)
	res.Notes = append(res.Notes, "Offline token/privilege analysis — no live OpenProcessToken calls.")
	res.Notes = append(res.Notes, "Abuse paths are planning notes for authorized labs only.")
	return res
}

func mustRID(sid string) uint64 {
	rid, _ := sidRID(sid)
	return rid
}

func domainAnalyze(path string) (AnalysisResult, error) {
	text, err := readFileString(path)
	if err != nil {
		return AnalysisResult{}, err
	}
	rep, err := parseTokenExport(text)
	if err != nil {
		return AnalysisResult{}, err
	}
	return analyzeTokens(rep, baseName(path)), nil
}

func domainDemoResult() AnalysisResult {
	demo := `{
  "tokens": [
    {
      "User": "CORP\\\\svc_web",
      "Integrity": "High",
      "Elevation": "Full",
      "TokenType": "Primary",
      "Impersonation": "Identification",
      "Groups": ["CORP\\\\IIS_USRS", "BUILTIN\\\\Users", "NT AUTHORITY\\\\SERVICE"],
      "Privileges": [
        {"Name": "SeImpersonatePrivilege", "Enabled": true},
        {"Name": "SeAssignPrimaryTokenPrivilege", "Enabled": false},
        {"Name": "SeChangeNotifyPrivilege", "Enabled": true},
        {"Name": "SeCreateGlobalPrivilege", "Enabled": true}
      ],
      "SIDHistory": []
    },
    {
      "User": "CORP\\\\jdoe",
      "Integrity": "Medium",
      "Elevation": "Limited",
      "TokenType": "Primary",
      "Impersonation": "Identification",
      "Groups": ["CORP\\\\Domain Users", "BUILTIN\\\\Users"],
      "Privileges": [
        {"Name": "SeChangeNotifyPrivilege", "Enabled": true},
        {"Name": "SeIncreaseWorkingSetPrivilege", "Enabled": true},
        {"Name": "SeShutdownPrivilege", "Enabled": true}
      ]
    },
    {
      "User": "CORP\\\\migrated_admin",
      "Integrity": "High",
      "Elevation": "Full",
      "TokenType": "Primary",
      "Impersonation": "Delegation",
      "Groups": ["CORP\\\\Domain Admins", "BUILTIN\\\\Administrators"],
      "Privileges": [
        {"Name": "SeDebugPrivilege", "Enabled": true},
        {"Name": "SeTcbPrivilege", "Enabled": false},
        {"Name": "SeBackupPrivilege", "Enabled": true},
        {"Name": "SeRestorePrivilege", "Enabled": true},
        {"Name": "SeTakeOwnershipPrivilege", "Enabled": true}
      ],
      "SIDHistory": ["S-1-5-21-999-888-777-512"]
    }
  ]
}`
	rep, _ := parseTokenExport(demo)
	res := analyzeTokens(rep, "demo-tokens")
	res.Notes = append(res.Notes, "Demo: svc_web with SeImpersonate (Potato path), migrated_admin with SeDebug+SID history+Delegation.")
	return res
}

func domainHowtoSteps() []string {
	return []string{
		"On an authorized host, collect token/privilege data: whoami /all, whoami /priv, or a token dumper export.",
		"Copy the text/JSON into the lab (no need for SYSTEM on the analysis workstation).",
		"Run OTokenX --input FILE to classify privileges, impersonation level, SID history.",
		"Review CRITICAL findings: SeDebug, SeImpersonate, SeAssignPrimaryToken, SeTcb, SID history.",
		"Use the abuse-path notes for lab reporting; remediate privilege grants on the source hosts.",
		"Export SARIF/MD into the engagement report.",
	}
}

func domainRequirements() []string {
	return []string{
		"Exported token/privilege inventory (whoami, accesschk, custom JSON).",
		"No live token APIs required by this analyzer.",
		"Written authorization for the assessed hosts/accounts.",
	}
}

func domainHowtoNotes() []Section {
	return []Section{
		{Title: "DANGEROUS PRIVILEGES", Lines: []string{
			"SeDebugPrivilege — process inject / LSASS dump",
			"SeImpersonatePrivilege — Potato-class → SYSTEM",
			"SeAssignPrimaryTokenPrivilege — token assign → SYSTEM",
			"SeTcbPrivilege — mint tokens",
			"SeLoadDriverPrivilege — BYOVD",
			"SeBackup/SeRestore — ACL bypass read/write",
			"SeCreateTokenPrivilege — arbitrary token creation",
		}},
		{Title: "IMPERSONATION LEVELS", Lines: []string{
			"Anonymous < Identification < Impersonation < Delegation",
			"Delegation enables remote multi-hop impersonation ( unconstrained risk ).",
		}},
		{Title: "SID HISTORY", Lines: []string{
			"T1134.005 — injected historical SIDs survive migration and can carry DA.",
			"Audit with ldap/AD tools; remove orphaned history.",
		}},
	}
}

func domainCatalogSections() []Section {
	var lines []string
	for _, p := range privilegeCatalog {
		lines = append(lines, fmt.Sprintf("%-42s [%s] %s", p.Name, p.Severity, p.Alias))
	}
	return []Section{
		{Title: "PRIVILEGE CATALOG", Lines: lines},
		{Title: "OPERATOR NOTES", Lines: []string{
			"Service accounts with SeImpersonate are the classic web→SYSTEM path.",
			"Filtered admin tokens (UAC) still carry privileged SIDs — linked tokens matter.",
			"Delegation-level tokens + unconstrained delegation = multi-hop nightmare.",
			"Correlate with OBloodMap HasSession edges for where tokens can be stolen.",
			"Never enable SeDebug on day-to-day admin accounts.",
		}},
	}
}

func domainMenuItems() []MenuItem {
	return []MenuItem{
		{Label: "Look up a privilege", Action: actionTokPriv},
		{Label: "List dangerous privileges", Action: actionTokDanger},
		{Label: "Impersonation level guide", Action: actionTokImp},
		{Label: "Potato-path checklist", Action: actionTokPotato},
	}
}

func actionTokPriv() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  PRIVILEGE LOOKUP", B+CY))
	fmt.Println()
	name := prompt("privilege name (e.g. SeDebugPrivilege)")
	if p, ok := lookupPriv(name); ok {
		okMsg(p.Name + " — " + p.Alias)
		fmt.Println("   " + col("severity : ", GY) + col(p.Severity, sevColor(p.Severity)))
		for _, ln := range wrap("abuse: "+p.Abuse, 60) {
			fmt.Println("   " + col(ln, W))
		}
		for _, ln := range wrap("fix: "+p.Mitigation, 60) {
			fmt.Println("   " + col(ln, GRN))
		}
		info("mitre: " + strings.Join(p.Mitre, ", "))
	} else {
		warnMsg("not in catalog")
	}
	pause()
}

func actionTokDanger() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  DANGEROUS PRIVILEGES", B+CY))
	fmt.Println()
	rows := [][]string{}
	for _, p := range privilegeCatalog {
		if sevRank(p.Severity) >= sevRank(SevHigh) {
			rows = append(rows, []string{p.Name, p.Severity, p.Alias})
		}
	}
	table([]string{"Privilege", "Sev", "Alias"}, rows)
	pause()
}

func actionTokImp() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  IMPERSONATION LEVELS", B+CY))
	fmt.Println()
	rows := [][]string{
		{"Anonymous", "1", "No identity"},
		{"Identification", "2", "Can get SIDs but not impersonate"},
		{"Impersonation", "3", "Local impersonation (Potato target)"},
		{"Delegation", "4", "Network multi-hop impersonation"},
	}
	table([]string{"Level", "Rank", "Meaning"}, rows)
	pause()
}

func actionTokPotato() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  POTATO-CLASS PATH (lab planning)", B+CY))
	fmt.Println()
	steps := []string{
		"1. Confirm SeImpersonatePrivilege (or SeAssignPrimaryToken) ENABLED on service account.",
		"2. Identify a coerce-able local auth path (HTTP.sys, print spooler, RPC, WinRM).",
		"3. In the LAB, capture a SYSTEM token via the chosen Potato variant.",
		"4. CreateProcessWithToken / StealToken → NT AUTHORITY\\SYSTEM shell.",
		"5. Report & remediate: remove privilege; lock down listeners; use gMSA.",
		"AUTHORIZED LAB ONLY — do not run coercion against production without written approval.",
	}
	for _, s := range steps {
		fmt.Println("   " + col(s, W))
	}
	pause()
}

// ---- OWL house help content + self-test ----
var owlHelpAbout = []string{
	"OTokenX analyses Windows access-token and privilege information collected offline — from a token dump, whoami /all output, or a JSON/CSV/LDIF export — and grades the privileges and group memberships for escalation risk.",
	"It flags dangerous privileges (SeDebugPrivilege, SeImpersonatePrivilege, SeBackupPrivilege and friends), maps findings to MITRE ATT&CK, and produces a graded report. It reads files only; it never touches a live system or calls any Windows API.",
}
var owlHelpFlow = []string{
	"Type the number of an option and press Enter. Start with [1] DEMO to see a synthetic walkthrough, or [2] Analyze to load a real export. [H] opens this help, [0] or q quits.",
	"Everything is also available from the command line: --input FILE --format txt|md|json|csv|sarif --output FILE. See page 2.",
}
var owlHelpMenu = []owlHelpItem{
	{"1", "Run DEMO: analyse a built-in synthetic token set so you can see the report format and grading."},
	{"2", "Analyze an input file: load a token dump / whoami / JSON / CSV / LDIF export and grade it."},
	{"3", "Reference catalog: the privileges and well-known SIDs OTokenX knows about and why they matter."},
	{"*", "Domain options: additional analysis actions the tool exposes for the loaded data."},
	{"*", "View / Export last result: review or write the most recent analysis as txt/md/json/csv/sarif."},
	{"*", "HOW TO USE / About: the usage screen and the MITRE ATT&CK mapping."},
}
var owlHelpTips = []owlHelpItem{
	{"*", "OTokenX is offline and read-only — collect a token dump on the target, then analyse it here."},
	{"*", "SeImpersonate/SeAssignPrimaryToken on a service account is the classic 'potato' escalation path — OTokenX flags it HIGH."},
	{"*", "Use --format sarif to feed results into code-scanning dashboards."},
	{"*", "Run --selftest (or build-in demo) to confirm the parser, grader and all five export formats."},
}

func runSelfTest() int {
	banner()
	header("Self-Test — parse / analyse / grade / export engines")
	pass, fail := 0, 0
	check := func(name string, cond bool) {
		if cond {
			pass++
			fmt.Println("  " + col("[✔] ", GRN) + col(name, W))
		} else {
			fail++
			fmt.Println("  " + col("[✘] ", R) + col(name, W))
		}
	}

	// Demo result pipeline.
	res := domainDemoResult()
	finalize(&res)
	check("demo result has findings", len(res.Findings) > 0)
	check("demo result graded", res.Grade != "")

	// Parse a synthetic whoami /all-style privilege block and grade it.
	sample := "SeDebugPrivilege                Debug programs                 Enabled\n" +
		"SeImpersonatePrivilege          Impersonate a client           Enabled\n" +
		"SeChangeNotifyPrivilege         Bypass traverse checking       Enabled\n"
	rep, err := parseTokenExport(sample)
	check("parseTokenExport parses privilege text", err == nil && rep != nil)
	if rep != nil {
		ar := analyzeTokens(rep, "selftest")
		finalize(&ar)
		check("analyze flags SeDebug/SeImpersonate", len(ar.Findings) > 0)
		hasHigh := false
		for _, f := range ar.Findings {
			if f.Severity == SevHigh || f.Severity == SevCrit {
				hasHigh = true
			}
		}
		check("dangerous privileges raise HIGH/CRITICAL", hasHigh)

		// Export round-trip through every format.
		check("exportTXT non-empty", len(exportTXT(&ar)) > 0)
		check("exportMD non-empty", len(exportMD(&ar)) > 0)
		check("exportCSV non-empty", len(exportCSV(&ar)) > 0)
		check("exportSARIF non-empty", len(exportSARIF(&ar)) > 0)
		js := exportJSON(&ar)
		var v interface{}
		check("exportJSON is valid JSON", json.Unmarshal([]byte(js), &v) == nil)
	}

	// Reference catalog present.
	check("reference catalog non-empty", len(domainCatalogSections()) > 0)

	fmt.Println()
	rule()
	if fail == 0 {
		okMsg(fmt.Sprintf("ALL %d CHECKS PASSED", pass))
		return 0
	}
	errMsg(fmt.Sprintf("%d passed, %d FAILED", pass, fail))
	return 1
}
