package markdown_test

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// tagsIn returns the live markup in rendered output, which is what has to be
// judged. Text that was escaped is not markup and cannot do anything.
func tagsIn(rendered string) []string {
	return regexp.MustCompile(`<[^>]*>`).FindAllString(rendered, -1)
}

// dangerous is what must not survive rendering, whatever route it takes in.
//
// The check is deliberately crude and deliberately broad: nothing executable,
// nothing that fetches, and no attribute a browser will run. A subtle check
// here would be a second place to get the rules wrong.
var dangerous = []string{
	"<script", "javascript:", "onerror", "onload", "onclick", "onmouseover",
	"onfocus", "<iframe", "<object", "<embed", "<svg", "<img", "data:text/html",
	"vbscript:", "<style", "<link", "<meta", "<base", "srcdoc", "formaction",
}

// corpus is markup and markdown that has been used to get script past
// sanitizers, plus the shapes specific to markdown itself.
var corpus = []string{
	`<script>alert(1)</script>`,
	`<img src=x onerror=alert(1)>`,
	`<svg/onload=alert(1)>`,
	`<iframe src="javascript:alert(1)"></iframe>`,
	`<body onload=alert(1)>`,
	`<a href="javascript:alert(1)">click</a>`,
	`[click](javascript:alert(1))`,
	`[click](JaVaScRiPt:alert(1))`,
	`[click](java&#115;cript:alert(1))`,
	`[click](	javascript:alert(1))`,
	`[click](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)`,
	`![img](javascript:alert(1))`,
	`![img](https://evil.example/pixel.gif)`,
	`<a href="vbscript:msgbox(1)">x</a>`,
	`<div style="background:url(javascript:alert(1))">x</div>`,
	`<object data="data:text/html,<script>alert(1)</script>"></object>`,
	`<embed src="data:text/html,<script>alert(1)</script>">`,
	`<base href="https://evil.example/">`,
	`<meta http-equiv="refresh" content="0;url=javascript:alert(1)">`,
	`<link rel=stylesheet href="https://evil.example/x.css">`,
	`<form action="javascript:alert(1)"><button>go</button></form>`,
	`<button formaction="javascript:alert(1)">go</button>`,
	`<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"></iframe>`,
	"```<script>alert(1)</script>\ncode\n```",
	"```javascript:alert(1)\ncode\n```",
	"``` \"><script>alert(1)</script>\ncode\n```",
	`<p onmouseover="alert(1)">hover</p>`,
	`<a href="#" onclick="alert(1)">x</a>`,
	`<input type="text" onfocus="alert(1)" autofocus>`,
	`<style>@import 'https://evil.example/x.css';</style>`,
	`<!--<script>alert(1)</script>-->`,
	`<math><mtext><script>alert(1)</script></mtext></math>`,
	`<xmp><script>alert(1)</script></xmp>`,
	`<noscript><p title="</noscript><script>alert(1)</script>">`,
	`&lt;script&gt;alert(1)&lt;/script&gt;`,
	`<scr<script>ipt>alert(1)</scr</script>ipt>`,
	`<a href=" javascript:alert(1)">x</a>`,
	`<a href="jav&#x0A;ascript:alert(1)">x</a>`,
}

func TestNothingInTheCorpusSurvivesRendering(t *testing.T) {
	// Rendered text goes to the people who hold the most access here, so this
	// is the check that has to hold whatever else changes underneath it — a
	// different parser, a different sanitizer, a new extension.
	for _, payload := range corpus {
		rendered, err := markdown.Render(context.Background(), payload)
		if err != nil {
			// Refusing outright is a fine answer.
			continue
		}
		// Checked against the markup rather than the text. Escaped text is the
		// correct outcome and contains the same words — `&lt;svg/onload=…&gt;`
		// is a safe rendering of a dangerous input, and a check that could not
		// tell the two apart would fail on the thing working.
		for _, tag := range tagsIn(rendered) {
			lowered := strings.ToLower(tag)
			for _, forbidden := range dangerous {
				if strings.Contains(lowered, forbidden) {
					t.Errorf("%q survived rendering as %q (live markup %q contains %q)",
						payload, rendered, tag, forbidden)
				}
			}
		}
	}
}

func TestTheSameCorpusIsRefusedAtSubmission(t *testing.T) {
	// Enforced twice on purpose. Refusing at submission is what tells somebody
	// their text will not do what they meant; sanitizing at render is what
	// covers text stored before a rule existed. Neither replaces the other.
	//
	// Not everything in the corpus is refused — plain escaped text is fine,
	// and a bare fenced tag is downgraded rather than rejected — so this
	// checks the ones that carry an address or a tag.
	mustRefuse := []string{
		`<script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`[click](javascript:alert(1))`,
		`![img](https://evil.example/pixel.gif)`,
		`[click](data:text/html;base64,abcd)`,
		`<a href="vbscript:msgbox(1)">x</a>`,
	}
	for _, payload := range mustRefuse {
		if err := markdown.Check(payload); err == nil {
			t.Errorf("%q was accepted at submission", payload)
		}
	}
}

func TestOrdinaryTriageWritingIsAccepted(t *testing.T) {
	// The other direction, and the one that makes the refusals worth having.
	// A policy that refused real justifications would teach people to write
	// plain sentences with no evidence in them, which is worse than no policy.
	accepted := []string{
		"The parser is never reached: we only call `Encode`.",
		"See [the advisory](https://nvd.nist.gov/vuln/detail/CVE-2026-1) for detail.",
		"Mail [the maintainer](mailto:security@example.com) about it.",
		"```go\nfunc main() { fmt.Println(\"hi\") }\n```",
		"```\nplain block\n```",
		"| component | version |\n|---|---|\n| libfoo | 1.2.3 |",
		"- [x] checked with upstream\n- [ ] backport written",
		"Relative link to [another finding](/v1/findings/12).",
		"> Quoting the advisory:\n> not exploitable without the debug flag.",
		"A stack trace:\n\n    at parse (parser.go:112)\n    at main (main.go:9)",
	}
	for _, text := range accepted {
		if err := markdown.Check(text); err != nil {
			t.Errorf("ordinary writing was refused: %q\n  %v", text, err)
		}
		if _, err := markdown.Render(context.Background(), text); err != nil {
			t.Errorf("ordinary writing would not render: %q\n  %v", text, err)
		}
	}
}

func TestARefusalSaysWhereToLook(t *testing.T) {
	// A justification is forty lines and a refusal naming a category means
	// hunting. Somebody who cannot find what to fix rewrites the whole thing
	// or stops explaining themselves.
	err := markdown.Check("fine line\nanother fine line\nsee ![this](https://evil.example/x.png)")
	if err == nil {
		t.Fatal("a remote image was accepted")
	}
	faults, ok := err.(markdown.Faults)
	if !ok {
		t.Fatalf("a refusal came back as %T", err)
	}
	if len(faults) != 1 {
		t.Fatalf("reported %d faults, want 1: %v", len(faults), faults)
	}
	if faults[0].Line != 3 {
		t.Errorf("pointed at line %d, want 3", faults[0].Line)
	}
	if !strings.Contains(faults[0].Offending, "evil.example") {
		t.Errorf("did not quote what was wrong: %q", faults[0].Offending)
	}
}

func TestEverythingWrongIsReportedAtOnce(t *testing.T) {
	// Fixing one problem and resubmitting to find the next is how somebody
	// learns to write plain sentences with no evidence in them.
	err := markdown.Check("![a](https://evil.example/1.png)\n[b](javascript:alert(1))\n<script>x</script>")
	faults, ok := err.(markdown.Faults)
	if !ok {
		t.Fatalf("a refusal came back as %T", err)
	}
	if len(faults) < 3 {
		t.Errorf("reported %d of three problems: %v", len(faults), faults)
	}
}

func TestTextFromAScanFileIsNeverRendered(t *testing.T) {
	// Once a renderer exists, pointing it at a component description is the
	// obvious next step — and that hands whoever wrote the scan file a
	// formatting language aimed at the browsers of the people with the most
	// access here.
	fromAFile := `<script>alert(1)</script> **not bold**`
	shown := markdown.Escaped(fromAFile)
	if strings.Contains(shown, "<script") {
		t.Errorf("text from a scan file kept its markup: %q", shown)
	}
	if !strings.Contains(shown, "**not bold**") {
		t.Errorf("text from a scan file was interpreted rather than shown: %q", shown)
	}
}

func TestTextPastTheBoundIsRefused(t *testing.T) {
	// Rendering is work somebody else asked for, and what is stored is kept
	// forever.
	if err := markdown.Check(strings.Repeat("a", markdown.MaxBytes+1)); err == nil {
		t.Error("text past the bound was accepted")
	}
	if _, err := markdown.Render(context.Background(), strings.Repeat("a", markdown.MaxBytes+1)); err == nil {
		t.Error("text past the bound was rendered")
	}
}

func TestALegitimateLinkSurvivesWithItsAddress(t *testing.T) {
	// The other half of restricting schemes, and the half that is easy to lose
	// without noticing: a policy that strips every link is "safe" and useless.
	// An advisory link is the most common thing in a justification, and one
	// that silently became plain text would send people back to a search
	// engine — which is the whole problem the evidence is there to solve.
	rendered, err := markdown.Render(context.Background(),
		"See [the advisory](https://nvd.nist.gov/vuln/detail/CVE-2026-1).")
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{`<a`, `href=`, "nvd.nist.gov"} {
		if !strings.Contains(rendered, wanted) {
			t.Errorf("a legitimate link lost its %s: %q", wanted, rendered)
		}
	}
	// And it does not carry the reader's referrer or a live opener with it.
	for _, wanted := range []string{`rel=`, `nofollow`} {
		if !strings.Contains(rendered, wanted) {
			t.Errorf("an outbound link is unqualified: %q", rendered)
		}
	}

	// A mail link too, since that is the other scheme people actually use.
	rendered, err = markdown.Render(context.Background(), "Ask [security](mailto:security@example.com).")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered, "mailto:security@example.com") {
		t.Errorf("a mail link was stripped: %q", rendered)
	}
}

func TestAnUnknownLanguageLosesItsLabelAndKeepsItsBlock(t *testing.T) {
	// A fenced block's language tag is typed by a person and lands in a class
	// attribute, so it is input like any other. An unknown one loses the label
	// rather than being refused: making the tool argue with somebody about a
	// syntax-highlighting hint is not what it is for.
	//
	// Asserted through the renderer, which is where the rule is actually
	// enforced. Asking the allowlist directly proves the allowlist agrees with
	// itself.
	for _, tag := range []string{`"><script>`, "brainfuck", "go\" onload=\"alert(1)"} {
		markup, err := markdown.Render(t.Context(), "```"+tag+"\nx := 1\n```")
		if err != nil {
			t.Fatalf("render %q: %v", tag, err)
		}
		if strings.Contains(markup, "class=") {
			t.Errorf("an unrecognized language reached a class attribute: %s", markup)
		}
		if !strings.Contains(markup, "<code") {
			t.Errorf("the code block itself was lost: %s", markup)
		}
	}

	// A recognized one keeps its label, because that is what a client-side
	// highlighter reads.
	markup, err := markdown.Render(t.Context(), "```go\nx := 1\n```")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(markup, `class="language-go"`) {
		t.Errorf("a known language lost its label: %s", markup)
	}
}

func TestALinkInsideThisDeploymentSurvivesBeingRendered(t *testing.T) {
	// The submission check calls a relative destination ordinary and accepts
	// it — one finding referring to another. The sanitizer then deleted the
	// anchor and left the text, so a link accepted when it was written stopped
	// being a link when anybody read it. Two halves of one rule disagreeing is
	// worse than either answer, because nothing reports it.
	for _, source := range []string{
		"[see](../findings/3)", "[see](/v1/findings/3)", "[see](thing.md)",
	} {
		markup, err := markdown.Render(t.Context(), source)
		if err != nil {
			t.Fatalf("render %q: %v", source, err)
		}
		if !strings.Contains(markup, "href=") {
			t.Errorf("%q rendered as %q, losing the link", source, markup)
		}
	}
}

func TestALinkThatLeavesHereSaysSoAndCarriesNothing(t *testing.T) {
	// Opening in a new tab hands the opened page a reference back to ours
	// unless it is refused, and the address of the page somebody is reading is
	// itself worth not sending — a link in a comment on an undisclosed finding
	// would otherwise carry our internal address to whoever runs the site at
	// the other end.
	markup, err := markdown.Render(t.Context(), "[see](https://elsewhere.example/a)")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"noreferrer", "noopener", "nofollow"} {
		if !strings.Contains(markup, required) {
			t.Errorf("an outbound link is missing %q: %s", required, markup)
		}
	}
}
