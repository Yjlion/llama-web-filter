package textextract

import (
	"strings"
	"testing"
)

func TestExtractPullsTitleMetaHeadingsTextAndImages(t *testing.T) {
	src := `<html><head><title> Hello   World </title><meta name="description" content="A test page"><style>.x{}</style></head>
<body><nav>Menu Menu</nav><h1>Heading One</h1><script>var evil = "ignored";</script><p>Visible <b>body</b> text.</p>
<img src="/a.jpg" alt="An alt"><img src="data:image/png;base64,xx"><footer>foot</footer></body></html>`
	p := Extract([]byte(src))
	if p.Title != "Hello World" || p.Description != "A test page" {
		t.Fatalf("title/desc = %q / %q", p.Title, p.Description)
	}
	if len(p.Headings) != 1 || p.Headings[0] != "Heading One" {
		t.Fatalf("headings = %v", p.Headings)
	}
	if strings.Contains(p.Text, "ignored") || strings.Contains(p.Text, "Menu") || strings.Contains(p.Text, "foot") || strings.Contains(p.Text, ".x{}") {
		t.Fatalf("text should skip script/style/nav/footer: %q", p.Text)
	}
	if !strings.Contains(p.Text, "Visible body text.") || !strings.Contains(p.Text, "An alt") {
		t.Fatalf("text missing visible content: %q", p.Text)
	}
	if len(p.ImageURLs) != 1 || p.ImageURLs[0] != "/a.jpg" {
		t.Fatalf("images = %v (data: URIs excluded)", p.ImageURLs)
	}
	if !strings.HasPrefix(p.Summary(), "A test page\nHeading One\n") {
		t.Fatalf("summary = %q", p.Summary())
	}
}

func TestExtractCapsText(t *testing.T) {
	src := "<p>" + strings.Repeat("word ", 5000) + "</p>"
	p := Extract([]byte(src))
	if len(p.Text) > MaxText {
		t.Fatalf("text len %d > %d", len(p.Text), MaxText)
	}
}
