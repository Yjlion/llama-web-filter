// Package textextract turns an HTML document into the few kilobytes the
// text classifier should read: title, description, headings and the first
// stretch of visible body text, with scripts, styles and markup removed.
package textextract

import (
	"bytes"
	"strings"
	"unicode"

	"golang.org/x/net/html"
)

// Page is the extracted content.
type Page struct {
	Title       string
	Description string
	Headings    []string
	Text        string
	// ImageURLs are the src attributes of <img> tags in document order,
	// unresolved, for speculative pre-scoring.
	ImageURLs []string
}

// MaxText caps Page.Text in bytes.
const MaxText = 3000

var skipElements = map[string]bool{
	"script": true, "style": true, "noscript": true, "template": true, "svg": true,
	"head": false, "nav": true, "footer": true, "iframe": true, "object": true,
}

// Extract parses src and returns its visible content. Parsing never fails:
// x/net/html is tolerant, and a document with no body yields empty fields.
func Extract(src []byte) Page {
	var p Page
	doc, err := html.Parse(bytes.NewReader(src))
	if err != nil {
		return p
	}
	var text strings.Builder
	var walk func(n *html.Node, skip bool)
	walk = func(n *html.Node, skip bool) {
		switch n.Type {
		case html.ElementNode:
			name := n.Data
			switch name {
			case "title":
				if p.Title == "" {
					p.Title = compact(textOf(n))
				}
				return
			case "meta":
				if strings.EqualFold(attr(n, "name"), "description") || strings.EqualFold(attr(n, "property"), "og:description") {
					if p.Description == "" {
						p.Description = compact(attr(n, "content"))
					}
				}
				return
			case "img":
				if src := strings.TrimSpace(attr(n, "src")); src != "" && !strings.HasPrefix(src, "data:") && len(p.ImageURLs) < 64 {
					p.ImageURLs = append(p.ImageURLs, src)
				}
				if alt := compact(attr(n, "alt")); alt != "" && text.Len() < MaxText {
					text.WriteString(alt)
					text.WriteByte(' ')
				}
				return
			case "h1", "h2", "h3":
				if h := compact(textOf(n)); h != "" && len(p.Headings) < 12 {
					p.Headings = append(p.Headings, h)
				}
			}
			if skipElements[name] {
				skip = true
			}
			if name == "br" || name == "p" || name == "div" || name == "li" || name == "tr" {
				text.WriteByte(' ')
			}
		case html.TextNode:
			if !skip && text.Len() < MaxText {
				text.WriteString(n.Data)
				text.WriteByte(' ')
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, skip)
		}
	}
	walk(doc, false)
	p.Text = compact(text.String())
	if len(p.Text) > MaxText {
		p.Text = p.Text[:MaxText]
	}
	return p
}

// Summary joins the parts into the string handed to the model.
func (p Page) Summary() string {
	var b strings.Builder
	if p.Description != "" {
		b.WriteString(p.Description)
		b.WriteString("\n")
	}
	if len(p.Headings) > 0 {
		b.WriteString(strings.Join(p.Headings, " | "))
		b.WriteString("\n")
	}
	b.WriteString(p.Text)
	return b.String()
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

func textOf(n *html.Node) string {
	var b strings.Builder
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
			b.WriteByte(' ')
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(n)
	return b.String()
}

// compact collapses whitespace runs to single spaces and trims.
func compact(s string) string {
	var b strings.Builder
	space := true
	for _, r := range s {
		if unicode.IsSpace(r) {
			if !space {
				b.WriteByte(' ')
				space = true
			}
			continue
		}
		b.WriteRune(r)
		space = false
	}
	return strings.TrimSpace(b.String())
}
