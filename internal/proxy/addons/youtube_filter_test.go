package addons_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
)

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal test fixture: %v", err)
	}
	return string(data)
}

func newYoutubeFlow(t *testing.T, path, contentType, body string) (*models.Policy, *proxy.FlowContext) {
	t.Helper()
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "https://www.youtube.com"+path)
	fc.Response = &http.Response{Header: http.Header{"Content-Type": []string{contentType}}}
	fc.ResponseBody = []byte(body)
	policy := models.NewPolicy()
	policy.YouTube = models.NewYouTubeConfig()
	policy.YouTube.Enabled = true
	fc.Policy = &policy
	return &policy, fc
}

func TestYouTubePlayerBlocksBlacklistedChannel(t *testing.T) {
	policy, fc := newYoutubeFlow(t, "/youtubei/v1/player", "application/json", `{
		"videoDetails": {"channelId": "UCabcdefghijklmnopqrstuv", "author": "BadChannel"},
		"streamingData": {"formats": []}
	}`)
	policy.YouTube.Mode = models.YouTubeModeBlacklist
	policy.YouTube.Channels = []string{"UCabcdefghijklmnopqrstuv"}

	addons.YouTubeFilter{}.HandleResponse(fc)

	body := string(fc.ResponseBody)
	if !strings.Contains(body, `"status":"ERROR"`) {
		t.Errorf("expected playabilityStatus ERROR, body = %s", body)
	}
	if strings.Contains(body, "streamingData") {
		t.Error("expected streamingData to be dropped")
	}
	if fc.WFAction != "blocked" || fc.WFComponent != "youtube" {
		t.Errorf("WFAction/WFComponent = %q/%q", fc.WFAction, fc.WFComponent)
	}
}

func TestYouTubePlayerAllowsUnlistedChannel(t *testing.T) {
	policy, fc := newYoutubeFlow(t, "/youtubei/v1/player", "application/json", `{
		"videoDetails": {"channelId": "UCzzzzzzzzzzzzzzzzzzzzzz", "author": "GoodChannel"},
		"streamingData": {"formats": []}
	}`)
	policy.YouTube.Mode = models.YouTubeModeBlacklist
	policy.YouTube.Channels = []string{"UCabcdefghijklmnopqrstuv"}

	original := string(fc.ResponseBody)
	addons.YouTubeFilter{}.HandleResponse(fc)

	if string(fc.ResponseBody) != original {
		t.Errorf("expected body unchanged for a non-blacklisted channel, got %s", fc.ResponseBody)
	}
}

func TestYouTubePlayerWhitelistBlocksUnlisted(t *testing.T) {
	policy, fc := newYoutubeFlow(t, "/youtubei/v1/player", "application/json", `{
		"videoDetails": {"channelId": "UCzzzzzzzzzzzzzzzzzzzzzz", "author": "RandomChannel"}
	}`)
	policy.YouTube.Mode = models.YouTubeModeWhitelist
	policy.YouTube.Channels = []string{"UCabcdefghijklmnopqrstuv"}

	addons.YouTubeFilter{}.HandleResponse(fc)

	if !strings.Contains(string(fc.ResponseBody), `"status":"ERROR"`) {
		t.Error("expected whitelist mode to block a channel not on the allow list")
	}
}

func TestYouTubeGetWatchArrayBlocksAndStripsComments(t *testing.T) {
	getWatchBody := mustMarshal(t, []map[string]any{
		{"playerResponse": map[string]any{
			"videoDetails": map[string]any{"channelId": "UCabcdefghijklmnopqrstuv", "author": "BadChannel"},
		}},
		{"watchNextResponse": map[string]any{
			"contents": map[string]any{
				"twoColumnWatchNextResults": map[string]any{
					"results": map[string]any{
						"results": map[string]any{
							"contents": []map[string]any{
								{"itemSectionRenderer": map[string]any{"sectionIdentifier": "comment-item-section"}},
								{"itemSectionRenderer": map[string]any{"sectionIdentifier": "other-section"}},
							},
						},
					},
					"secondaryResults": map[string]any{"x": 1},
				},
			},
		}},
	})
	policy, fc := newYoutubeFlow(t, "/youtubei/v1/get_watch", "application/json", getWatchBody)
	policy.YouTube.Mode = models.YouTubeModeBlacklist
	policy.YouTube.Channels = []string{"UCabcdefghijklmnopqrstuv"}
	policy.YouTube.RemoveComments = true
	policy.YouTube.RemoveRecommendations = true

	addons.YouTubeFilter{}.HandleResponse(fc)

	body := string(fc.ResponseBody)
	if !strings.Contains(body, `"status":"ERROR"`) {
		t.Errorf("expected player response to be blocked, body = %s", body)
	}
	if strings.Contains(body, "comment-item-section") {
		t.Error("expected comments section to be stripped")
	}
	if strings.Contains(body, "secondaryResults") {
		t.Error("expected sidebar to be stripped")
	}
	if !strings.Contains(body, "other-section") {
		t.Error("expected non-comment sections to be preserved")
	}
}

func TestYouTubeNextStripsCommentsOnly(t *testing.T) {
	policy, fc := newYoutubeFlow(t, "/youtubei/v1/next", "application/json", `{
		"contents": {"twoColumnWatchNextResults": {"results": {"results": {"contents": [
			{"itemSectionRenderer": {"sectionIdentifier": "comments-entry-point"}},
			{"itemSectionRenderer": {"sectionIdentifier": "other"}}
		]}}, "secondaryResults": {"x": 1}}}
	}`)
	policy.YouTube.RemoveComments = true
	policy.YouTube.RemoveRecommendations = false

	addons.YouTubeFilter{}.HandleResponse(fc)

	body := string(fc.ResponseBody)
	if strings.Contains(body, "comments-entry-point") {
		t.Error("expected comments to be stripped")
	}
	if !strings.Contains(body, "secondaryResults") {
		t.Error("did not expect sidebar to be stripped when remove_recommendations is false")
	}
}

func TestYouTubeNextStripsCommentContinuation(t *testing.T) {
	policy, fc := newYoutubeFlow(t, "/youtubei/v1/next", "application/json", `{
		"responseContext": {},
		"onResponseReceivedEndpoints": [
			{"reloadContinuationItemsCommand": {
				"targetId": "comments-section",
				"continuationItems": [
					{"commentsHeaderRenderer": {"countText": {"simpleText": "184 Comments"}}}
				]
			}},
			{"reloadContinuationItemsCommand": {
				"targetId": "watch-next-feed",
				"continuationItems": [
					{"compactVideoRenderer": {"videoId": "abc"}}
				]
			}}
		]
	}`)
	policy.YouTube.RemoveComments = true
	policy.YouTube.RemoveRecommendations = false

	addons.YouTubeFilter{}.HandleResponse(fc)

	body := string(fc.ResponseBody)
	if strings.Contains(body, "comments-section") || strings.Contains(body, "commentsHeaderRenderer") {
		t.Errorf("expected comments continuation to be stripped, body = %s", body)
	}
	if !strings.Contains(body, "watch-next-feed") || !strings.Contains(body, "compactVideoRenderer") {
		t.Errorf("expected non-comment continuation to be preserved, body = %s", body)
	}
}

func TestYouTubeWatchHTMLStripsInitialCommentsAndSidebar(t *testing.T) {
	initialData := mustMarshal(t, map[string]any{
		"contents": map[string]any{
			"twoColumnWatchNextResults": map[string]any{
				"results": map[string]any{
					"results": map[string]any{
						"contents": []map[string]any{
							{"itemSectionRenderer": map[string]any{"sectionIdentifier": "comment-item-section"}},
							{"itemSectionRenderer": map[string]any{"sectionIdentifier": "video-primary-info"}},
						},
					},
				},
				"secondaryResults": map[string]any{"secondaryResults": map[string]any{"results": []any{}}},
				"autoplay":         map[string]any{"sets": []any{}},
				"playlist":         map[string]any{"playlistId": "PL123"},
			},
		},
	})
	policy, fc := newYoutubeFlow(t, "/watch?v=abc", "text/html; charset=utf-8",
		`<html><script>var ytInitialData = `+initialData+`;</script></html>`)
	policy.YouTube.RemoveComments = true
	policy.YouTube.RemoveRecommendations = true

	addons.YouTubeFilter{}.HandleResponse(fc)

	body := string(fc.ResponseBody)
	for _, removed := range []string{"comment-item-section", "secondaryResults", "autoplay", "playlist"} {
		if strings.Contains(body, removed) {
			t.Errorf("expected %s to be stripped, body = %s", removed, body)
		}
	}
	if !strings.Contains(body, "video-primary-info") {
		t.Errorf("expected non-comment watch content to be preserved, body = %s", body)
	}
}

func TestYouTubeBrowseBlocksChannelByHandle(t *testing.T) {
	policy, fc := newYoutubeFlow(t, "/youtubei/v1/browse", "application/json", `{
		"responseContext": {"foo": "bar"},
		"metadata": {"channelMetadataRenderer": {
			"externalId": "UCzzzzzzzzzzzzzzzzzzzzzz",
			"title": "Some Channel",
			"vanityChannelUrl": "https://www.youtube.com/@somechannel"
		}}
	}`)
	policy.YouTube.Mode = models.YouTubeModeBlacklist
	policy.YouTube.Channels = []string{"@SomeChannel"}

	addons.YouTubeFilter{}.HandleResponse(fc)

	body := string(fc.ResponseBody)
	if strings.Contains(body, "channelMetadataRenderer") {
		t.Error("expected browse payload to be blanked")
	}
	if !strings.Contains(body, `"foo":"bar"`) {
		t.Error("expected responseContext to be preserved in the blanked payload")
	}
}

func TestYouTubeBrowseHomeFeedBlockedInWhitelistMode(t *testing.T) {
	policy, fc := newYoutubeFlow(t, "/youtubei/v1/browse", "application/json", `{
		"responseContext": {},
		"contents": {"some": "feed"}
	}`)
	policy.YouTube.Mode = models.YouTubeModeWhitelist
	policy.YouTube.BlockHome = true

	addons.YouTubeFilter{}.HandleResponse(fc)

	if strings.Contains(string(fc.ResponseBody), "feed") {
		t.Error("expected home feed to be blanked in whitelist mode")
	}
}

func TestYouTubeWatchHTMLBlocksChannel(t *testing.T) {
	policy, fc := newYoutubeFlow(t, "/watch", "text/html; charset=utf-8", `
		<html><script>var data = {"channelId":"UCabcdefghijklmnopqrstuv","author":"BadChannel"};</script></html>
	`)
	policy.YouTube.Mode = models.YouTubeModeBlacklist
	policy.YouTube.Channels = []string{"UCabcdefghijklmnopqrstuv"}

	addons.YouTubeFilter{}.HandleResponse(fc)

	if fc.Response.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want 200 (block page)", fc.Response.StatusCode)
	}
	if !strings.Contains(string(fc.ResponseBody), "BadChannel") {
		t.Error("expected block page to reference the blocked channel")
	}
}

func TestYouTubeChannelHTMLBlocksByURLHandle(t *testing.T) {
	policy, fc := newYoutubeFlow(t, "/@somechannel", "text/html; charset=utf-8", `
		<html><script>"externalId":"UCzzzzzzzzzzzzzzzzzzzzzz"</script></html>
	`)
	policy.YouTube.Mode = models.YouTubeModeBlacklist
	policy.YouTube.Channels = []string{"@somechannel"}

	addons.YouTubeFilter{}.HandleResponse(fc)

	if fc.Response.Header.Get("Content-Type") == "text/html; charset=utf-8" && fc.ResponseBody == nil {
		t.Fatal("expected a block response body")
	}
	if !strings.Contains(string(fc.ResponseBody), "Access Blocked") {
		t.Errorf("expected block page, got %s", fc.ResponseBody)
	}
}

func TestYouTubeHomeHTMLBlockedInWhitelistMode(t *testing.T) {
	policy, fc := newYoutubeFlow(t, "/", "text/html; charset=utf-8", "<html>home feed</html>")
	policy.YouTube.Mode = models.YouTubeModeWhitelist
	policy.YouTube.BlockHome = true

	addons.YouTubeFilter{}.HandleResponse(fc)

	if !strings.Contains(string(fc.ResponseBody), "Access Blocked") {
		t.Error("expected home page to be blocked in whitelist mode with block_home")
	}
}

func TestYouTubeDisabledIsNoop(t *testing.T) {
	policy, fc := newYoutubeFlow(t, "/watch", "text/html", "<html>irrelevant</html>")
	policy.YouTube.Enabled = false

	addons.YouTubeFilter{}.HandleResponse(fc)

	if fc.Response.StatusCode == http.StatusOK && string(fc.ResponseBody) != "<html>irrelevant</html>" {
		t.Error("did not expect any mutation when youtube filtering is disabled")
	}
}
