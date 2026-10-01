package mgmtapi

import (
	"context"
	"net/http"
	"time"

	"github.com/yjlion/llama-web-filter/internal/models"
)

func contextWithTimeout(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}

func policyByName(policies []models.Policy, name string) models.Policy {
	for _, p := range policies {
		if p.Name == name {
			return p
		}
	}
	p := models.NewPolicy()
	p.Name = name
	return p
}
