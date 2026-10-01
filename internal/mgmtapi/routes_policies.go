package mgmtapi

import (
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yjlion/llama-web-filter/internal/config"
	"github.com/yjlion/llama-web-filter/internal/logstore"
	"github.com/yjlion/llama-web-filter/internal/models"
)

// adminClientIP extracts the caller's IP from a management API request,
// stripping the port. Falls back to the raw RemoteAddr if it isn't in
// host:port form (e.g. under some test transports).
func adminClientIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	list, err := s.Policies.List()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	p, err := s.Policies.Get(name)
	if errors.Is(err, config.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "Policy '"+name+"' not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	p := models.NewPolicy()
	if err := readJSON(r, &p); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid policy body: "+err.Error())
		return
	}
	if err := s.Policies.Create(p); err != nil {
		if errors.Is(err, config.ErrExists) {
			writeJSONError(w, http.StatusConflict, "Policy '"+p.Name+"' already exists")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.Logs.LogPolicyChange(logstore.PolicyChangeEntry{
		TS: time.Now().Unix(), Action: "created", PolicyName: p.Name, ClientIP: adminClientIP(r),
	})
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	p := models.NewPolicy()
	if err := readJSON(r, &p); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid policy body: "+err.Error())
		return
	}
	if err := s.Policies.Update(name, p); err != nil {
		switch {
		case errors.Is(err, config.ErrNotFound):
			writeJSONError(w, http.StatusNotFound, "Policy '"+name+"' not found")
		case errors.Is(err, config.ErrExists):
			writeJSONError(w, http.StatusConflict, "Policy '"+p.Name+"' already exists")
		default:
			writeJSONError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	oldName := ""
	if name != p.Name {
		oldName = name
	}
	_ = s.Logs.LogPolicyChange(logstore.PolicyChangeEntry{
		TS: time.Now().Unix(), Action: "updated", PolicyName: p.Name, OldName: oldName, ClientIP: adminClientIP(r),
	})
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := s.Policies.Delete(name); err != nil {
		if errors.Is(err, config.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "Policy '"+name+"' not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.Logs.LogPolicyChange(logstore.PolicyChangeEntry{
		TS: time.Now().Unix(), Action: "deleted", PolicyName: name, ClientIP: adminClientIP(r),
	})
	w.WriteHeader(http.StatusNoContent)
}
