package main

// The REST API under /pf/api/, for scripts and the console's API tab
// (Swagger UI over console/openapi.json). Every endpoint takes a console
// session, or the console password in X-API-Token. Requests that change
// something also need X-PF-Console: 1 or X-API-Token, so a cross-site form
// cannot send them. The console page's own routes in console.go stay as
// they are.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

func (s *consoleServer) apiRoutes(mux *http.ServeMux) {
	read := func(h http.HandlerFunc) http.HandlerFunc { return s.requireAuth(h) }
	write := func(h http.HandlerFunc) http.HandlerFunc { return s.requireCSRF(s.requireAuth(h)) }
	p := consolePrefix + "/api"
	mux.HandleFunc("GET "+p+"/health", s.handleHealth)
	mux.HandleFunc("GET "+p+"/stats", read(s.handleStats))
	mux.HandleFunc("GET "+p+"/policy", read(s.handlePolicy))
	mux.HandleFunc("GET "+p+"/listeners", read(s.handleListListeners))
	mux.HandleFunc("POST "+p+"/listeners/validate", write(s.handleValidateListener))
	mux.HandleFunc("GET "+p+"/listeners/{id}", read(s.handleGetListener))
	mux.HandleFunc("PUT "+p+"/listeners/{id}", write(s.handleEditListener))
	mux.HandleFunc("DELETE "+p+"/listeners/{id}", write(s.handleDeleteListener))
	mux.HandleFunc("GET "+p+"/listeners/{id}/connections", read(s.handleListenerConnections))
	mux.HandleFunc("GET "+p+"/connections", read(s.handleListConnections))
	mux.HandleFunc("GET "+p+"/connections/{id}", read(s.handleGetConnection))
	mux.HandleFunc("DELETE "+p+"/connections/{id}", write(s.handleStop))
	mux.HandleFunc("GET "+p+"/flows", read(s.handleFlows))
}

// apiListener is a listener without its pipes; they have their own
// endpoint. The outer Pipes field hides the embedded one.
type apiListener struct {
	listenerSnapshot
	Pipes []pipeSnapshot `json:"pipes,omitempty"`
}

func apiListeners(all []listenerSnapshot) []apiListener {
	out := make([]apiListener, len(all))
	for i, l := range all {
		out[i] = apiListener{listenerSnapshot: l}
	}
	return out
}

func (s *consoleServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"status": "ok", "version": version})
}

type apiStats struct {
	Version          string  `json:"version"`
	Host             string  `json:"host"`
	Now              int64   `json:"now"`     // unix ms
	Started          int64   `json:"started"` // unix ms
	UptimeSeconds    float64 `json:"uptimeSeconds"`
	Listeners        int     `json:"listeners"`
	Running          int     `json:"running"`
	ActiveConns      int     `json:"activeConnections"`
	Accepted         uint64  `json:"accepted"`
	Failed           uint64  `json:"failed"`
	Rejected         uint64  `json:"rejected"`
	BytesUp          uint64  `json:"bytesUp"`
	BytesDown        uint64  `json:"bytesDown"`
	ManagementOn     bool    `json:"management"`
	FlowHistoryLimit int     `json:"flowHistoryLimit"`
}

func (s *consoleServer) handleStats(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	st := apiStats{
		Version: version, Host: s.host, Now: now.UnixMilli(), Started: s.started.UnixMilli(),
		UptimeSeconds: now.Sub(s.started).Seconds(), ManagementOn: s.mgr.policy != nil, FlowHistoryLimit: flowHistory,
	}
	for _, l := range s.mgr.snapshot() {
		st.Listeners++
		if l.Running {
			st.Running++
		}
		st.ActiveConns += l.PipeCount
		st.Accepted += l.Accepted
		st.Failed += l.Failed
		st.Rejected += l.Rejected
		st.BytesUp += l.BytesUp
		st.BytesDown += l.BytesDown
	}
	writeJSON(w, st)
}

func (s *consoleServer) handlePolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.mgr.info())
}

func (s *consoleServer) handleListListeners(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, apiListeners(s.mgr.snapshot()))
}

// findListener returns the listener named by the {id} path value, or writes
// the error.
func (s *consoleServer) findListener(w http.ResponseWriter, r *http.Request) (listenerSnapshot, bool) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad listener id")
		return listenerSnapshot{}, false
	}
	for _, l := range s.mgr.snapshot() {
		if l.ID == id {
			return l, true
		}
	}
	writeError(w, http.StatusNotFound, errNotFound.Error())
	return listenerSnapshot{}, false
}

func (s *consoleServer) handleGetListener(w http.ResponseWriter, r *http.Request) {
	if l, ok := s.findListener(w, r); ok {
		writeJSON(w, apiListener{listenerSnapshot: l})
	}
}

func (s *consoleServer) handleListenerConnections(w http.ResponseWriter, r *http.Request) {
	l, ok := s.findListener(w, r)
	if !ok {
		return
	}
	writeJSON(w, s.connections(l.ID))
}

// connections lists the open connections, all of them or one listener's
// (listener >= 0), oldest first.
func (s *consoleServer) connections(listener int) []pipeSnapshot {
	live, _ := pipes.list(0)
	out := []pipeSnapshot{}
	for _, p := range live {
		if listener < 0 || p.listener.id == listener {
			out = append(out, p.snapshot())
		}
	}
	return out
}

func (s *consoleServer) handleListConnections(w http.ResponseWriter, r *http.Request) {
	listener := -1
	if v := r.URL.Query().Get("listener"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad listener id")
			return
		}
		listener = n
	}
	writeJSON(w, s.connections(listener))
}

func (s *consoleServer) handleGetConnection(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad connection id")
		return
	}
	p := pipes.get(id)
	if p == nil {
		writeError(w, http.StatusNotFound, "no such connection")
		return
	}
	writeJSON(w, p.snapshot())
}

// decodeSpec reads a listener spec from the body, or writes the error.
func decodeSpec(w http.ResponseWriter, r *http.Request) (listenerSpec, bool) {
	var spec listenerSpec
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		writeError(w, http.StatusBadRequest, "bad request: "+err.Error())
		return spec, false
	}
	return spec, true
}

// handleValidateListener checks a spec as add would, or as edit would with
// ?id=, without changing anything.
func (s *consoleServer) handleValidateListener(w http.ResponseWriter, r *http.Request) {
	id := -1
	if v := r.URL.Query().Get("id"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "bad listener id")
			return
		}
		id = n
	}
	spec, ok := decodeSpec(w, r)
	if !ok {
		return
	}
	normalized, err := s.mgr.validate(spec, id)
	if err != nil {
		writeError(w, statusFor(err), err.Error())
		return
	}
	writeJSON(w, map[string]any{"valid": true, "spec": normalized})
}

func (s *consoleServer) handleEditListener(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad listener id")
		return
	}
	spec, ok := decodeSpec(w, r)
	if !ok {
		return
	}
	if err := s.mgr.edit(id, spec); err != nil {
		writeError(w, statusFor(err), err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *consoleServer) handleDeleteListener(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad listener id")
		return
	}
	if err := s.mgr.remove(id); err != nil {
		writeError(w, statusFor(err), err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
