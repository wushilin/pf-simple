package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestManagePolicy(t *testing.T) {
	p, err := newManagePolicy(&consoleTable{
		AllowTargetHosts: []string{"10.0.0.6", "192.168.1.0/24", "db.internal", "2001:db8::/32"},
		AllowTargetPorts: "80, 9030, 3000-3999",
		AllowBindHosts:   []string{"127.0.0.1", "0.0.0.0"},
		AllowBindPorts:   "18000-18010, 19030",
	})
	if err != nil {
		t.Fatal(err)
	}
	ok := []string{"127.0.0.1:18000@10.0.0.6:80", "18010@192.168.1.77:3500", "0.0.0.0:19030@db.internal:9030",
		"18005@[2001:db8::1]:80", "18001@DB.Internal:3000"}
	for _, v := range ok {
		fw, _ := parseForward(v)
		if err := p.check(fw); err != nil {
			t.Errorf("%s should be allowed: %v", v, err)
		}
	}
	bad := map[string]string{
		"18000@10.0.0.7:80":          "target host 10.0.0.7 is not allowed",
		"18000@other.internal:80":    "target host other.internal",
		"18000@10.0.0.6:81":          "target port 81 is not allowed",
		"18011@10.0.0.6:80":          "listen port 18011 is not allowed",
		"10.0.0.9:18000@10.0.0.6:80": "listen host 10.0.0.9 is not allowed",
	}
	for v, want := range bad {
		fw, _ := parseForward(v)
		if err := p.check(fw); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", v, want, err)
		}
	}

	// A bind host list without the unspecified address refuses "all interfaces".
	local, _ := newManagePolicy(&consoleTable{AllowBindHosts: []string{"127.0.0.1"}})
	fw, _ := parseForward("18000@10.0.0.6:80")
	if err := local.check(fw); err == nil || !strings.Contains(err.Error(), "all interfaces") {
		t.Errorf("all-interface bind under a loopback-only policy: %v", err)
	}
	fw, _ = parseForward("127.0.0.1:18000@10.0.0.6:80")
	if err := local.check(fw); err != nil {
		t.Errorf("loopback bind: %v", err)
	}

	// No lists: no restriction at all.
	open, _ := newManagePolicy(&consoleTable{})
	fw, _ = parseForward("80@anything.example:1")
	if err := open.check(fw); err != nil {
		t.Errorf("empty policy should allow anything: %v", err)
	}
	for _, c := range []*consoleTable{
		{AllowTargetHosts: []string{"10.0.0.0/99"}},
		{AllowBindHosts: []string{"not a host"}},
		{AllowTargetPorts: "9000-80"},
		{AllowBindPorts: "70000"},
	} {
		if _, err := newManagePolicy(c); err == nil {
			t.Errorf("%+v should be rejected", c)
		}
	}
}

// startFromConfig runs pf-simple from a config file the way main does and
// returns the console URL and manager.
func startFromConfig(t *testing.T, path string) (string, *manager) {
	t.Helper()
	cfg, err := loadConfig(path, "")
	if err != nil {
		t.Fatal(err)
	}
	mgr := newManager(cfg.forwards, cfg.console.manage, halfCloseIdleTimeout)
	mgr.configPath, mgr.consoleRaw = cfg.configPath, cfg.consoleRaw
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); mgr.shutdown() })
	if err := mgr.startAll(ctx); err != nil {
		t.Fatal(err)
	}
	cs := newConsoleServer("", "", mgr)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go cs.serve(ctx, ln)
	return "http://" + ln.Addr().String(), mgr
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func apiPost(t *testing.T, url, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set(csrfHeader, "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestListenerLifecycleRewritesConfig(t *testing.T) {
	echo := startServer(t, func(c *net.TCPConn) { _, _ = io.Copy(c, c) })
	_, echoPort, _ := net.SplitHostPort(echo)
	fixedPort := freePort(t)
	path := writeConfig(t, fmt.Sprintf(`# hand-written comment
[console]
listen = "127.0.0.1:%d"
password = "secret@pw"
allow_target_hosts = ["127.0.0.1"]
allow_bind_ports = "1024-65535"

[[forward]]
name = "Fixed"
listen = "127.0.0.1:%d"
target = "127.0.0.1:%s"
`, freePort(t), fixedPort, echoPort))
	base, mgr := startFromConfig(t, path)
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// Add, then use it.
	code, body := apiPost(t, base+"/api/listeners", fmt.Sprintf(`{"name":"Echo","listen":%q,"target":"127.0.0.1:%s","maxConnections":5,"perConnSpeed":"10MiB/s"}`, addr, echoPort))
	if code != http.StatusCreated {
		t.Fatalf("add: %d %s", code, body)
	}
	var created struct{ ID int }
	_ = json.Unmarshal([]byte(body), &created)
	c := dial(t, addr)
	_, _ = c.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("forward after add: %q %v", buf, err)
	}

	// The config file now holds both listeners and the untouched [console].
	data := readFile(t, path)
	for _, want := range []string{`password = "secret@pw"`, `allow_target_hosts = ["127.0.0.1"]`, `allow_bind_ports = "1024-65535"`,
		`name = "Fixed"`, `name = "Echo"`, `listen = "` + addr + `"`, "max_connections = 5", `per_connection_max_speed = "10MiB/s"`} {
		if !strings.Contains(data, want) {
			t.Errorf("config lacks %s:\n%s", want, data)
		}
	}
	if strings.Contains(data, "enabled") || strings.Contains(data, "hand-written") {
		t.Errorf("unexpected content (enabled listeners omit the key; comments are replaced):\n%s", data)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("config mode %v", info.Mode().Perm())
	}

	// Policy and duplicate checks.
	if code, body := apiPost(t, base+"/api/listeners", fmt.Sprintf(`{"listen":"%d","target":"10.9.9.9"}`, freePort(t))); code != 400 || !strings.Contains(body, "not allowed") {
		t.Errorf("disallowed target: %d %s", code, body)
	}
	if code, body := apiPost(t, base+"/api/listeners", fmt.Sprintf(`{"listen":%q,"target":"127.0.0.1:1"}`, addr)); code != 400 || !strings.Contains(body, "already used") {
		t.Errorf("duplicate listen: %d %s", code, body)
	}
	if code, _ := apiPost(t, base+"/api/listeners", `{"listen":"1","target":"x","bogus":1}`); code != 400 {
		t.Errorf("unknown field: %d", code)
	}

	// Delete and edit need a stopped listener.
	if code, body := apiPost(t, fmt.Sprintf("%s/api/listeners/%d/delete", base, created.ID), ""); code != http.StatusConflict || !strings.Contains(body, "stop the listener first") {
		t.Fatalf("delete while running: %d %s", code, body)
	}
	if code, _ := apiPost(t, fmt.Sprintf("%s/api/listeners/%d/edit", base, created.ID), `{"listen":"1","target":"x"}`); code != http.StatusConflict {
		t.Fatalf("edit while running: %d", code)
	}

	// Stop: the open pipe is reset, the port refuses, the stop is saved.
	if code, body := apiPost(t, fmt.Sprintf("%s/api/listeners/%d/stop", base, created.ID), ""); code != http.StatusNoContent {
		t.Fatalf("stop: %d %s", code, body)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(buf); err == nil {
		t.Fatal("open pipe should be reset by stop")
	}
	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		conn.Close()
		t.Fatal("stopped listener still accepts")
	}
	if n := snapshotFor(mgr, created.ID).PipeCount; n != 0 {
		t.Fatalf("pipes left after stop: %d", n)
	}
	if data := readFile(t, path); strings.Count(data, "enabled = false") != 1 {
		t.Errorf("stop not saved:\n%s", data)
	}

	// Edit while stopped: counters carry over, unset limits disappear.
	before := snapshotFor(mgr, created.ID).Accepted
	if code, body := apiPost(t, fmt.Sprintf("%s/api/listeners/%d/edit", base, created.ID),
		fmt.Sprintf(`{"name":"Echo 2","listen":%q,"target":"127.0.0.1:%s","totalSpeed":"50MiB/s"}`, addr, echoPort)); code != http.StatusNoContent {
		t.Fatalf("edit: %d %s", code, body)
	}
	if s := snapshotFor(mgr, created.ID); s.Name != "Echo 2" || s.TotalSpeed != 50<<20 || s.MaxConns != 0 || s.Accepted != before || s.Running {
		t.Fatalf("after edit: %+v", s)
	}
	data = readFile(t, path)
	if !strings.Contains(data, `name = "Echo 2"`) || strings.Contains(data, "max_connections") || !strings.Contains(data, "enabled = false") {
		t.Errorf("edit not saved:\n%s", data)
	}

	// The rewritten file loads again: same listeners, stopped one stays stopped.
	_, mgr2 := startFromConfigOnFreeConsole(t, path, fixedPort, addr)
	if s := snapshotFor(mgr2, 1); s.Listen != addr || s.Running || s.Name != "Echo 2" || s.Source != sourceConfig {
		t.Fatalf("reloaded listener: %+v", s)
	}
	mgr2.shutdown()

	// Start, then stop and delete.
	if code, body := apiPost(t, fmt.Sprintf("%s/api/listeners/%d/start", base, created.ID), ""); code != http.StatusNoContent {
		t.Fatalf("start: %d %s", code, body)
	}
	c2 := dial(t, addr)
	_, _ = c2.Write([]byte("pong"))
	if _, err := io.ReadFull(c2, buf); err != nil || string(buf) != "pong" {
		t.Fatalf("forward after start: %q %v", buf, err)
	}
	if data := readFile(t, path); strings.Contains(data, "enabled") {
		t.Errorf("start not saved:\n%s", data)
	}
	apiPost(t, fmt.Sprintf("%s/api/listeners/%d/stop", base, created.ID), "")
	if code, body := apiPost(t, fmt.Sprintf("%s/api/listeners/%d/delete", base, created.ID), ""); code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", code, body)
	}
	if data := readFile(t, path); strings.Contains(data, addr) || !strings.Contains(data, `name = "Fixed"`) {
		t.Errorf("after delete:\n%s", data)
	}

	// Listeners written in the file by hand are editable too.
	if code, body := apiPost(t, fmt.Sprintf("%s/api/listeners/0/stop", base), ""); code != http.StatusNoContent {
		t.Fatalf("stop file listener: %d %s", code, body)
	}
	if code, body := apiPost(t, fmt.Sprintf("%s/api/listeners/0/delete", base), ""); code != http.StatusNoContent {
		t.Fatalf("delete file listener: %d %s", code, body)
	}
	if data := readFile(t, path); strings.Contains(data, "[[forward]]") {
		t.Errorf("file listener not deleted:\n%s", data)
	}
}

// startFromConfigOnFreeConsole loads the same file while the first instance
// still holds its ports, so the second instance's listeners fail to bind; that
// is fine for checking what was loaded.
func startFromConfigOnFreeConsole(t *testing.T, path string, _ int, _ string) (string, *manager) {
	t.Helper()
	cfg, err := loadConfig(path, "")
	if err != nil {
		t.Fatal(err)
	}
	mgr := newManager(cfg.forwards, cfg.console.manage, halfCloseIdleTimeout)
	mgr.configPath, mgr.consoleRaw = cfg.configPath, cfg.consoleRaw
	return "", mgr
}

func TestFixedListenersStartStopOnly(t *testing.T) {
	// Command-line listeners: start and stop work, add, edit and delete do not.
	cliFw, _ := parseForward(fmt.Sprintf("127.0.0.1:%d@127.0.0.1:1", freePort(t)))
	mgr := newManager([]forwarding{cliFw}, nil, halfCloseIdleTimeout)
	if err := mgr.startAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer mgr.shutdown()
	if err := mgr.stop(0); err != nil {
		t.Errorf("stop: %v", err)
	}
	if conn, err := net.DialTimeout("tcp", cliFw.listen, time.Second); err == nil {
		conn.Close()
		t.Error("stopped listener still accepts")
	}
	if err := mgr.remove(0); err != errNoManaging {
		t.Errorf("delete a command-line listener: %v", err)
	}
	if err := mgr.edit(0, listenerSpec{Listen: "2000", Target: "x"}); err != errNoManaging {
		t.Errorf("edit a command-line listener: %v", err)
	}
	if _, err := mgr.add(listenerSpec{Listen: "2000", Target: "x"}); err != errNoManaging {
		t.Errorf("add a command-line listener: %v", err)
	}
	if err := mgr.start(0); err != nil {
		t.Errorf("start: %v", err)
	}

	// A command-line listener mixed with a policy (not possible from main,
	// but the source check must still hold).
	policy, _ := newManagePolicy(&consoleTable{})
	mixed := newManager([]forwarding{cliFw}, policy, halfCloseIdleTimeout)
	if err := mixed.remove(0); err != errReadOnly {
		t.Errorf("delete a command-line listener with a policy: %v", err)
	}
}

func snapshotFor(m *manager, id int) listenerSnapshot {
	for _, l := range m.snapshot() {
		if l.ID == id {
			return l
		}
	}
	return listenerSnapshot{}
}
