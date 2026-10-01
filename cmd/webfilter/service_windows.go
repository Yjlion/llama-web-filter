//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// windowsServiceRunName is passed to svc.Run purely for event-log labeling;
// it does not need to match the name a service was installed under - the
// dispatch-table service name is ignored by Windows for
// SERVICE_WIN32_OWN_PROCESS services, which is what `service install`
// always creates (one webfilter process per service, never shared).
const windowsServiceRunName = "WebFilterProxy"

// runAsWindowsServiceIfApplicable detects whether this process was launched
// by the Service Control Manager (as opposed to a normal interactive/console
// invocation of `webfilter run`) and, if so, hands off to svc.Run's blocking
// service dispatch loop instead of returning to cobra's normal command flow.
func runAsWindowsServiceIfApplicable(settingsPath string) (handled bool, err error) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, nil
	}
	return true, svc.Run(windowsServiceRunName, &webfilterService{settingsPath: settingsPath})
}

// webfilterService adapts runProxyAndMgmt to svc.Handler: it starts the
// proxy+management server on a background goroutine, reports Running once
// it has, and waits for a Stop/Shutdown control request to cancel the
// context and let runProxyAndMgmt shut down its two listeners cleanly
// before reporting Stopped back to the SCM.
type webfilterService struct {
	settingsPath string
}

func (h *webfilterService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- runProxyAndMgmt(ctx, h.settingsPath) }()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case err := <-errCh:
			// The server exited on its own (startup failure, fatal error) -
			// nothing left to supervise.
			changes <- svc.Status{State: svc.Stopped}
			if err != nil {
				return true, 1
			}
			return false, 0
		case req := <-r:
			switch req.Cmd {
			case svc.Interrogate:
				changes <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				<-errCh // wait for runProxyAndMgmt to actually finish shutting down
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		}
	}
}

// ---------------------------------------------------------------------------
// `webfilter service install|uninstall|start|stop|status`
// ---------------------------------------------------------------------------

func newServiceCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "service",
		Short: "Manage WebFilter Proxy as a Windows service (most subcommands need an elevated/Administrator prompt)",
	}
	var name string
	root.PersistentFlags().StringVar(&name, "name", windowsServiceRunName, "Windows service name")

	install := &cobra.Command{Use: "install", Short: "Register `webfilter run` as a Windows service"}
	f := addConfigFlags(install)
	install.RunE = func(cmd *cobra.Command, args []string) error {
		return installWindowsService(name, f.settingsPath)
	}

	uninstall := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the registered Windows service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return uninstallWindowsService(name)
		},
	}
	start := &cobra.Command{
		Use:   "start",
		Short: "Start the installed Windows service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return startWindowsService(name)
		},
	}
	stop := &cobra.Command{
		Use:   "stop",
		Short: "Stop the running Windows service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return stopWindowsService(name)
		},
	}
	status := &cobra.Command{
		Use:   "status",
		Short: "Show the Windows service's current state",
		RunE: func(cmd *cobra.Command, args []string) error {
			return statusWindowsService(name)
		},
	}

	root.AddCommand(install, uninstall, start, stop, status)
	return root
}

func openManager() (*mgr.Mgr, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("connect to Windows Service Control Manager (try running as Administrator): %w", err)
	}
	return m, nil
}

func installWindowsService(name, settingsPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return fmt.Errorf("resolve absolute executable path: %w", err)
	}
	absSettings, err := filepath.Abs(settingsPath)
	if err != nil {
		return fmt.Errorf("resolve absolute settings path: %w", err)
	}

	m, err := openManager()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	if existing, err := m.OpenService(name); err == nil {
		existing.Close()
		return fmt.Errorf("service %q is already installed - run `webfilter service uninstall --name %s` first", name, name)
	}

	s, err := m.CreateService(name, exe, mgr.Config{
		DisplayName: "WebFilter Proxy",
		Description: "MITM web-filtering proxy + management UI (webfilter run)",
		StartType:   mgr.StartAutomatic,
	}, "run", "--settings", absSettings)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	fmt.Printf("Service %q installed (binary: %s, settings: %s)\n", name, exe, absSettings)
	fmt.Printf("Run `webfilter service start --name %s` to start it now.\n", name)
	return nil
}

func uninstallWindowsService(name string) error {
	m, err := openManager()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("open service %q: %w", name, err)
	}
	defer s.Close()

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service %q: %w", name, err)
	}
	fmt.Printf("Service %q removed.\n", name)
	return nil
}

func startWindowsService(name string) error {
	m, err := openManager()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("open service %q: %w", name, err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("start service %q: %w", name, err)
	}
	fmt.Printf("Service %q start requested.\n", name)
	return nil
}

func stopWindowsService(name string) error {
	m, err := openManager()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("open service %q: %w", name, err)
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("stop service %q: %w", name, err)
	}

	deadline := time.Now().Add(15 * time.Second)
	for status.State != svc.Stopped {
		if time.Now().After(deadline) {
			return fmt.Errorf("stop service %q: timed out waiting for it to stop", name)
		}
		time.Sleep(300 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("query service %q status: %w", name, err)
		}
	}
	fmt.Printf("Service %q stopped.\n", name)
	return nil
}

func statusWindowsService(name string) error {
	state, err := queryWindowsServiceState(name)
	if err != nil {
		return err
	}
	fmt.Printf("Service %q: %s\n", name, serviceStateString(state))
	return nil
}

// queryWindowsServiceState is the shared lookup behind statusWindowsService
// (CLI: prints the result) and the tray's "Service Status" menu item (shows
// it in a balloon notification instead).
func queryWindowsServiceState(name string) (svc.State, error) {
	m, err := openManager()
	if err != nil {
		return 0, err
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return 0, fmt.Errorf("open service %q: %w", name, err)
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return 0, fmt.Errorf("query service %q status: %w", name, err)
	}
	return status.State, nil
}

func serviceStateString(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start pending"
	case svc.StopPending:
		return "stop pending"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continue pending"
	case svc.PausePending:
		return "pause pending"
	case svc.Paused:
		return "paused"
	default:
		return fmt.Sprintf("unknown (%d)", state)
	}
}
