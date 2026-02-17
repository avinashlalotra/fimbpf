package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"watchd/bpfloader"
	"watchd/eventcore"
	"watchd/netlog"
	"watchd/preprocess"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/spf13/cobra"
)

var (
	config  string
	apifile string

	version   = "1.0.0"
	buildDate = "2026-02-16"
	gitCommit = "dev"
)

func main() {

	rootCmd := &cobra.Command{
		Use:   "watchd",
		Short: "watchd -eBPF-powered file activity monitor for Linux",
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(
		&config,
		"config",
		"/etc/watchd/config.txt",
		"Path to config file",
	)

	rootCmd.PersistentFlags().StringVar(
		&apifile,
		"api",
		"",
		"Path to API JSON file",
	)

	// ---------------- RUN ----------------
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Start the watchd",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {

			var enableNet bool

			if os.Geteuid() != 0 {
				log.Fatal("requires root")
			}
			// Vaidate command line arguments
			if apifile != "" {
				if err := netlog.InitApiAuth(apifile); err != nil {
					log.Printf("Error initializing API auth: %v", err)
				} else {
					enableNet = true
				}
			} else {
				log.Println("API file is required, use --api")
				log.Println("Disabled network logging")
			}

			// parse config file
			policy, err := preprocess.ParseConfig(config)
			if err != nil {
				log.Fatalf("parsing policy: %v", err)
			}

			/* Load eBPF objects */
			bpf := bpfloader.InitBPF()
			if err := bpf.Load(bpf.Objects, nil); err != nil {
				log.Fatalf("loading eBPF objects: %v", err)
			}

			/* Populate policy map */
			count, err := policy.LoadTrackedFileMap(bpf)
			if err != nil {
				log.Printf("loading policy map: %v", err)
			}
			if count == 0 {
				log.Printf("No policy loaded")
				return
			}

			/* Attach eBPF programs */
			links, err := bpf.AttachPrograms()
			if err != nil {
				log.Printf("ERROR: Couldn't attach eBPF programs : %v", err)
				return
			}

			/* Create ring buffer reader */
			rd, err := ringbuf.NewReader(bpf.Objects.Events)
			if err != nil {
				log.Fatalf("opening ring buffer reader: %v", err)
			}

			// Cleanup
			defer func() {

				// Cleanup ring buffer reader
				if rd != nil {
					rd.Close()
				}

				// Cleanup attached programs
				for _, link := range links {
					if link != nil {
						link.Close()
					}
				}
				// Cleanup loaded objects
				bpf.Objects.Close()

			}()

			log.Println("Successfully loaded eBPF program. Monitoring VFS operations...")

			/* Handle CTRL-C */
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

			/* Read events from ring buffer in a goroutine */
			go func() {
				for {
					record, err := rd.Read()
					if err != nil {
						if errors.Is(err, ringbuf.ErrClosed) {
							log.Println("Ring buffer closed, stopping event reader")
							return
						}
						log.Printf("reading from ring buffer: %v", err)
						continue
					}

					// Pstringarse the event
					var event bpfloader.FileChangeEvent
					if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
						log.Printf("parsing event: %v", err)
						continue
					}

					// Process and display the event
					payload := eventcore.ProcessEvent(&event, bpf, &policy)
					eventcore.PrintPayload(payload)
					if enableNet {
						netlog.SendPOST(payload)
					}

				}
			}()

			/* Wait for signal */
			<-sig
			log.Println("Received Termination signal, shutting down...")

			return

		},
	}

	// ---------------- VALIDATE ----------------
	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration file and exit",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {

			cfgPath := config

			if cfgPath == "" {
				return fmt.Errorf("config file path is required, use --config")
			}

			tokens, err := preprocess.ReadConfig(cfgPath)
			if err != nil {
				return fmt.Errorf("error reading config file: %s", err)
			}
			if err := preprocess.SyntaxValidation(tokens); err != nil {
				return fmt.Errorf("error validating config file: %s", err)
			}

			fmt.Println("Config file is valid")
			return nil
		},
	}

	// ---------------- VERSION ----------------
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version, build info, and exit",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Version: %s\n", version)
			fmt.Printf("Git Commit: %s\n", gitCommit)
			fmt.Printf("Build Date: %s\n", buildDate)
		},
	}

	// ---------------- STATUS ----------------
	const serviceName = "watchd.service"

	var statusCmd = &cobra.Command{
		Use:   "status",
		Short: "Check daemon status",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {

			out, err := exec.Command("systemctl", "is-active", serviceName).Output()
			status := strings.TrimSpace(string(out))

			if err != nil || status != "active" {
				fmt.Println("watchd is down")
				os.Exit(1)
			}

			fmt.Println("watchd is up")
		},
	}

	// Add commands
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(statusCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
