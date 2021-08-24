package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"

	log "github.com/sirupsen/logrus"
)

type fileFlag []string

func (f *fileFlag) String() string {
	s := []string(*f)
	return fmt.Sprintf("files: %v", s)
}

func (f *fileFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	// intFlag is used to send gratuitous arps at this interval
	intFlag := flag.Duration("garp", 30*time.Second, "time interval for gratuitous arps IPs, negative values disables garps. NOTE: garps only work for statically and dynamically configured IPs")
	// intFlag is used to send gratuitous arps at this interval
	refreshFlag := flag.Duration("refresh", 2*time.Minute, "time interval for refreshing static IP DB file")
	// ifaceFlag is used to set a network interface for ARP traffic
	ifaceFlag := flag.String("iface", "", "network interface to use for ARP traffic")
	// macFlag is used to set the MAC address to proxy ARP on behalf of
	macFlag := flag.String("mac", "", "Mac address to spoof in arp reply")

	routeFlag := flag.Bool("route", false, "will enable a local route-lookup, if route points to an interface != iface a spoofed arp will be sent")
	allFlag := flag.Bool("spoofAll", false, "spoof all arps you see coming in - use file flag to exclude (you wanna exclude your actual gateway, it needs to arp local ips)")

	//fileFlag := flag.String("static", "", "file listing all migrated IPv4")
	var files fileFlag
	flag.Var(&files, "file", "file listing all IPv4 to be spoofed. can be used multiple times - or if spoofAll is set, a list of IPs to *exclude*")

	logFlag := flag.String("loglevel", "info", "loglevel")
	logJSON := flag.Bool("logjson", false, "log plain text or json")
	graceFlag := flag.Duration("grace", -1*time.Millisecond, "time to wait for arp reply before considering IP non-local and spoof it. a negative value will disable auto-detect")

	flag.Parse()

	// fix me through cli
	switch *logFlag {
	case "trace":
		log.SetLevel(log.TraceLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}

	if *logJSON {
		log.SetFormatter(&log.JSONFormatter{})
	} else {
		log.SetFormatter(&log.TextFormatter{
			FullTimestamp: true,
			PadLevelText:  true,
			DisableColors: false,
		})
	}

	s, err := NewSpoofer(*ifaceFlag, *macFlag, *graceFlag, *routeFlag, *allFlag)
	if err != nil {
		log.Fatalf("failed to get spoofer: %v", err)
	}

	// update IPs from file at intervals
	if len(files) > 0 {
		go updater(s, &files, *refreshFlag)
	}

	// send gratuitous arps
	if *intFlag > 0 {
		go s.HandleGARP(*intFlag)
	}

	// read/listen for arps
	go s.readArp()

	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, os.Interrupt)
	<-sigC
	os.Exit(1)
}

func updater(c *Spoofer, filenames *fileFlag, timer time.Duration) {
	// read file immediately on first run
	firstRun := make(chan struct{}, 1)
	firstRun <- struct{}{}

	for {
		// wait for the next interval
		select {
		case <-time.After(timer):
		case <-firstRun:
		}

		newIps := make(map[string]struct{})

		for _, f := range *filenames {
			if err := readFile(f, newIps); err != nil {
				log.Warnf("Unable to read file: %v", err)
				continue
			}
		}

		log.Infof("Updated list of static IPs: %v", newIps)
		c.UpdateStaticIPs(&newIps)
	}
}

func readFile(filename string, newIps map[string]struct{}) error {
	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		return fmt.Errorf("failed opening file: %w", err)
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		s := scanner.Text()
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() == nil {
			log.Warnf("could not parse IP %v", s)
			continue
		}
		newIps[s] = struct{}{}
	}

	return nil
}
