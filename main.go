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

func main() {
	// intFlag is used to send gratuitous arps at this interval
	intFlag := flag.Duration("t", 2*time.Minute, "time interval for gratuitous arps for migrated IPs")
	// ifaceFlag is used to set a network interface for ARP traffic
	ifaceFlag := flag.String("i", "", "network interface to use for ARP traffic")
	// ipFlag is used to set an IPv4 address to proxy ARP on behalf of
	macFlag := flag.String("mac", "", "Mac address to spoof in arp reply")
	fileFlag := flag.String("f", "/etc/arpproxy.list", "file listing all migrated IPv4")
	logFlag := flag.String("loglevel", "info", "loglevel")
	logJson := flag.Bool("logjson", false, "log plain text or json")
	graceFlag := flag.Duration("grace", 500*time.Millisecond, "time to wait for arp reply before considering IP non-local and spoof it. setting this negative will disable auto-detect")

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

	if *logJson {
		log.SetFormatter(&log.JSONFormatter{})
	} else {
		log.SetFormatter(&log.TextFormatter{
			FullTimestamp: true,
			PadLevelText:  true,
			DisableColors: false,
		})
	}

	s, err := NewSpoofer(*ifaceFlag, *macFlag, *graceFlag)
	if err != nil {
		log.Fatalf("failed to get spoofer: %v", err)
	}

	// update IPs from file at intervals
	go updater(s, *fileFlag, *intFlag)

	// send gratuitous arps
	go s.sendGratuitous(*intFlag)

	// read/listen for arps
	go s.readArp()

	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, os.Interrupt)
	<-sigC
	os.Exit(1)
}

func updater(c *Spoofer, filename string, timer time.Duration) {
	// read file immediately on first run
	firstRun := make(chan struct{}, 1)
	firstRun <- struct{}{}

	for {
		// wait for the next interval
		select {
		case <-time.After(timer):
		case <-firstRun:
		}

		newIps, err := readFile(filename)
		if err != nil {
			log.Warnf("Unable to read file: %v", err)
			continue
		}

		log.Infof("Updated list of static IPs: %v", *newIps)
		c.SetIPs(newIps)
	}
}

func readFile(filename string) (*map[string]net.IP, error) {
	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		return nil, fmt.Errorf("failed opening file: %w", err)
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	//var newIps []net.IP
	newIps := make(map[string]net.IP)

	for scanner.Scan() {
		s := scanner.Text()
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() == nil {
			log.Warnf("could not parse IP %v", s)
			continue
		}
		newIps[s] = ip
	}

	return &newIps, nil
}
