package main

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/raw"
	log "github.com/sirupsen/logrus"

	"github.com/vishvananda/netlink"
)

// protocolARP is the uint16 EtherType representation of ARP (Address
// Resolution Protocol, RFC 826).
const protocolARP = 0x0806

// A Spoofer is an Object containing various needs to send and receive spoofed arp packages
type Spoofer struct {
	c        *arp.Client
	p        *raw.Conn
	ifi      *net.Interface
	spoofed  net.HardwareAddr
	sLock    sync.RWMutex
	sIPs     map[string]struct{}
	dLock    sync.RWMutex
	dIPs     map[string]time.Time
	grace    time.Duration
	rtLookup bool
}

// NewSpoofer creates a new Spoofer object based on interface name to listen on, Mac Address to use in spoofed replies
// it also takes a timeDuration option that defines the graceperiod to wait for an arp response to be receive before actively starting to reply with spoofed reponses
func NewSpoofer(ifName, macS string, grace time.Duration, rtLookup bool) (*Spoofer, error) {
	// parse mac
	mac, err := net.ParseMAC(macS)
	if err != nil {
		log.Fatal(err)
	}

	// Ensure valid interface and IPv4 address
	ifi, err := net.InterfaceByName(ifName)
	if err != nil {
		log.Fatal(err)
	}

	p, err := raw.ListenPacket(ifi, protocolARP, nil)
	if err != nil {
		log.Fatal(err)
	}

	c, err := arp.New(ifi, p)
	if err != nil {
		log.Fatalf("couldn't create ARP client: %s", err)
	}

	ips := make(map[string]struct{})
	querriedIps := make(map[string]time.Time)

	if grace < 0 {
		log.Info("auto-detect arp spoofing disabled")
	}

	if rtLookup {
		log.Info("route lookups enabled")
	} else {
		log.Info("route lookups disabled")
	}

	return &Spoofer{
		c:        c,
		p:        p,
		spoofed:  mac,
		ifi:      ifi,
		sIPs:     ips,
		dIPs:     querriedIps,
		grace:    grace,
		rtLookup: rtLookup,
	}, nil
}

func (c *Spoofer) readArp() {
	//func readArp(c *arp.Client, mac, srcMac net.HardwareAddr) {
	// Handle ARP requests bound for designated IPv4 address, using proxy ARP
	// to indicate that the address belongs to the mac specified
	for {
		pkt, eth, err := c.c.Read()
		if err != nil {
			log.Warnf("error processing ARP requests: %s", err)
			continue
		}
		go c.handleArp(pkt, eth)
	}
}

func (c *Spoofer) handleArp(req *arp.Packet, eth *ethernet.Frame) {
	// Ignore ARP requests which are not broadcast
	// do I need this? this was part of upstream arpproxy example
	// this would ignore arp requests going to unicast macs, it does however also ignore arp requests to our spoofed mac which most likely won't answer to that arp
	// eventually the client falls back to broadcasts and traffic should in theory never stop but its not ideal one way or another
	// this only affects requests made/originated on the local host since unicasts from different hosts wouldn't make it to this host anyway.
	// soo skipping these really makes more sense and more consistent experience
	if !bytes.Equal(eth.Destination, ethernet.Broadcast) {
		log.Tracef("arp request but not broadcast: %s %s %-15s %-15s", req.SenderHardwareAddr, eth.Destination, req.SenderIP, req.TargetIP)
		return
	}

	// spoofing arps for statically configured IPs
	if req.Operation == arp.OperationRequest && c.hasStaticIP(req.TargetIP.String()) {
		log.Debugf("static  spoofing %v for %v/%v", req.TargetIP, req.SenderIP, req.SenderHardwareAddr)
		if err := c.sendReply(req.SenderHardwareAddr, req.SenderIP, req.TargetIP); err != nil {
			log.Warnf("handleArp failed: %s", err)
		}
		return
	}

	// spoofing arps matching route lookups
	if c.rtLookup && req.Operation == arp.OperationRequest {
		if err := c.handleArpRouteLookup(req); err != nil {
			log.Warnf("routeLookup ARP failed: %s", err)
		}
	}

	// spoofing arps for dynamically learned macs that don't seem to be local (aka, do not answer arps)
	if c.grace > 0 {
		if err := c.handleArpDynamic(req); err != nil {
			log.Warnf("dynamic ARP failed: %s", err)
		}
		return
	}

	log.Tracef("not qualified for spoofing %v", req.TargetIP)
}

func (c *Spoofer) handleArpRouteLookup(req *arp.Packet) error {
	rts, err := netlink.RouteGet(req.TargetIP)
	if err != nil {
		return fmt.Errorf("unable to lookup route: %v", err)
	}

	log.Tracef("routes matched for %v: %v", req.TargetIP, rts)
	log.Tracef("my ifi: %v", c.ifi)

	for _, r := range rts {
		if r.LinkIndex != c.ifi.Index {
			log.Debugf("route based spoofing %v for %v/%v", req.TargetIP, req.SenderIP, req.SenderHardwareAddr)
			return c.sendReply(req.SenderHardwareAddr, req.SenderIP, req.TargetIP)
		}
	}

	return nil
}

func (c *Spoofer) handleArpDynamic(req *arp.Packet) error {
	// if arp reply and remove the IP in question from potential spoofing candidate. if rely shows up clearly its not in a different network
	if req.Operation == arp.OperationReply {
		c.delDynIP(req.SenderIP)
		return nil
	}

	// check for IP in dynamic DB
	t, exists := c.getDynIP(req.TargetIP)

	// did I recently check this IP already? and if so, how long ago
	// we may need this to prevent amplification attacks? maybe I'm overthinking...
	// in other words I only wanna send out an arp request for a specific IP at most every grace period/2 intervals -> which may already be kinda agressive
	// if I didn't check for this IP yet at all - or I already heard back from it - check it again
	if !exists || time.Since(t) > c.grace/2 {
		if err := c.c.Request(req.TargetIP); err == nil {
			c.addDynIP(req.TargetIP)
		} else {
			return fmt.Errorf("failed sending probing arp to %s: %s.... disqualified for spoofing", req.TargetIP, err)
		}
	}

	// only proxy ARP requests for IPs we are supposed to handle
	// in this case qualifying auto-detected IPs. aka IPs that have not answered my own arps for time of "grace period"
	if exists && time.Since(t) > c.grace {
		log.Debugf("dynamic spoofing %v for %v/%v", req.TargetIP, req.SenderIP, req.SenderHardwareAddr)
		return c.sendReply(req.SenderHardwareAddr, req.SenderIP, req.TargetIP)
	}

	return nil
}

func (c *Spoofer) getDynIP(ip net.IP) (time.Time, bool) {
	c.dLock.RLock()
	defer c.dLock.RUnlock()
	t, e := c.dIPs[ip.String()]
	return t, e
}

func (c *Spoofer) delDynIP(ip net.IP) {
	if _, exists := c.getDynIP(ip); exists {
		log.Tracef("removing: %s", ip)
		c.dLock.Lock()
		delete(c.dIPs, ip.String())
		c.dLock.Unlock()
	}
}

func (c *Spoofer) addDynIP(ip net.IP) {
	if _, exists := c.getDynIP(ip); !exists {
		log.Tracef("tracking: %s", ip)
		c.dLock.Lock()
		c.dIPs[ip.String()] = time.Now()
		c.dLock.Unlock()
	}
}

func (c *Spoofer) hasStaticIP(ip string) bool {
	c.sLock.RLock()
	defer c.sLock.RUnlock()
	_, exists := c.sIPs[ip]
	return exists
}

// UpdateStaticIPs updates the list of statically configured IPs to send spoofed ARPs to
func (c *Spoofer) UpdateStaticIPs(ips *map[string]struct{}) {
	c.sLock.Lock()
	c.sIPs = *ips
	c.sLock.Unlock()
}

func (c *Spoofer) sendReply(dstMac net.HardwareAddr, dstIP, srcIP net.IP) error {
	log.Tracef("     reply for %15s: %15s is-at %s", dstIP, srcIP, c.spoofed)
	p, err := arp.NewPacket(arp.OperationReply, c.spoofed, srcIP, dstMac, dstIP)
	if err != nil {
		return fmt.Errorf("sendReply failed: %w", err)
	}

	pb, err := p.MarshalBinary()
	if err != nil {
		return fmt.Errorf("sendReply failed: %w", err)
	}

	f := &ethernet.Frame{
		Destination: dstMac,
		Source:      c.ifi.HardwareAddr,
		EtherType:   ethernet.EtherTypeARP,
		Payload:     pb,
	}

	fb, err := f.MarshalBinary()
	if err != nil {
		return fmt.Errorf("sendReply failed: %w", err)
	}

	_, err = c.p.WriteTo(fb, &raw.Addr{HardwareAddr: dstMac})
	if err != nil {
		return fmt.Errorf("sendReply failed: %w", err)
	}
	return nil
}

// HandleGARP handles the constant sending of gratuitous ARPs
func (c *Spoofer) HandleGARP(timer time.Duration) {
	for {
		select {
		case <-time.After(timer):
		}

		c.sLock.RLock()
		for ip := range c.sIPs {
			go c.SendGARP(ip)
		}
		c.sLock.RUnlock()

		if c.grace > 0 {
			c.dLock.RLock()
			for ip, t := range c.dIPs {
				if time.Since(t) > c.grace {
					go c.SendGARP(ip)
				}
			}
			c.dLock.RUnlock()
		}
	}
}

// SendGARP sends a single gratuitous ARP of the IP given
func (c *Spoofer) SendGARP(ip string) {
	log.Debugf("gratuitous arp: %s is-at %s", ip, c.spoofed)
	if err := c.sendReply(ethernet.Broadcast, net.IPv4bcast, net.ParseIP(ip)); err != nil {
		log.Warnf("Failed sending arp for %s: %s", ip, err)
	}
}
