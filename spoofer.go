package main

import (
	"bytes"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/raw"
	log "github.com/sirupsen/logrus"
)

// protocolARP is the uint16 EtherType representation of ARP (Address
// Resolution Protocol, RFC 826).
const protocolARP = 0x0806

type Spoofer struct {
	c       *arp.Client
	p       *raw.Conn
	spoofed net.HardwareAddr
	mine    net.HardwareAddr
	lock    sync.RWMutex
	ips     map[string]net.IP
	qLock   sync.RWMutex
	qIps    map[string]time.Time
	grace   time.Duration
}

func NewSpoofer(ifName, macS string, grace time.Duration) (*Spoofer, error) {
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

	ips := make(map[string]net.IP)
	querriedIps := make(map[string]time.Time)

	return &Spoofer{
		c:       c,
		p:       p,
		spoofed: mac,
		mine:    ifi.HardwareAddr,
		ips:     ips,
		qIps:    querriedIps,
		grace:   grace,
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
	// handle Reply
	if req.Operation == arp.OperationReply {
		// if we were asked for this IP, lets dropp it from the queing list. if we see a reply that means that IP lives here in my network version
		c.DelQIp(req.SenderIP)
		return
	}

	// Ignore ARP requests which are not broadcast
	// do I need this?
	if !bytes.Equal(eth.Destination, ethernet.Broadcast) {
		log.Tracef("arp request but not broadcast: %s %s %s", req.SenderHardwareAddr, req.SenderIP, req.TargetIP)
		//return
	}

	log.Tracef("   request: who-has %s?  tell %s (%s)", req.TargetIP, req.SenderIP, req.SenderHardwareAddr)

	// check if we recently checked for this IP already, only bother if we havn't checked in the past second
	// we may need this to prevent amplification attacks? maybe I'm overthinking...
	//if t, exists := c.GetQIp(req.TargetIP); !exists || time.Since(t) > time.Second {

	if err := c.c.Request(req.TargetIP); err == nil {
		c.AddQIp(req.TargetIP)
	} else {
		log.Warnf("failed to send arp request for %s", req.TargetIP)
	}

	// only proxy ARP requests for IPs we are supposed to handle

	// ip statically configured?
	if c.CheckIp(req.TargetIP) {
		log.Tracef("spoofing due to static list: %s", req.TargetIP)
		if err := c.sendReply(req.SenderHardwareAddr, req.SenderIP, req.TargetIP); err != nil {
			log.Warnf("failed sending arp reply: %s", err)
		}
		return
	}

	// send reply if IP has been seen before, querried for and not heard a response since graceperiod
	if t, exists := c.GetQIp(req.TargetIP); exists && c.grace > 0 {
		if time.Since(t) > c.grace {
			log.Tracef("spoofing due to dynamic list: %s", req.TargetIP)
			if err := c.sendReply(req.SenderHardwareAddr, req.SenderIP, req.TargetIP); err != nil {
				log.Warnf("failed sending arp reply: %s", err)
			}
			return
		}
	}
}

func (c *Spoofer) GetQIp(ip net.IP) (time.Time, bool) {
	c.qLock.RLock()
	defer c.qLock.RUnlock()
	t, e := c.qIps[ip.String()]
	return t, e
}

func (c *Spoofer) DelQIp(ip net.IP) {
	if _, exists := c.GetQIp(ip); exists {
		log.Tracef("removing from querryIPs: %s", ip)
		c.qLock.Lock()
		delete(c.qIps, ip.String())
		c.qLock.Unlock()
	}
}

func (c *Spoofer) AddQIp(ip net.IP) {
	if _, exists := c.GetQIp(ip); !exists {
		log.Tracef("adding to querryIPs: %s", ip)
		c.qLock.Lock()
		c.qIps[ip.String()] = time.Now()
		c.qLock.Unlock()
	}
}

/*
func (c *Spoofer) GetAllIPs() []net.IP {
	c.lock.RLock()
	var ips []net.IP
	for _, i := range c.ips {
		ips = append(ips, i)
	}
	c.lock.RUnlock()
	return ips
}
*/

func (c *Spoofer) CheckIp(ip net.IP) bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	_, exists := c.ips[ip.String()]
	return exists
}

func (c *Spoofer) SetIPs(ips *map[string]net.IP) {
	c.lock.Lock()
	c.ips = *ips
	c.lock.Unlock()
}

func (c *Spoofer) sendReply(dstMac net.HardwareAddr, dstIP, srcIP net.IP) error {
	log.Debugf("     reply: %s: %s is-at %s", dstIP, srcIP, c.spoofed)
	p, err := arp.NewPacket(arp.OperationReply, c.spoofed, srcIP, dstMac, dstIP)
	if err != nil {
		return err
	}

	pb, err := p.MarshalBinary()
	if err != nil {
		return err
	}

	f := &ethernet.Frame{
		Destination: dstMac,
		Source:      c.mine,
		EtherType:   ethernet.EtherTypeARP,
		Payload:     pb,
	}

	fb, err := f.MarshalBinary()
	if err != nil {
		return err
	}

	_, err = c.p.WriteTo(fb, &raw.Addr{HardwareAddr: dstMac})
	return err
}

func (c *Spoofer) sendGratuitous(timer time.Duration) {
	for {
		select {
		case <-time.After(timer):
		}

		c.lock.RLock()
		for _, ip := range c.ips {
			log.Debugf("gratuitous: %s is-at %s", ip, c.spoofed)
			if err := c.sendReply(ethernet.Broadcast, net.IPv4bcast, ip); err != nil {
				log.Warnf("Failed sending arp for %s: %s", ip, err)
			}
		}
		c.lock.RUnlock()

		answer := []net.IP{}
		notAnswer := []string{}

		c.qLock.RLock()
		for ip, t := range c.qIps {
			if time.Since(t) > c.grace {
				answer = append(answer, net.ParseIP(ip))
			} else {
				notAnswer = append(notAnswer, ip)
			}
		}
		log.Tracef("dynamic IPs handled: %v", answer)
		log.Tracef("dynamic IPs not handled: %v", notAnswer)
		c.qLock.RUnlock()
	}
}
