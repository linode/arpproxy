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
	ips     *[]net.IP
	lock    sync.RWMutex
}

func NewSpoofer(ifName, macS string) (*Spoofer, error) {
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

	return &Spoofer{
		c:       c,
		p:       p,
		spoofed: mac,
		mine:    ifi.HardwareAddr,
		ips:     &[]net.IP{},
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
	// Ignore ARP replies
	if req.Operation != arp.OperationRequest {
		return
	}

	// Ignore ARP requests which are not broadcast
	if !bytes.Equal(eth.Destination, ethernet.Broadcast) {
		return
	}

	log.Tracef("   request: who-has %s?  tell %s (%s)", req.TargetIP, req.SenderIP, req.SenderHardwareAddr)

	// only proxy ARP requests for IPs we are supposed to handle
	c.lock.RLock()
	currentIps := *c.ips
	c.lock.RUnlock()

	for _, ip := range currentIps {
		if req.TargetIP.Equal(ip) {
			if err := c.sendReply(req.SenderHardwareAddr, req.SenderIP, req.TargetIP); err != nil {
				log.Warnf("failed sending arp reply: %v", err)
				break
			}
		}
	}
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
		currentIps := *c.ips
		c.lock.RUnlock()

		for _, ip := range currentIps {
			log.Debugf("gratuitous: %s is-at %s", ip, c.spoofed)
			if err := c.sendReply(ethernet.Broadcast, net.IPv4bcast, ip); err != nil {
				log.Warnf("Failed sending arp for %v: %v", ip, err)
			}
		}
	}
}

func (c *Spoofer) updateIps(newIps *[]net.IP) {
	c.lock.Lock()
	c.ips = newIps
	c.lock.Unlock()
}
