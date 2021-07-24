package main

import (
	//"bytes"
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

	if grace < 0 {
		log.Info("auto-detect arp spoofing disabled")
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
	// Ignore ARP requests which are not broadcast
	// do I need this? this was part of upstream arpproxy example, but I think I need to skip this since I wanna catch as many arps as possible
	/*
		if !bytes.Equal(eth.Destination, ethernet.Broadcast) {
			log.Tracef("arp request but not broadcast: %s %s %s", req.SenderHardwareAddr, req.SenderIP, req.TargetIP)
			return
		}
	*/

	// spoofing arps for statically configured IPs
	if req.Operation == arp.OperationRequest && c.CheckIp(req.TargetIP) {
		log.Tracef("static  spoofing %v for %v/%v", req.TargetIP, req.SenderIP, req.SenderHardwareAddr)
		if err := c.sendReply(req.SenderHardwareAddr, req.SenderIP, req.TargetIP); err != nil {
			log.Warnf("failed sending arp reply: %s", err)
		}
		return
	}

	// spoofing arps for dynamically learned macs that don't seem to be local (aka, do not answer arps)
	if c.grace > 0 {
		c.handleArpDynamic(req, eth)
		return
	}
	log.Tracef("not handling arp packet for %v", req.TargetIP)
}

func (c *Spoofer) handleArpDynamic(req *arp.Packet, eth *ethernet.Frame) {
	// if arp reply and remove the IP in question from potential spoofing candidate. if rely shows up clearly its not in a different network
	if req.Operation == arp.OperationReply {
		c.DelQIp(req.SenderIP)
		return
	}

	// check for IP in dynamic DB
	t, exists := c.GetQIp(req.TargetIP)

	// did I recently check this IP already? and if so, how long ago
	// we may need this to prevent amplification attacks? maybe I'm overthinking...
	// in other words I only wanna send out an arp request for a specific IP at most every grace period/2 intervals -> which may already be kinda agressive
	// if I didn't check for this IP yet at all - or I already heard back from it - check it again
	if !exists || time.Since(t) > c.grace/2 {
		if err := c.c.Request(req.TargetIP); err == nil {
			c.AddQIp(req.TargetIP)
		} else {
			log.Warnf("failed to send arp request for %s, not qualifying for spoofing", req.TargetIP)
			return
		}
	}

	// only proxy ARP requests for IPs we are supposed to handle
	// in this case qualifying auto-detected IPs. aka IPs that have not answered my own arps for time of "grace period"
	if exists && time.Since(t) > c.grace {
		log.Tracef("dynamic spoofing %v for %v/%v", req.TargetIP, req.SenderIP, req.SenderHardwareAddr)
		if err := c.sendReply(req.SenderHardwareAddr, req.SenderIP, req.TargetIP); err != nil {
			log.Warnf("failed sending arp reply: %s", err)
		}
		return
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
		log.Tracef("removing: %s", ip)
		c.qLock.Lock()
		delete(c.qIps, ip.String())
		c.qLock.Unlock()
	}
}

func (c *Spoofer) AddQIp(ip net.IP) {
	if _, exists := c.GetQIp(ip); !exists {
		log.Tracef("tracking: %s", ip)
		c.qLock.Lock()
		c.qIps[ip.String()] = time.Now()
		c.qLock.Unlock()
	}
}

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
			log.Debugf("gratuitous for static: %s is-at %s", ip, c.spoofed)
			if err := c.sendReply(ethernet.Broadcast, net.IPv4bcast, ip); err != nil {
				log.Warnf("Failed sending arp for %s: %s", ip, err)
			}
		}
		c.lock.RUnlock()

		if c.grace > 0 {
			ipsAnnounce := []net.IP{}
			c.qLock.RLock()
			for ip, t := range c.qIps {
				if time.Since(t) > c.grace {
					ipsAnnounce = append(ipsAnnounce, net.ParseIP(ip))
				}
			}
			c.qLock.RUnlock()

			for _, ip := range ipsAnnounce {
				log.Debugf("gratuitous for dynamic: %s is-at %s", ip, c.spoofed)
				if err := c.sendReply(ethernet.Broadcast, net.IPv4bcast, ip); err != nil {
					log.Warnf("Failed sending arp for %s: %s", ip, err)
				}
			}
		}
	}
}
