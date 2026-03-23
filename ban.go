package main

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type IPBan struct {
	mu          sync.RWMutex
	triggers    map[string][]time.Time
	banned      map[string]bool
	window      time.Duration
	maxTriggers int
	logger      *Logger
}

func NewIPBan(window time.Duration, maxTriggers int, logger *Logger) *IPBan {
	ib := &IPBan{
		triggers:    make(map[string][]time.Time),
		banned:      make(map[string]bool),
		window:      window,
		maxTriggers: maxTriggers,
		logger:      logger,
	}
	go ib.cleanup()
	return ib
}

func (ib *IPBan) IsBanned(ip net.IP) bool {
	ib.mu.RLock()
	defer ib.mu.RUnlock()
	return ib.banned[ip.String()]
}

func (ib *IPBan) Trigger(ip net.IP) bool {
	ib.mu.Lock()
	defer ib.mu.Unlock()
	ipStr := ip.String()
	now := time.Now()
	ib.triggers[ipStr] = append(ib.triggers[ipStr], now)

	var recent []time.Time
	for _, t := range ib.triggers[ipStr] {
		if now.Sub(t) <= ib.window {
			recent = append(recent, t)
		}
	}
	ib.triggers[ipStr] = recent

	if len(recent) >= ib.maxTriggers {
		ib.banned[ipStr] = true
		ib.logger.Event(LOG_WARNING, "ban", fmt.Sprintf("IP %s banned for %d triggers in %v", ipStr, len(recent), ib.window))
		return true // banned
	}
	return false
}

func (ib *IPBan) cleanup() {
	for {
		time.Sleep(ib.window)
		ib.mu.Lock()
		now := time.Now()
		for ip, times := range ib.triggers {
			var recent []time.Time
			for _, t := range times {
				if now.Sub(t) <= ib.window {
					recent = append(recent, t)
				}
			}
			if len(recent) == 0 {
				delete(ib.triggers, ip)
				if ib.banned[ip] {
					delete(ib.banned, ip)
					ib.logger.Event(LOG_INFO, "ban", fmt.Sprintf("IP %s unbanned", ip))
				}
			} else {
				ib.triggers[ip] = recent
			}
		}
		ib.mu.Unlock()
	}
}
