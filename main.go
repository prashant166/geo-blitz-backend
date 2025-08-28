package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	ip2location "github.com/ip2location/ip2location-go/v9"
	"github.com/oschwald/geoip2-golang"
)

type Geo struct {
	IP          string  `json:"ip"`
	CountryCode string  `json:"country_code,omitempty"`
	CountryName string  `json:"country_name,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Lat         float64 `json:"lat,omitempty"`
	Lon         float64 `json:"lon,omitempty"`
	ASN         uint    `json:"asn,omitempty"` // reserved for future (local ASN DB)
	Org         string  `json:"org,omitempty"` // reserved for future
	Source      string  `json:"source"`
	LookupMS    int64   `json:"lookup_ms"`
}

type Resolver interface {
	Resolve(ctx context.Context, ip netip.Addr) (*Geo, error)
	Name() string
}

type MaxMindProvider struct{ DB *geoip2.Reader }

func (m *MaxMindProvider) Name() string { return "maxmind" }

func (m *MaxMindProvider) Resolve(ctx context.Context, ip netip.Addr) (*Geo, error) {
	rec, err := m.DB.City(ip.AsSlice())
	if err != nil {
		return nil, err
	}
	if rec == nil || rec.Country.IsoCode == "" {
		return nil, errors.New("no data")
	}
	out := &Geo{
		IP:          ip.String(),
		CountryCode: rec.Country.IsoCode,
		CountryName: rec.Country.Names["en"],
		City:        rec.City.Names["en"],
		Source:      "maxmind",
	}
	if len(rec.Subdivisions) > 0 {
		out.Region = rec.Subdivisions[0].Names["en"]
	}
	out.Lat = rec.Location.Latitude
	out.Lon = rec.Location.Longitude
	return out, nil
}

type IP2LocationProvider struct{ DB *ip2location.DB }

func (p *IP2LocationProvider) Name() string { return "ip2location" }

func (p *IP2LocationProvider) Resolve(ctx context.Context, ip netip.Addr) (*Geo, error) {
	rec, err := p.DB.Get_all(ip.String())
	if err != nil {
		return nil, err
	}

	// can't check rec == nil (it's a value). Just validate required fields.
	if rec.Country_short == "" {
		return nil, errors.New("no data")
	}

	out := &Geo{
		IP:          ip.String(),
		CountryCode: rec.Country_short,
		CountryName: rec.Country_long,
		Region:      rec.Region,
		City:        rec.City,
		Lat:         float64(rec.Latitude),  // cast float32 -> float64
		Lon:         float64(rec.Longitude), // cast float32 -> float64
		Source:      "ip2location",
	}
	return out, nil
}

type Chain struct {
	Providers []Resolver
	Cache     *lru.Cache[string, *Geo]
}

func (c *Chain) Resolve(ctx context.Context, ip netip.Addr) (*Geo, error) {
	key := ip.String()
	if c.Cache != nil {
		if v, ok := c.Cache.Get(key); ok && v != nil {
			clone := *v
			return &clone, nil
		}
	}
	var lastErr error
	for _, p := range c.Providers {
		start := time.Now()
		res, err := p.Resolve(ctx, ip)
		if err == nil && res != nil && res.CountryCode != "" {
			res.LookupMS = time.Since(start).Milliseconds()
			if c.Cache != nil {
				c.Cache.Add(key, res)
			}
			return res, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no provider returned data")
	}
	return nil, lastErr
}

var (
	chain *Chain
	cfg   Config
)

type Config struct {
	Addr            string
	MMDBPath        string
	IP2LPath        string
	TrustXFF        bool
	AllowPrivateIPs bool
	CacheSize       int
	ReqTimeoutMS    int
}

func main() {
	cfg = loadConfig()

	var providers []Resolver

	if cfg.MMDBPath != "" {
		db, err := geoip2.Open(cfg.MMDBPath)
		if err != nil {
			log.Fatalf("open maxmind: %v", err)
		}
		defer db.Close()
		providers = append(providers, &MaxMindProvider{DB: db})
		log.Printf("MaxMind ready: %s", cfg.MMDBPath)
	}
	if cfg.IP2LPath != "" {
		db, err := ip2location.OpenDB(cfg.IP2LPath)
		if err != nil {
			log.Fatalf("open ip2location: %v", err)
		}
		defer db.Close()
		providers = append(providers, &IP2LocationProvider{DB: db})
		log.Printf("IP2Location ready: %s", cfg.IP2LPath)
	}
	if len(providers) == 0 {
		log.Fatal("no providers configured (set MMDB_PATH and/or IP2L_BIN_PATH)")
	}

	var cache *lru.Cache[string, *Geo]
	if cfg.CacheSize > 0 {
		c, _ := lru.New[string, *Geo](cfg.CacheSize)
		cache = c
	}
	chain = &Chain{Providers: providers, Cache: cache}

	http.HandleFunc("/geo", handleGeo)
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              cfg.Addr,
		ReadHeaderTimeout: 2 * time.Second,
	}
	log.Printf("listening on %s", cfg.Addr)
	log.Fatal(srv.ListenAndServe())
}

func handleGeo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	ctx := r.Context()
	if cfg.ReqTimeoutMS > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(cfg.ReqTimeoutMS)*time.Millisecond)
		defer cancel()
	}

	ip, err := detectClientIP(r, cfg.TrustXFF)
	if err != nil {
		http.Error(w, `{"error":"invalid or missing ip"}`, http.StatusBadRequest)
		return
	}
	if !cfg.AllowPrivateIPs && !isPublic(ip) {
		http.Error(w, `{"error":"private or reserved ip not allowed"}`, http.StatusBadRequest)
		return
	}

	start := time.Now()
	res, err := chain.Resolve(ctx, ip)
	if err != nil {
		http.Error(w, `{"error":"lookup failed: `+escapeJSON(err.Error())+`"}`, http.StatusBadGateway)
		return
	}
	res.LookupMS = time.Since(start).Milliseconds()
	json.NewEncoder(w).Encode(res)
}

func detectClientIP(r *http.Request, trustXFF bool) (netip.Addr, error) {
	// 1) explicit ?ip=
	if raw := r.URL.Query().Get("ip"); raw != "" {
		if ip, ok := parseIP(raw); ok {
			return ip, nil
		}
		return netip.Addr{}, errors.New("invalid ip in query")
	}
	// 2) optionally trust X-Forwarded-For (left-most)
	if trustXFF {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip, ok := parseIP(strings.TrimSpace(parts[0])); ok {
				return ip, nil
			}
		}
	}
	// 3) X-Real-IP
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		if ip, ok := parseIP(strings.TrimSpace(xr)); ok {
			return ip, nil
		}
	}
	// 4) RemoteAddr
	host, _, _ := strings.Cut(r.RemoteAddr, ":")
	if ip, ok := parseIP(host); ok {
		return ip, nil
	}
	return netip.Addr{}, errors.New("cannot determine client ip")
}

func parseIP(s string) (netip.Addr, bool) {
	if ip, err := netip.ParseAddr(s); err == nil {
		return ip, true
	}
	if p := net.ParseIP(s); p != nil {
		if ip, ok := netip.AddrFromSlice(p); ok {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

func isPublic(ip netip.Addr) bool {
	// loopback, link-local, unspecified
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip.Is4() {
		v4 := ip.As4()
		if v4[0] == 10 { // 10.0.0.0/8
			return false
		}
		if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 { // 172.16/12
			return false
		}
		if v4[0] == 192 && v4[1] == 168 { // 192.168/16
			return false
		}
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 { // 100.64/10 CGNAT
			return false
		}
		if v4[0] == 169 && v4[1] == 254 { // 169.254/16
			return false
		}
	}
	if ip.Is6() {
		b := ip.As16()
		// fc00::/7 (ULA)
		if b[0]&0xfe == 0xfc {
			return false
		}
		// fe80::/10 (link-local)
		if b[0] == 0xfe && (b[1]&0xc0) == 0x80 {
			return false
		}
	}
	return true
}

func loadConfig() Config {
	addr := getenv("ADDR", ":8080")
	mmdb := os.Getenv("MMDB_PATH")
	ip2l := os.Getenv("IP2L_BIN_PATH")
	trustXFF := getenvBool("TRUST_XFF", false)
	allowPriv := getenvBool("ALLOW_PRIVATE_IPS", false)
	cacheSize := getenvInt("CACHE_SIZE", 200000)
	reqTOms := getenvInt("REQ_TIMEOUT_MS", 80)

	return Config{
		Addr:            addr,
		MMDBPath:        mmdb,
		IP2LPath:        ip2l,
		TrustXFF:        trustXFF,
		AllowPrivateIPs: allowPriv,
		CacheSize:       cacheSize,
		ReqTimeoutMS:    reqTOms,
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

func getenvBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		switch strings.ToLower(v) {
		case "1", "true", "yes", "y", "on":
			return true
		case "0", "false", "no", "n", "off":
			return false
		}
	}
	return def
}

func escapeJSON(s string) string {
	b, _ := json.Marshal(s)
	if len(b) >= 2 && b[0] == '"' && b[len(b)-1] == '"' {
		return string(b[1 : len(b)-1])
	}
	return s
}
