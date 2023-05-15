package main

type Information struct {
	Ip     string          `json:"ip"`
	Type   string          `json:"proto"`
	Method string          `json:"method"`
	Path   string          `json:"path"`
	TLS    *TLSInformation `json:"tls,omitempty"`
	HTTP   interface{}     `json:"http"`
}

type TLSInformation struct {
	Ciphers    []string          `json:"ciphers"`
	Extensions []string          `json:"extensions"`
	ALPN       []string          `json:"alpn"`
	Schemes    []SignatureStruct `json:"schemes"`
	Versions   []string          `json:"versions"`
	Curves     []string          `json:"curves"`
	Points     []int             `json:"points"`
	JA3        string            `json:"ja3"`
	JA3Hash    string            `json:"ja3_hash"`
}

type HTTP1Information struct {
	Header []string `json:"header"`
}

type HTTP2Information struct {
	AF     string        `json:"akamai_fingerprint"`
	AFH    string        `json:"akamai_fingerprint_hash"`
	Frames []interface{} `json:"frames"`
}

type Settings struct {
	Type     string   `json:"type"`
	Length   int      `json:"length"`
	ID       int      `json:"stream_id"`
	Settings []string `json:"settings"`
}

type WindowsUpdate struct {
	Type      string `json:"type"`
	Length    int    `json:"length"`
	ID        int    `json:"stream_id"`
	Increment int    `json:"increment"`
}

type Priorities struct {
	Type      string `json:"type"`
	Length    int    `json:"length"`
	ID        int    `json:"stream_id"`
	StreamDep int    `json:"stream_dep"`
	Exclusive bool   `json:"exclusive"`
	Weight    int    `json:"weight"`
}

type HTTP2Headers struct {
	Type    string   `json:"type"`
	Length  int      `json:"length"`
	ID      int      `json:"stream_id"`
	Headers []string `json:"headers"`
}
