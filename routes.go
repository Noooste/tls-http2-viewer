package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	http "github.com/Noooste/fhttp"
	"strconv"
	"time"
)

func redirect(path string, res http.ResponseWriter, req *http.Request) {
	res.Header().Add("Location", path)

	res.WriteHeader(302)
	_, _ = res.Write([]byte("302 Moved Temporarily"))
}

func sendUnknown(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(404)
	res.Write([]byte("Page not found !"))
}

func showTLS(res http.ResponseWriter, req *http.Request) {
	var response = Information{
		Type:   req.Proto,
		Method: req.Method,
		Path:   req.URL.Path,
	}

	if req.TLS != nil {
		clientHello := req.TLSConn.ClientHello
		eString, eValue := getExtensionsString(clientHello.Raw)

		response.TLS = &TLSInformation{
			Ciphers:    getCiphersString(clientHello.CipherSuites),
			Extensions: eString,
			Schemes:    getAlgoString(clientHello.SupportedSignatureAlgorithms),
			ALPN:       clientHello.AlpnProtocols,
			Versions:   getVersionsValues(clientHello.SupportedVersions),
			Curves:     getCurvesValues(clientHello.SupportedCurves),
			Points:     getPointsValues(clientHello.SupportedPoints),
		}
		response.TLS.JA3 = getJA3(req.TLS.Version, clientHello.CipherSuites, eValue, clientHello.SupportedCurves, clientHello.SupportedPoints)
		hash := md5.Sum([]byte(response.TLS.JA3))
		response.TLS.JA3Hash = hex.EncodeToString(hash[:])
		response.Ip = req.TLSConn.RemoteAddr().String()
	} else {
		response.Ip = req.RemoteAddr
	}

	switch req.Proto {
	case "HTTP/2.0":
		frames, af := parseHTTP2Frames(req)
		hash := md5.Sum([]byte(af))
		afh := hex.EncodeToString(hash[:])
		response.HTTP = &HTTP2Information{
			Frames: frames,
			AF:     af,
			AFH:    afh,
		}
	default:
		response.HTTP = &HTTP1Information{
			Header: getHTTP1Headers(req),
		}
	}

	h := res.Header()

	h.Add("content-type", "application/json")
	h.Add("Access-Control-Allow-Origin", "*")
	h.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

	if result, err := json.MarshalIndent(response, "", "  "); err == nil {
		res.Write(result)
	} else {
		res.Write([]byte("error"))
	}
}

func redirectNTimes(res http.ResponseWriter, req *http.Request) {
	var r = numberReg.FindStringSubmatch(req.URL.Path)

	if len(r) == 2 {
		value, _ := strconv.Atoi(r[1])
		if value > 1 {
			redirect("/redirect/"+strconv.Itoa(value-1), res, req)
		} else if value == 1 {
			redirect("/get", res, req)
		} else {
			sendUnknown(res, req)
		}
	} else {
		sendUnknown(res, req)
	}
}

func delayResponse(res http.ResponseWriter, req *http.Request) {
	var r = numberReg.FindStringSubmatch(req.URL.Path)

	if len(r) == 2 {
		value, _ := strconv.Atoi(r[1])
		time.Sleep(time.Duration(value) * time.Second)
		showTLS(res, req)
	} else {
		sendUnknown(res, req)
	}
}

func wrongValue(valueName, in string, res http.ResponseWriter, req *http.Request) {
	res.Write([]byte("wrong value in " + in + " : " + valueName))
	res.WriteHeader(400)

}

func getCookie(res http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()
	cookie := &http.Cookie{}

	if v := query.Get("name"); v != "" {
		cookie.Name = v
	} else {
		cookie.Name = "test-cookie"
	}

	if v := query.Get("value"); v != "" {
		cookie.Value = v
	} else {
		cookie.Value = "aaaa"
	}

	if v := query.Get("max-age"); v != "" {
		var l, err = strconv.Atoi(v)
		if err != nil {
			wrongValue("max-age", "query", res, req)
			return
		}
		cookie.MaxAge = l
	}

	cookie.Path = query.Get("path")
	cookie.Secure = query.Get("secure") == "true"
	cookie.Domain = query.Get("domain")
	cookie.HttpOnly = query.Get("http-only") == "true"
	cookie.Origin = query.Get("origin")

	res.Header().Set("set-cookie", (cookie).String())
}
