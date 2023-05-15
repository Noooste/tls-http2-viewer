package main

import (
	"context"
	"encoding/json"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/simplecert"
	"github.com/Noooste/tlsconfig"
	"log"
	"os"
	"regexp"
	"time"
)

var numberReg = regexp.MustCompile(`/(\d+)$`)

type Config struct {
	Domain string `json:"domain"`
}

func main() {
	//load config.json
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Fatal(err)
	}
	defer configFile.Close()

	//decode config.json
	var config Config
	jsonParser := json.NewDecoder(configFile)
	jsonParser.Decode(&config)

	//handle
	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Location", "/get")
		res.WriteHeader(302)
	})

	http.HandleFunc("/get", showTLS)
	http.HandleFunc("/redirect/", redirectNTimes)
	http.HandleFunc("/delay/", delayResponse)
	http.HandleFunc("/cookie", getCookie)

	if config.Domain != "localhost" {
		startServerWithDomain(config.Domain)
	} else {
		startServer()
	}
}

func serve(ctx context.Context, srv *http.Server) {
	// lets go
	go func() {
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %+s\n", err)
		}
	}()

	log.Printf("server started")
	<-ctx.Done()
	log.Printf("server stopped")

	ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		cancel()
	}()

	err := srv.Shutdown(ctxShutDown)
	if err == http.ErrServerClosed {
		log.Printf("server exited properly")
	} else if err != nil {
		log.Printf("server encountered an error on exit: %+s\n", err)
	}
}

func startServerWithDomain(domain string) {
	go (&http.Server{
		Addr:         ":80",
		Handler:      nil,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}).ListenAndServe()

	var domains = []string{
		domain,
	}

	var (
		// the structure that handles reloading the certificate
		certReloader *simplecert.CertReloader
		err          error
		numRenews    int
		ctx, cancel  = context.WithCancel(context.Background())

		// init strict tlsConfig (this will enforce the use of modern TLS configurations)
		// you could use a less strict configuration if you have a customer facing web application that has visitors with old browsers
		tlsConf = tlsconfig.NewServerTLSConfig(tlsconfig.TLSModeServerStrict)
	)

	// a simple constructor for a http.Server with our Handler
	makeServer := func() *http.Server {
		return &http.Server{
			Addr:         ":443",
			Handler:      nil,
			TLSConfig:    tlsConf,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		}
	}

	// init server
	srv := makeServer()

	// init simplecert configuration
	cfg := simplecert.Default

	// configure
	cfg.Domains = domains

	cfg.CacheDir = "letsencrypt"
	cfg.SSLEmail = "no-email-please@sap.alice-and-bob.xyz"

	// this function will be called just before certificate renewal starts and is used to gracefully stop the service
	// (we need to temporarily free port 443 in order to complete the TLS challenge)
	cfg.WillRenewCertificate = func() {
		// stop server
		cancel()
	}

	// this function will be called after the certificate has been renewed, and is used to restart your service.
	cfg.DidRenewCertificate = func() {
		numRenews++

		// restart server: both context and server instance need to be recreated!
		ctx, cancel = context.WithCancel(context.Background())
		srv = makeServer()

		// force reload the updated cert from disk
		certReloader.ReloadNow()

		// here we go again
		go serve(ctx, srv)
	}

	// init simplecert configuration
	// this will block initially until the certificate has been obtained for the first time.
	// on subsequent runs, simplecert will load the certificate from the cache directory on disk.
	certReloader, err = simplecert.Init(cfg, func() {
		os.Exit(0)
	})

	if err != nil {
		log.Fatal("simplecert init failed: ", err)
	}

	// enable hot reload
	tlsConf.GetCertificate = certReloader.GetCertificateFunc()

	log.Println("server started on port " + srv.Addr)
	serve(ctx, srv)
	<-make(chan bool)
}

func startServer() {
	serv := &http.Server{
		Addr:         ":443",
		Handler:      nil,
		TLSConfig:    tlsconfig.NewServerTLSConfig(tlsconfig.TLSModeServerStrict),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	go func() {
		if err := serv.ListenAndServeTLS("security/fullchain.pem", "security/privkey.pem"); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %+s\n", err)
		}
	}()

	log.Printf("server started on port 443")
	<-make(chan bool)
}
