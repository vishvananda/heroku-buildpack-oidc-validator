package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var cmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate oauth creds and proxy to subcommand",
	Long: `Validate outh creds and proxy to subcommand

Simple wrapper to validate oauth`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("specify subcommand")
		}
		return runValidate(args)
	},
}

type idToken struct {
	Issuer  string `json:"iss"`
}

func getIssuer(p string) (string, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 3 {
		return "", fmt.Errorf("malformed jwt, expected 3 parts got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("malformed jwt payload: %v", err)
	}

	var token idToken
	if err := json.Unmarshal(payload, &token); err != nil {
		log.Errorf("failed to unmarshal token: %v", err)
		return "", nil
	}
	return token.Issuer, nil
}


func getSub (ctx context.Context, auth string, conn connection) (string) {
	parts := strings.Fields(auth)
	log.Info("Start")
	if len(parts) != 2 {
		return ""
	}
	if parts[0] != "Bearer" {
		return ""
	}

	rawToken := parts[1]
	log.Info("Parsing")
	issuer, err := getIssuer(rawToken)


	if !conn.iss.MatchString(issuer) {
		log.Debugf("unmatched issuer: %v %v", issuer, conn)
		return ""
	}

	// TODO: cache providers
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Debugf("Failed to create provider: %v", err)
		return ""
	}

	var verifier = provider.Verifier(&oidc.Config{SkipClientIDCheck: true})

	token, err := verifier.Verify(ctx, rawToken)
	if err != nil {
		log.Errorf("Invalid token: %v", err)
		return ""
	}

	match := false
	for _, aud := range token.Audience {
		if conn.aud.MatchString(aud) {
			match = true
			break
		}
	}
	if !match {
		log.Debugf("unmatched audience: %v %v", token.Audience, conn)
		return ""
	}

	results := conn.sub.FindStringSubmatch(token.Subject)
	if results == nil {
		log.Debugf("unmatched subject: %v %v", token.Subject, conn)
		return ""
	}
	if len(results) > 1 {
		return results[1]
	} else {
		return token.Subject
	}
}

type connection struct {
	id string
	iss *regexp.Regexp
	aud *regexp.Regexp
	sub *regexp.Regexp
}

func getConnection(name, id string) (connection, error) {
	// default value will allow any heroku identities to connect
	base := "CONN_" + name
	conn := connection{id: id}
	var err error
	iss := "^https://oidc.heroku.com"
	if v, ok := os.LookupEnv(base+"_OIDC_ISS"); ok {
		iss = v
	}
	conn.iss, err = regexp.Compile(iss)
	if err != nil {
		return conn, err
	}
	aud := "^heroku$" // should probably be connured from HEROKU_APP_UUID
	if v, ok := os.LookupEnv(base+"_OIDC_AUD"); ok {
		aud = v
	}
	conn.aud, err = regexp.Compile(aud)
	if err != nil {
		return conn, err
	}
	sub := "^app:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\.[a-z0-9\\-]+::(?:dyno|run):[a-z0-9\\.]*$"
	if v, ok := os.LookupEnv(base+"_OIDC_SUB"); ok {
		sub = v
	}
	conn.sub, err = regexp.Compile(sub)
	if err != nil {
		return conn, err
	}
	os.Unsetenv(base+"_OIDC_ISS")
	os.Unsetenv(base+"_OIDC_AUD")
	os.Unsetenv(base+"_OIDC_SUB")
	return conn, nil
}


func runValidate(args []string) error {
	port := "8000"
	if p, ok := os.LookupEnv("PORT"); ok {
		port = p
	}

	subHeader := "X-Heroku-Conn-Sub"
	if v, ok := os.LookupEnv("VALIDATOR_SUB_HEADER"); ok {
		subHeader = v
	}

	idHeader := "X-Heroku-Conn-Id"
	if v, ok := os.LookupEnv("VALIDATOR_ID_HEADER"); ok {
		idHeader = v
	}

	idRe, err := regexp.Compile("^CONN_([A-Z0-9_]+)_ID=")
	if err != nil {
		log.Error(err)
		return err
	}

	conns := []connection{}
	for _, item := range os.Environ() {
		results := idRe.FindStringSubmatch(item)
		if results != nil {
			id := strings.SplitN(item, "=", 2)
			conn, err := getConnection(results[1], id[1])
			if err != nil {
				log.Error(err)
				return err
			}
			conns = append(conns, conn)
		}
	}


	subPort := "2000"
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(
		ctx,
		args[0],
		args[1:]...,
	)

	cmd.Env = append(os.Environ(), "PORT=" + subPort)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		log.Error(err)
		cancel()
		return err
	}

	log.Infof("Starting subcommand %s on :%s...", strings.Join(args, " "), subPort)
	go func() {
		if err := cmd.Wait(); err != nil {
			log.Error(err)
		}
		cancel()
	}()

	remote, err := url.Parse(fmt.Sprintf("http://localhost:%s", subPort))
	if err != nil {
		return err
	}

	handler := func(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
			return func(w http.ResponseWriter, r *http.Request) {
					log.Println(r.URL)
					r.Host = remote.Host
					auth := r.Header.Get("Authorization")
					r.Header.Del(idHeader)
					r.Header.Del(subHeader)
					for _, conn := range conns {
						sub := getSub(r.Context(), auth, conn)
						if sub != "" {
							r.Header.Set(idHeader, conn.id)
							r.Header.Set(subHeader, sub)
							break
						}
					}
					p.ServeHTTP(w, r)
			}
	}

	proxy := httputil.NewSingleHostReverseProxy(remote)
	http.HandleFunc("/", handler(proxy))

	srv := &http.Server{Addr: fmt.Sprintf(":%s", port), Handler: nil}
	go func() {
		<-ctx.Done()
		if err := srv.Shutdown(context.Background()); err != nil {
			log.Error(err)
		}
	}()
	log.Infof("Proxy Listening on :%s...", port)
	return srv.ListenAndServe()
}

const version = "0.1.0"

var log = logrus.WithFields(logrus.Fields{"version": version})

func init() {
	// TODO(vish): turn this into a global flag
	logrus.SetLevel(logrus.DebugLevel)
}

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
