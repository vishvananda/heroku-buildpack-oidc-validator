package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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


func getAppId (ctx context.Context, auth string, config extractConfig) (string) {
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


	// TODO: switch to regex
	if !config.issuer.MatchString(issuer) {
		log.Errorf("invalid issuer: %v", issuer)
		return ""
	}

	// TODO: cache provider locally
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Errorf("Failed to create provider: %v", err)
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
		if config.audience.MatchString(aud) {
			match = true
			break
		}
	}
	if !match {
		log.Errorf("invalid audience: %v", token.Audience)
		return ""
	}

	results := config.subject.FindStringSubmatch(token.Subject)
	if results == nil || len(results) != 2 {
		log.Errorf("invalid subject: %v", token.Subject)
		return ""
	}
	return results[1]
}

type extractConfig struct {
	issuer *regexp.Regexp
	audience *regexp.Regexp
	subject *regexp.Regexp
}

func getRegexConfig() (extractConfig, error) {
	config := extractConfig{}
	var err error
	issuer := "^https://oidc.heroku.com"
	if v, ok := os.LookupEnv("VALIDATOR_ISSUER_REGEX"); ok {
		issuer = v
	}
	config.issuer, err = regexp.Compile(issuer)
	if err != nil {
		return config, err
	}
	audience := "^heroku$" // should probably be configured from HEROKU_APP_UUID
	if v, ok := os.LookupEnv("VALIDATOR_AUDIENCE_REGEX"); ok {
		audience = v
	}
	config.audience, err = regexp.Compile(audience)
	if err != nil {
		return config, err
	}
	subject := "^app:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\.[a-z0-9\\-]+::(?:dyno|run):[a-z0-9\\.]*$"
	if v, ok := os.LookupEnv("VALIDATOR_SUBJECT_REGEX"); ok {
		subject = v
	}
	config.subject, err = regexp.Compile(subject)
	if err != nil {
		return config, err
	}
	if config.subject.NumSubexp() < 1 {
		return config, errors.New("Must specify a match group for subject")
	}
	return config, nil
}

func runValidate(args []string) error {
	port := "8000"
	if p, ok := os.LookupEnv("PORT"); ok {
		port = p
	}

	headerName := "X-Heroku-App-Id"
	if v, ok := os.LookupEnv("VALIDATOR_HEADER_NAME"); ok {
		headerName = v
	}

	config, err := getRegexConfig()
	if err != nil {
		log.Error(err)
		return err
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
					appId := getAppId(r.Context(), auth, config)
					if appId == "" {
						r.Header.Del(headerName)
					} else {
						r.Header.Set(headerName, appId)
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
