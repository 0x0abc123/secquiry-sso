package main

import (
	"os"
	"fmt"
	"time"
	"bytes"
	"errors"
	"crypto/rand"
	"encoding/base64"
	"io"
	"flag"
	"strings"
	"net/http"
        "encoding/json"
        "path/filepath"
        "log"
	"golang.org/x/oauth2"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/net/context"
)

const CONFIG_FILE_NAME string = "secquirysso.conf.json"

const htmlResponse string = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Logging in...</title>
<script>
	document.addEventListener("DOMContentLoaded", async function () {
	const qs = window.location.search;
	try {
		const response = await fetch("/sso/exchange"+qs);
		if (!response.ok) {
		throw new Error("HTTP error! Status: "+response.status);
		}
		const data = await response.json();
		const data_token = data.token;
		if (data_token) {
			localStorage.setItem("CoggedBearerToken", data_token);
			window.location.href = "/";
		} else if(data.error) {
			document.write(data.error)
		}
	} catch (error) {
		console.error("Error fetching token:", error);
	}
	});
</script>
</head>
<body>
<p>Logging in...</p>
</body>
</html>
`

const (
	loginApiPath = "/auth/login"
	userNameApiPath  = "/user/name"
	userPatchApiPath  = "/admin/users"
)

var (
	coggedHostPort = "http://localhost:8090"
)

var accountCredCache map[string]string

type GraphUser struct {

	Uid		string		`json:"uid"`
	DgraphType	[]string	`json:"dgraph.type,omitempty"`
	AuthzData	string		`json:"ad,omitempty"`
	Username	*string 	    `json:"un,omitempty"`
	PasswordHash 	*string 	    `json:"ph,omitempty"`
	Data 		*string 	    `json:"us,omitempty"`
	InternalData 	*string 	    `json:"intd,omitempty"`
	Role 		*string 	    `json:"role,omitempty"`
}

type UserResponse struct {
	User 	*GraphUser 	`json:"user"`
	Error 	string 		`json:"error,omitempty"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type TokenResponse struct {
	Token	string	`json:"token"`
	Expires	int	`json:"exp"`  // expires in N seconds
}

type CoggedResponse struct {
	CreatedUids	map[string]string	`json:"created_uids,omitempty"`
	ServerTime	*time.Time		`json:"timestamp"`
	Error		string			`json:"error,omitempty"`
}

type UsersRequest struct {
	Users *[]*GraphUser	`json:"users,omitempty"`
}

func postLogin(username, password string) (string,error) {
	// Create the login payload
	loginData := LoginRequest{
		Username: username,
		Password: password,
	}

	// Convert to JSON
	jsonData, err := json.Marshal(loginData)
	if err != nil {
		log.Printf("Error marshalling login data: %v", err)
		return "", err
	}

	// Make the login request
	resp, err := http.Post(coggedHostPort+loginApiPath, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error making login request: %v", err)
		return "", err
	}
	defer resp.Body.Close()

	// Parse login response
	var loginResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		log.Printf("Error decoding login response: %v", err)
		return "", err
	}

	return loginResp.Token, nil
}

func doCoggedLogin(conf *Config, username string) (string, error) {

	// try to login as user with cached creds
	password, userExists := accountCredCache[username]
	if userExists {
		token, err := postLogin(username, password)
		if err == nil {
			return token, nil
		}
	}
	token, err := postLogin(conf.Get("cogged.user"),conf.Get("cogged.pass"))
	if err != nil {
		log.Printf("Error logging into Cogged as SSO user: %v", err)
		return "", err
	}

	// Make authenticated request to /api/user/name
	req, err := http.NewRequest("GET", coggedHostPort+userNameApiPath+"/"+username, nil)
	if err != nil {
		log.Printf("Error creating request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	userResp, err := client.Do(req)
	if err != nil {
		log.Printf("Error making user request: %v", err)
	}
	defer userResp.Body.Close()

	if userResp.StatusCode != http.StatusOK {
		return "", errors.New("user does not exist")
	}

	// Parse user response
	var user UserResponse
	if err := json.NewDecoder(userResp.Body).Decode(&user); err != nil {
		log.Printf("Error decoding user response: %v", err)
	}

	fmt.Println("User:", user.User.Uid)

	newRandPassword, err := randString(40)
	if err != nil {
		log.Printf("Error generating random password: %v", err)
		return "", err
	}

	user.User.PasswordHash = &newRandPassword
	usersList := []*GraphUser{user.User}
	userPatchData := UsersRequest{
		Users: &usersList,
	}

	// Convert to JSON
	jsonData, err := json.Marshal(userPatchData)
	if err != nil {
		log.Printf("Error marshalling users patch data: %v", err)
		return "", err
	}

	req2, err := http.NewRequest("PATCH", coggedHostPort+userPatchApiPath, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error creating request: %v", err)
	}
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")

	//client := &http.Client{}
	userPatchResp, err := client.Do(req2)
	if err != nil {
		log.Printf("Error making user request: %v", err)
	}
	defer userPatchResp.Body.Close()

	if userPatchResp.StatusCode != http.StatusOK {
		return "", errors.New("failed updating user password")
	}

	accountCredCache[username] = newRandPassword
	token2, err := postLogin(username, newRandPassword)
	if err == nil {
		return token2, nil
	}
	//bodyBytes, err := io.ReadAll(userResp.Body)
	//fmt.Println(string(bodyBytes))

	return "", nil
}


type Config map[string]string

func (c *Config) Get(key string) string {
	return (*c)[key]
}

func LoadConfig(cliValue string) *Config {
	// CLI flag overrides other places
	configFilePath := cliValue 
	// try getting path from envionment variable if not from CLI flag
	if configFilePath == "" {
		configFilePath = os.Getenv("SECQUIRYSSO_CONFIG_FILE")
		if configFilePath == "" {
			// try current working directory
			configFilePath = workingDirectoryConfigPath()
			if !statFile(configFilePath) {
				// try exe directory
				configFilePath = exeDirectoryConfigPath()
				if !statFile(configFilePath) {
					panic("Could not load config file")
					return nil
				}
			}
			configFilePath = configFilePath
		}
	}
	confFile, err := os.ReadFile(configFilePath)
	if err != nil {
		panic(err)
	}

	var confData Config
	if err := json.Unmarshal(confFile, &confData); err != nil {
		panic(err)
	}
	return &confData
}

func statFile(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func exeDirectoryConfigPath() string {
	exePath, err := os.Executable()
	if err != nil {
		log.Println("Error getting executable path:", err)
		return ""
	}
	// Get the directory of the executable file
	exeDir := filepath.Dir(exePath)
	return exeDir + "/" + CONFIG_FILE_NAME
}

func workingDirectoryConfigPath() string {
	currentDir, err := os.Getwd()
	if err != nil {
		log.Println("Error getting current working directory:", err)
		return ""
	}
	return currentDir + "/" + CONFIG_FILE_NAME
}


func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}


type DefaultHandler struct {
    Conf    *Config
    Ctx      *context.Context
    OIDCProvider *oidc.Provider
    OIDCConfig   *oauth2.Config
    OIDCVerifier *oidc.IDTokenVerifier
}

func (h *DefaultHandler) ErrorResponse(code int, message string, w http.ResponseWriter, r *http.Request) {
	text := message
	if len(message) < 1 { text = http.StatusText(code) }
	http.Error(w, text, code)
}


func (h *DefaultHandler) OkResponse(jsonString string, w http.ResponseWriter) {
    w.Header().Set("Content-Type", "application/json; charset=utf-8")
    fmt.Fprintf(w, jsonString)
}

func (h *DefaultHandler) OkHtmlResponse(htmlString string, w http.ResponseWriter) {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    fmt.Fprintf(w, htmlString)
}

func CreateDefaultHandler(conf *Config) *DefaultHandler {
	ctx := context.Background()

        clientID := conf.Get("clientid")
        clientSecret := conf.Get("clientsecret")
        idpUrl := conf.Get("idpurl")
        redirectUrl := conf.Get("redirecturl")

	provider, err := oidc.NewProvider(ctx, idpUrl)
	if err != nil {
		log.Fatal(err)
	}
	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}
	verifier := provider.Verifier(oidcConfig)

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectUrl,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

    return &DefaultHandler{ Conf: conf, OIDCProvider: provider, OIDCConfig: &config, OIDCVerifier: verifier, Ctx: &ctx } 
}


func (h *DefaultHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSpace(r.URL.Path)

	if strings.HasPrefix(path, "/sso/callback") {
		h.OkHtmlResponse(htmlResponse, w)

	} else if strings.HasPrefix(path, "/sso/exchange") {
		state, err := r.Cookie("state")
		if err != nil {
			h.ErrorResponse(http.StatusBadRequest, "state not found", w, r)
			return
		}
		if r.URL.Query().Get("state") != state.Value {
			h.ErrorResponse(http.StatusBadRequest, "state did not match", w, r)
			return
		}

		oauth2Token, err := h.OIDCConfig.Exchange(*h.Ctx, r.URL.Query().Get("code"))
		if err != nil {
			h.ErrorResponse(http.StatusInternalServerError, "Failed to exchange token: "+err.Error(), w, r)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			h.ErrorResponse(http.StatusInternalServerError, "No id_token field in oauth2 token.", w, r)
			return
		}
		idToken, err := h.OIDCVerifier.Verify(*h.Ctx, rawIDToken)
		if err != nil {
			h.ErrorResponse(http.StatusInternalServerError, "Failed to verify ID Token: "+err.Error(), w, r)
			return
		}

		nonce, err := r.Cookie("nonce")
		if err != nil {
			h.ErrorResponse(http.StatusBadRequest, "nonce not found", w, r)
			return
		}
		if idToken.Nonce != nonce.Value {
			h.ErrorResponse(http.StatusBadRequest, "nonce did not match", w, r)
			return
		}


		var claims struct {
			Email    string `json:"email"`
			Verified bool   `json:"email_verified"`
		}
		if err := idToken.Claims(&claims); err != nil {
			h.ErrorResponse(http.StatusInternalServerError, err.Error(), w, r)
			return
		}
		data, err := doCoggedLogin(h.Conf, claims.Email)
		rd := fmt.Sprintf("{\"token\": \"%s\", \"error\":\"%s\"}",data,err)
		h.OkResponse(rd, w)

	} else if path == "/sso/" {
		state, err := randString(16)
		if err != nil {
			h.ErrorResponse(http.StatusInternalServerError, "internal error", w, r)
			return
		}
		nonce, err := randString(16)
		if err != nil {
			h.ErrorResponse(http.StatusInternalServerError, "internal error", w, r)
			return
		}
		setCallbackCookie(w, r, "state", state)
		setCallbackCookie(w, r, "nonce", nonce)

		http.Redirect(w, r, h.OIDCConfig.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
	} else {
		h.ErrorResponse(404, "not found", w, r)
	}

}

func main() {
	var flagListenPort int
	flag.IntVar(&flagListenPort, "p", 0, "TCP Port that SecquirySSO listens on (overrides config file)")
	
	var flagListenIP string
	flag.StringVar(&flagListenIP, "ip", "", "Interface that SecquirySSO binds to to listen for incoming connections (overrides config file)")

	var flagConfigFile string
	flag.StringVar(&flagConfigFile, "conf", "", "Full filesystem path to config file (JSON)")

	var flagCoggedHost string
	flag.StringVar(&flagCoggedHost, "ch", "", "URL for Cogged host eg. http://10.1.2.3 (overrides config file)")

	var flagCoggedPort string
	flag.StringVar(&flagCoggedPort, "cp", "", "URL for Cogged port eg. 8080 (overrides config file)")

	flag.Parse()

	conf := LoadConfig(flagConfigFile)

	envCoggedUser := os.Getenv("SECQUIRYSSO_CUSER")
	if conf.Get("cogged.user") == "" && envCoggedUser != "" {
		(*conf)["cogged.user"] = envCoggedUser
	}
	envCoggedPass := os.Getenv("SECQUIRYSSO_CPASS")
	if conf.Get("cogged.pass") == "" && envCoggedPass != "" {
		(*conf)["cogged.pass"] = envCoggedPass
	}

	if len(flagCoggedHost) > 0 {
		(*conf)["cogged.host"] = flagCoggedHost
	}
	if len(flagCoggedPort) > 0 {
		(*conf)["cogged.port"] = flagCoggedPort
	}

	_, coggedHostSet := (*conf)["cogged.host"]
	_, coggedPortSet := (*conf)["cogged.port"]
	if coggedHostSet {
		coggedHostPort = (*conf)["cogged.host"]
		if coggedPortSet {
			coggedHostPort = fmt.Sprintf("%s:%s",coggedHostPort,(*conf)["cogged.port"])
		}
	}

	accountCredCache = make(map[string]string)

	log.Println("secquiry-sso started, using config:", conf)

	dh := CreateDefaultHandler(conf)

	mux := http.NewServeMux()
	mux.Handle("/", dh)
	
	listenOn := ""
	if flagListenIP != "" {
		listenOn = flagListenIP
	} else {
		listenOn = conf.Get("listen.host")
	}

	lp := ":8091"
	if flagListenPort > 0 {
		lp = fmt.Sprintf(":%d",flagListenPort)
	} else if clp := conf.Get("listen.port"); clp != "" {
		lp = ":" + clp
	}
	listenOn += lp
	
	fmt.Printf("Cogged started and listening on %s\n",listenOn)
	http.ListenAndServe(listenOn, mux)
}
