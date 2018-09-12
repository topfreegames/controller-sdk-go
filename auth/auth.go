// Package auth handles user management: creation, deletion, and authentication.
package auth

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"

	deis "github.com/deis/controller-sdk-go"
	"github.com/deis/controller-sdk-go/api"
)

// Register a new user with the controller.
// If controller registration is set to administrators only, a valid administrative
// user token is required in the client.
func Register(c *deis.Client, username, password, email string) error {
	user := api.AuthRegisterRequest{Username: username, Password: password, Email: email}
	body, err := json.Marshal(user)

	if err != nil {
		return err
	}

	res, err := c.Request("POST", "/v2/auth/register/", body)
	if err == nil {
		res.Body.Close()
	}
	return err
}

func openBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
		url = strings.Replace(url, "&", "^&", -1)
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}

func getGoogleAuthGrabCodeURL(c *deis.Client) (string, error) {
	res, reqErr := c.Request("GET", "/google_auth/code_url", []byte(""))
	if reqErr != nil && !deis.IsErrAPIMismatch(reqErr) {
		return "", reqErr
	}
	defer res.Body.Close()
	codeURL := api.CodeURLResponse{}
	if err := json.NewDecoder(res.Body).Decode(&codeURL); err != nil {
		return "", err
	}
	return codeURL.CodeURL, nil
}

func exchangeCodeForAccessToken(c *deis.Client, code string) (string, string, error) {
	exchangeCodeURL := fmt.Sprintf("/google_auth/authenticate/?code=%s", code)
	res, reqErr := c.Request("POST", exchangeCodeURL, []byte(""))
	if reqErr != nil && !deis.IsErrAPIMismatch(reqErr) {
		return "", "", reqErr
	}
	defer res.Body.Close()
	token := api.AuthLoginResponse{}
	if err := json.NewDecoder(res.Body).Decode(&token); err != nil {
		return "", "", err
	}
	return token.Token, token.Email, nil

}

// GoogleAuthLogin logins the user to the controller using google auth
func GoogleAuthLogin(c *deis.Client) (string, string, error) {
	codeURL, err := getGoogleAuthGrabCodeURL(c)
	if err != nil {
		return "", "", err
	}
	if err := openBrowser(codeURL); err != nil {
		return "", "", err
	}
	l, err := net.Listen("tcp", ":57654")

	if err != nil {
		return "", "", err
	}
	code, err := func() (string, error) {
		var code string
		var err error
		http.HandleFunc("/google_auth/complete", func(w http.ResponseWriter, r *http.Request) {
			if c, ok := r.URL.Query()["code"]; ok {
				code = c[0]
				err = nil
				fmt.Fprintf(w, "you are logged in! now go back to the cli.")
				l.Close()
			} else {
				code = ""
				err = fmt.Errorf("couldn't get user authentication token")
				fmt.Fprintf(w, "failed to authenticate :/")
				l.Close()
			}
		})
		fmt.Println("Go login into your google account in the browser... waiting for callback...")
		http.Serve(l, nil)
		return code, err
	}()
	if err != nil {
		return "", "", err
	}
	return exchangeCodeForAccessToken(c, code)
}

// Login to the controller and get a token
func Login(c *deis.Client, username, password string) (string, error) {
	user := api.AuthLoginRequest{Username: username, Password: password}
	reqBody, err := json.Marshal(user)

	if err != nil {
		return "", err
	}

	res, reqErr := c.Request("POST", "/v2/auth/login/", reqBody)
	if reqErr != nil && !deis.IsErrAPIMismatch(reqErr) {
		return "", reqErr
	}
	defer res.Body.Close()

	token := api.AuthLoginResponse{}
	if err = json.NewDecoder(res.Body).Decode(&token); err != nil {
		return "", err
	}

	return token.Token, reqErr
}

// Delete deletes a user.
func Delete(c *deis.Client, username string) error {
	var body []byte
	var err error

	if username != "" {
		req := api.AuthCancelRequest{Username: username}
		body, err = json.Marshal(req)

		if err != nil {
			return err
		}
	}

	res, err := c.Request("DELETE", "/v2/auth/cancel/", body)
	if err == nil {
		res.Body.Close()
	}
	return err
}

// Regenerate auth tokens. This invalidates existing tokens, and if targeting a specific user
// returns a new token.
//
// If username is an empty string and all is false, this regenerates the
// client user's token and will return a new token. Make sure to update the client token
// with this new token to avoid authentication errors.
//
// If username is set and all is false, this will regenerate that user's token
// and return a new token. If not targeting yourself, regenerate requires administrative privileges.
//
// If all is true, this will regenerate every user's token. This requires administrative privileges.
func Regenerate(c *deis.Client, username string, all bool) (string, error) {
	var reqBody []byte
	var err error

	if all {
		reqBody, err = json.Marshal(api.AuthRegenerateRequest{All: all})
	} else if username != "" {
		reqBody, err = json.Marshal(api.AuthRegenerateRequest{Name: username})
	}

	if err != nil {
		return "", err
	}

	res, reqErr := c.Request("POST", "/v2/auth/tokens/", reqBody)
	if reqErr != nil && !deis.IsErrAPIMismatch(reqErr) {
		return "", reqErr
	}
	defer res.Body.Close()

	if all {
		return "", nil
	}

	token := api.AuthRegenerateResponse{}
	if err = json.NewDecoder(res.Body).Decode(&token); err != nil {
		return "", err
	}

	return token.Token, reqErr
}

// Passwd changes a user's password.
//
// If username if an empty string, change the password of the client's user.
//
// If username is set, change the password of another user and do not require
// their password. This requires administrative privileges.
func Passwd(c *deis.Client, username, password, newPassword string) error {
	req := api.AuthPasswdRequest{Password: password, NewPassword: newPassword}

	if username != "" {
		req.Username = username
	}

	body, err := json.Marshal(req)

	if err != nil {
		return err
	}

	res, err := c.Request("POST", "/v2/auth/passwd/", body)
	if err == nil {
		res.Body.Close()
	}
	return err
}

// Whoami retrives the user object for the authenticated user.
func Whoami(c *deis.Client) (api.User, error) {
	res, err := c.Request("GET", "/v2/auth/whoami/", nil)
	if err != nil {
		return api.User{}, err
	}
	defer res.Body.Close()

	resUser := api.User{}
	if err = json.NewDecoder(res.Body).Decode(&resUser); err != nil {
		return api.User{}, err
	}

	return resUser, nil
}
