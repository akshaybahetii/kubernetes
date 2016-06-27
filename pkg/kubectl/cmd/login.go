package cmd

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/spf13/cobra"

	"k8s.io/kubernetes/pkg/client/restclient"
	"k8s.io/kubernetes/pkg/client/unversioned/clientcmd"
	clientcmdapi "k8s.io/kubernetes/pkg/client/unversioned/clientcmd/api"
	cmdutil "k8s.io/kubernetes/pkg/kubectl/cmd/util"
)

func NewCmdLogin(f *cmdutil.Factory, configAccess clientcmd.ConfigAccess, cmdIn io.Reader, cmdOut, cmdErr io.Writer) *cobra.Command {
	//func NewCmdLogin(f *cmdutil.Factory, pathOptions *clientcmd.PathOptions, out io.Writer) *cobra.Command {

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Login using specific command",
		Long:  `login obtains the neccesary credentials to make authenticated requests to the cluster. The type depends on the subcommand used.`,

		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
	cmd.AddCommand(NewCmdLDAPLogin(f, configAccess, cmdIn, cmdOut, cmdErr))

	return cmd

}

// handleAuthResponse takes an open response and handles the codes that may come
// back. It returns either an access token or an error.
/*func handleAuthResponse(resp *http.Response) (string, error) {
	n := atomic.AddInt32(&dumpcounter, 1)
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		type successResponse struct {
			AccessToken string `json:"access_token"`
		}

		var token *successResponse
		if err := json.Unmarshal(b, &token); err != nil {
			return "", errors.New("no token received")
		}

		if token.AccessToken == "" {
			return "", errors.New("no token received")
		}

		return token.AccessToken, nil
	default:
		var apiErr *httpapi.ApiError
		if err := json.Unmarshal(b, &apiErr); err != nil {
			return "", handlePlaintextError(resp.Status, b)
		}

		return "", apiErr
	}
}
*/
func NewCmdLDAPLogin(f *cmdutil.Factory, configAccess clientcmd.ConfigAccess, cmdIn io.Reader, cmdOut, cmdErr io.Writer) *cobra.Command {
	options := &LDAPOptions{
		In:           cmdIn,
		Out:          cmdOut,
		Err:          cmdErr,
		configAccess: configAccess,
	}

	cmd := &cobra.Command{
		Use:   "ldap",
		Short: "Login with LDAP credentials",
		Long:  `Login with LDAP cn and password.`,

		Run: func(cmd *cobra.Command, args []string) {
			err := options.RunLDAPLogin(cmdOut, cmdIn, cmd, f)
			cmdutil.CheckErr(err)
		},
	}
	// Login is the only command that can negotiate a session token against the auth server using basic auth
	cmd.Flags().StringVarP(&options.Username, "username", "u", "", "Username, will prompt if not provided")
	cmd.Flags().StringVarP(&options.Password, "password", "p", "", "Password, will prompt if not provided")

	return cmd

}

// AttachOptions declare the arguments accepted by the Exec command
type LDAPOptions struct {
	Username string
	Password string

	In  io.Reader
	Out io.Writer
	Err io.Writer

	configAccess clientcmd.ConfigAccess

	Config *restclient.Config
}

// Processes an auth server request with basic shared functionality... do the
// request, check the response type, parse the token, set it and return.
func (o *LDAPOptions) processAuthRequest(req *http.Request) error {

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return err

	}

	bodyText, err := ioutil.ReadAll(resp.Body)
	token := string(bodyText)

	config, err := o.configAccess.GetStartingConfig()
	if err != nil {
		return err

	}

	startingStanza, exists := config.AuthInfos["apcera"]
	if !exists {
		startingStanza = clientcmdapi.NewAuthInfo()

	}

	//Create a new auth info struct populate it with the token.
	//TODO V2 Add check if token exsist and is valid. Ask user for permission to overwrite.

	authInfo := o.modifyAuthInfo(*startingStanza, token)
	config.AuthInfos["apcera"] = &authInfo

	if err := clientcmd.ModifyConfig(o.configAccess, *config, true); err != nil {
		return err

	}

	fmt.Println("The respose is ", token)
	/*accessToken, err := handleAuthResponse(resp)
	if err != nil {
		return err

	}
	c.writeToken(accessToken)*/
	return fmt.Errorf(token)

}

func (o *LDAPOptions) modifyAuthInfo(existingAuthInfo clientcmdapi.AuthInfo, token string) clientcmdapi.AuthInfo {
	modifiedAuthInfo := existingAuthInfo
	if len(token) > 0 {
		modifiedAuthInfo.Token = token
	}

	// If any auth info was set, make sure any other existing auth types are cleared
	//TODO copy auth type clearing from context set.
	return modifiedAuthInfo
}

func (o *LDAPOptions) connectWithServer(serverHost string) error {
	ldapPort := 8082

	url := fmt.Sprintf("%s:%d", serverHost, ldapPort)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err

	}

	if len(o.Username) > 0 {
		req.SetBasicAuth(o.Username, o.Password)

	}

	//req.Header.Add("User-Agent", fmt.Sprintf("%s/v%s (Continuum Client)", c.GetUserAgent(), c.ApcVersion()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return o.processAuthRequest(req)

}

func (o *LDAPOptions) RunLDAPLogin(out io.Writer, in io.Reader, cmd *cobra.Command, f *cmdutil.Factory) error {
	var buf []byte

	config, err := f.ClientConfig()
	if err != nil {
		return err
	}
	o.Config = config

	io.ReadFull(in, buf)

	host, _, _ := net.SplitHostPort(config.Host)

	err = o.connectWithServer(host)
	fmt.Fprintf(out, fmt.Sprintf("Login success apcera !! [%s][%s][%q]", o.Username, o.Password, err))

	return nil
}
