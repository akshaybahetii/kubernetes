package connector

import (
	"net/http"

	"k8s.io/kubernetes/plugin/pkg/auth/authenticator/token/apceratoken/auth"
)

//Connector for auth type to provide authentication feature.
type Connector interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)

	//Setup configures connetor with config file parametes.
	Setup(authServer auth.Auth)
}
