package connector

import "net/http"
import "../claims"

//Connector for auth type to provide authentication feature.
type Connector interface {
	// ID returns the ID of the ConnectorConfig used to create the Connector.
	ID() string

	// Login returns if authorization was sucess and claim list.
	Login(r *http.Request) (bool, error, []*claims.Claim)

	//Setup configures connetor with config file parametes.
	Setup()
}
