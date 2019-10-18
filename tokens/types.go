package tokens

// SessionRequest is the request payload used to create a new session.
//
// swagger:model SessionRequest
type SessionRequest struct {
	ClientID string `json:"client_id"`
	Subject  string `json:"subject"`
	Scope    string `json:"scope"`
}
