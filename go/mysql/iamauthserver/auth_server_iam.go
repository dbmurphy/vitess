package iamauthserver

import (
	_ "fmt"
	"net"
	_ "os"
	"sync"
	"time"
	"vitess.io/vitess/go/mysql"
	_ "vitess.io/vitess/go/mysql/sqlerror"
	"vitess.io/vitess/go/vt/log"
	querypb "vitess.io/vitess/go/vt/proto/query"
)

type IAMAuthServer struct {
	RefreshSeconds int64
	methods        []mysql.AuthMethod
}

// HandleUser is part of the Validator interface. We
// handle any user here since we don't check up front.
func (asi *IAMAuthServer) HandleUser(user string) bool {
	return true
}

func (asi *IAMAuthServer) UserEntryWithHash(conn *mysql.Conn, salt []byte, user string, authResponse []byte, remoteAddr net.Addr) (mysql.Getter, error) {
	response, err := asi.Authenticate(user, string(salt))
	if err != nil {
		return nil, err
	}
	return response, nil

}

// IAMUserData holds username (iam role) as well as enough data to intelligently update itself.
type IAMUserData struct {
	authServer  *IAMAuthServer
	groups      []string
	username    string
	lastUpdated time.Time
	updating    bool
	sync.Mutex
}

// NewIAMAuthServer returns a new instance of IAMAuthServer.
func NewIAMAuthServer() *IAMAuthServer {
	return &IAMAuthServer{
		RefreshSeconds: 500,
		methods:        []mysql.AuthMethod{},
	}
}

// Init is public so it can be called from plugin_auth_iam.go (go/cmd/vtgate)
func Init() {

	iamAuthServer := NewIAMAuthServer()
	var authMethod mysql.AuthMethod
	authMethod = mysql.NewMysqlNativeAuthMethod(iamAuthServer, iamAuthServer)
	iamAuthServer.methods = append(iamAuthServer.methods, authMethod)
	mysql.RegisterAuthServer("iam", NewIAMAuthServer())
}

// TODO: Figure out how I should use method and descriptions
// AuthMethods returns the list of registered auth methods
// implemented by this auth server.
func (asi *IAMAuthServer) AuthMethods() []mysql.AuthMethod {
	return asi.methods
}

// DefaultAuthMethodDescription returns MysqlNativePassword as the default
// authentication method for the auth server implementation.
func (asi *IAMAuthServer) DefaultAuthMethodDescription() mysql.AuthMethodDescription {
	return mysql.MysqlNativePassword
}

// Authenticate validates the user and password with AWS IAM.
func (asi *IAMAuthServer) Authenticate(username string, password string) (mysql.Getter, error) {
	// Step 1: Remove MySQL client-side salt
	mySQLUnsaltedPassword, err := removeMySQLSalt(password)
	if err != nil {
		log.Errorf("Access denied for user '%s'", username)
		return nil, nil
	}

	// Step 2: Decrypt and extract the access key and secret key from the salted password
	accessKey, secretKey, err := decryptAndExtractKeys(username, mySQLUnsaltedPassword)
	if err != nil {
		log.Errorf("Access denied for user '%s'", username)
		return nil, nil
	}

	// Step 3: Use the extracted keys to validate with AWS STS
	roleName, err := validateWithSTS(accessKey, secretKey)
	if err != nil {
		log.Errorf("Access denied for user '%s'", username)
		return nil, nil
	}

	// Ensure the role name matches the expected username
	if roleName != username {
		log.Errorf("Access denied for user '%s'", username)
		return nil, nil
	}

	// If authentication succeeds, return a simple getter
	return &IAMUserData{
		authServer:  asi,
		groups:      []string{},
		username:    username,
		lastUpdated: time.Now(),
		updating:    false,
	}, nil
}

func (asi *IAMAuthServer) getGroups(username string) ([]string, error) {
	_ = username
	var groups []string
	return groups, nil
}

// Get returns wrapped username and possibly updates the cache
func (iud *IAMUserData) Get() *querypb.VTGateCallerID {
	if int64(time.Since(iud.lastUpdated).Seconds()) > iud.authServer.RefreshSeconds {
		go iud.update()
	}
	return &querypb.VTGateCallerID{Username: iud.username, Groups: iud.groups}
}

func (iud *IAMUserData) update() {
	iud.Lock()
	if iud.updating {
		iud.Unlock()
		return
	}
	iud.updating = true
	iud.Unlock()
	// TODO: IAM Groups???
	groups, err := iud.authServer.getGroups(iud.username)
	if err != nil {
		log.Errorf("Error updating LDAP user data: %v", err)
		return
	}
	iud.Lock()
	iud.groups = groups
	iud.lastUpdated = time.Now()
	iud.updating = false
	iud.Unlock()
}
