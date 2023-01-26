package session

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-zoox/cookie"
	"github.com/go-zoox/crypto/aes"
	"github.com/go-zoox/crypto/md5"
	"github.com/pkg/errors"
)

// Session ...
type Session interface {
	// Set sets response session with the given name and value.
	Set(name string, value string, maxAge time.Duration)
	// Get gets request session with the given name.
	Get(name string) string
	// Del deletes response session with the given name.
	Del(name string)
}

// session is a middleware for handling session.
type session struct {
	Cookie cookie.Cookie
	Cfg    *Config
	//
	// Crypto aes.Aes
	Crypto *aes.CFB
	Secret string
	//
	isParsed bool
	data     map[string]interface{}
}

// Config is the optional session config.
type Config struct {
	MaxAge time.Duration
	// coookie
	Path     string
	Domain   string
	Secure   bool
	HTTPOnly bool
}

// New creates a session getter and setter.
func New(cookie cookie.Cookie, secret string, cfg ...*Config) Session {
	cfgX := DefaultCfg

	if len(cfg) > 0 && cfg[0] != nil {
		cfgX = cfg[0]

		if cfgX.Path == "" {
			cfgX.Path = DefaultPath
		}

		if cfgX.MaxAge == 0 {
			cfgX.MaxAge = DefaultMaxAge
		}
	}

	if secret == "" {
		panic(fmt.Errorf("session secret is required"))
	}

	crypto, err := aes.NewCFB(256, &aes.Base64Encoding{}, nil)
	if err != nil {
		panic(fmt.Errorf("failed to create session crypto: %v", err))
	}

	return &session{
		Cookie: cookie,
		Cfg:    cfgX,
		//
		Crypto: crypto,
		// 32 => aes-256-cfb
		// why use md5: ensure length 32 => 256 bit for aes 256-cfb
		Secret: md5.Md5(secret),
	}
}

// Set sets response session with the given name and value.
func (s *session) Set(key string, value string, maxAge time.Duration) {
	s.parse()

	s.data[key] = value
	// s.data["timestamp"] = time.Now().Format("2006-01-02 15:04:05")

	s.flush()
}

// Get gets request session with the given name.
func (s *session) Get(key string) string {
	s.parse()

	if value, ok := s.data[key]; ok {
		if v, ok := value.(string); ok {
			return v
		}
	}

	return ""
}

// Del deletes response session with the given name.
func (s *session) Del(key string) {
	s.parse()

	delete(s.data, key)

	s.flush()
}

func (s *session) parse() error {
	if s.isParsed {
		return nil
	}

	s.isParsed = true

	sessionToken := s.Cookie.Get(DefaultCookieKey)
	if sessionToken == "" {
		return nil
	}

	sessionTokenRaw, err := s.Crypto.Decrypt([]byte(sessionToken), []byte(s.Secret))
	if err != nil {
		return fmt.Errorf("invlaid session(error: %s)", err)
	}

	sessionTokenData := map[string]interface{}{}
	if err := json.Unmarshal(sessionTokenRaw, &sessionTokenData); err != nil {
		return errors.Wrap(err, "failed to unmarshal session token data")
	}

	for key, value := range sessionTokenData {
		s.data[key] = value
	}

	return nil
}

func (s *session) flush() error {
	if s.data == nil {
		return nil
	}

	sessionTokenRaw, err := json.Marshal(s.data)
	if err != nil {
		return errors.Wrap(err, "failed to stringify raw session token")
	}

	sessionToken, err := s.Crypto.Encrypt([]byte(sessionTokenRaw), []byte(s.Secret))
	if err != nil {
		return errors.Wrap(err, "failed to generate session token")
	}

	s.Cookie.Set(DefaultCookieKey, string(sessionToken), s.Cfg.MaxAge)
	return nil
}
