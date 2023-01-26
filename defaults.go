package session

import "time"

// DefaultPath ...
const DefaultPath = "/"

// DefaultHTTPOnly ...
const DefaultHTTPOnly = true

// DefaultCookieKey ...
const DefaultCookieKey = "gsession"

// DefaultMaxAge ...
const DefaultMaxAge = 7 * 24 * time.Hour

// DefaultCfg is the default cookie config.
var DefaultCfg = &Config{
	MaxAge: DefaultMaxAge,
	//
	Path:     DefaultPath,
	HTTPOnly: DefaultHTTPOnly,
}
