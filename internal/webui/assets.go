package webui

import (
	"bytes"
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed static
var embeddedAssets embed.FS

const contentSecurityPolicy = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; font-src 'self'"

type assetHandler struct {
	assets fs.FS
	index  []byte
}

func New() http.Handler {
	assets, err := fs.Sub(embeddedAssets, "static")
	if err != nil {
		panic("embedded Aera account center is unavailable")
	}
	handler, err := NewFromFS(assets)
	if err != nil {
		panic("embedded Aera account center is invalid")
	}
	return handler
}

func NewFromFS(assets fs.FS) (http.Handler, error) {
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil || len(index) == 0 {
		return nil, fs.ErrNotExist
	}
	return &assetHandler{assets: assets, index: index}, nil
}

func (h *assetHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(response)
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		response.Header().Set("Allow", "GET, HEAD")
		http.Error(response, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	cleaned := strings.TrimPrefix(path.Clean("/"+request.URL.Path), "/")
	if reservedPath(cleaned) {
		http.NotFound(response, request)
		return
	}
	if cleaned != "" && cleaned != "." && fs.ValidPath(cleaned) {
		if info, err := fs.Stat(h.assets, cleaned); err == nil && !info.IsDir() {
			contents, readErr := fs.ReadFile(h.assets, cleaned)
			if readErr != nil {
				http.NotFound(response, request)
				return
			}
			response.Header().Set("Cache-Control", "public, max-age=3600")
			setContentType(response, cleaned)
			http.ServeContent(response, request, cleaned, time.Time{}, bytes.NewReader(contents))
			return
		}
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(response, request, "index.html", time.Time{}, bytes.NewReader(h.index))
}

func setSecurityHeaders(response http.ResponseWriter) {
	response.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("X-Frame-Options", "DENY")
	response.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}

func setContentType(response http.ResponseWriter, name string) {
	contentType := mime.TypeByExtension(path.Ext(name))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	response.Header().Set("Content-Type", contentType)
}

func reservedPath(cleaned string) bool {
	first, _, _ := strings.Cut(cleaned, "/")
	return first == "api" || first == "health" || first == "oauth" || first == ".well-known"
}
