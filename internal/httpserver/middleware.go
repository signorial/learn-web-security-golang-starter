//lint:file-ignore U1000 Some code in this file is used later

// httpserver holds the HTTP server, routing, and request middleware.
package httpserver

// Import the standard library and internal packages this file uses.
import (
	// rand supplies cryptographically secure random bytes for the CSP nonce.
	"crypto/rand"
	// base64 turns the raw nonce bytes into a header-safe string.
	"encoding/base64"
	// fmt formats panic values and error text.
	"fmt"
	// math provides Ceil so retry-after is rounded up to a whole second.
	"math"
	// net splits host and port out of RemoteAddr.
	"net"
	// http supplies handlers, requests, responses, and status codes.
	"net/http"
	// slices provides Backward so middleware is applied from the inside out.
	"slices"
	// strconv converts numbers into header strings.
	"strconv"
	// strings splits and trims the X-Forwarded-For header.
	"strings"
	// sync provides the mutex that guards the rate-limit map.
	"sync"
	// time tracks rate-limit windows and reset times.
	"time"

	// httpx writes JSON and HTML error responses and stores the CSP nonce.
	"github.com/bootdotdev/learn-web-security/internal/httpx"
	// logging records unhandled panics as structured events.
	"github.com/bootdotdev/learn-web-security/internal/logging"
	// templates renders the HTML error page after a panic.
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

// middleware wraps a handler and returns the wrapped handler.
type middleware func(http.Handler) http.Handler

// applyMiddleware nests each middleware around handler.
func applyMiddleware(handler http.Handler, middlewareChain ...middleware) http.Handler {
	// Walk the chain backward so the first middleware is the outermost wrapper.
	for _, currentMiddleware := range slices.Backward(middlewareChain) {
		// Replace handler with the current wrapper around the previous handler.
		handler = currentMiddleware(handler)
	}
	// Return the fully wrapped handler.
	return handler
}

func NosSniffMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// permissiveCORS echoes the request Origin and allows credentialed cross-origin calls.
func permissiveCORS(next http.Handler) http.Handler {
	// Return the handler that sets CORS headers before calling next.
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		// Read the Origin header only when the browser sent one.
		if origin := request.Header.Get("Origin"); origin != "" {
			// Reflect that origin instead of restricting it to a known site.
			responseWriter.Header().Set("Access-Control-Allow-Origin", origin)
			// Allow cookies and other credentials on that cross-origin response.
			responseWriter.Header().Set("Access-Control-Allow-Credentials", "true")
			// Tell caches the response depends on the Origin request header.
			responseWriter.Header().Set("Vary", "Origin")
		}
		// Treat an OPTIONS request as a CORS preflight and stop here.
		if request.Method == http.MethodOptions {
			// Advertise every method a preflight might ask to use.
			responseWriter.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			// Echo whatever request headers the browser asked to send.
			responseWriter.Header().Set("Access-Control-Allow-Headers", request.Header.Get("Access-Control-Request-Headers"))
			// Preflight responses have no body.
			responseWriter.WriteHeader(http.StatusNoContent)
			// Do not run the rest of the handler for a preflight.
			return
		}
		// Continue to the wrapped handler for every other method.
		next.ServeHTTP(responseWriter, request)
	})
}

// cspNonce creates a per-request nonce and stores it on the request context.
func cspNonce(next http.Handler) http.Handler {
	// Return the handler that generates the nonce before calling next.
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		// Allocate 16 bytes, which is 128 bits of nonce material.
		nonceBytes := make([]byte, 16)
		// Fill those bytes from the cryptographic random source.
		if _, err := rand.Read(nonceBytes); err != nil {
			// Fail the request if the operating system cannot supply random bytes.
			http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			// Stop before calling the next handler.
			return
		}
		// Encode the nonce so it can be placed in a CSP header or script attribute.
		nonce := base64.StdEncoding.EncodeToString(nonceBytes)
		// Attach the nonce to the request context for later template rendering.
		request = request.WithContext(httpx.WithCSPNonce(request.Context(), nonce))
		// Call the next handler with the nonce-bearing request.
		next.ServeHTTP(responseWriter, request)
	})
}

// recoverPanics turns a panic in next into a logged 500 response.
func recoverPanics(logger *logging.Logger, renderer *templates.Renderer) middleware {
	// Return the middleware closure that captures logger and renderer.
	return func(next http.Handler) http.Handler {
		// Return the handler that installs the panic recovery.
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			// Register the recovery function to run when this handler returns.
			defer func() {
				// Capture a panic value if one was raised.
				if recovered := recover(); recovered != nil {
					// Log the method, path, and panic text, ignoring a logging failure.
					_ = logger.Event("unhandled_error", map[string]any{
						// Record the HTTP method that panicked.
						"method": request.Method,
						// Record the URL path that panicked.
						"path": request.URL.Path,
						// Convert the panic value to a string for the log.
						"message": fmt.Sprint(recovered),
					})
					// Try to render the HTML error page with the panic text.
					if err := httpx.RespondWithErrorPage(responseWriter, renderer, http.StatusInternalServerError, "Unhandled Error", fmt.Sprint(recovered)); err != nil {
						// Fall back to a plain 500 if rendering the error page fails.
						http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					}
				}
			}()
			// Run the wrapped handler, which may panic.
			next.ServeHTTP(responseWriter, request)
		})
	}
}

// LoadShedder is a placeholder that currently does not shed load.
func LoadShedder(_ int, _ int) func(http.Handler) http.Handler {
	// Ignore the concurrency and retry arguments and return a pass-through wrapper.
	return func(next http.Handler) http.Handler {
		// Return the next handler unchanged.
		return next
	}
}

// SearchThrottle is a placeholder that currently does not throttle search.
func SearchThrottle(_ *templates.Renderer) func(http.Handler) http.Handler {
	// Ignore the renderer and return a pass-through wrapper.
	return func(next http.Handler) http.Handler {
		// Return the next handler unchanged.
		return next
	}
}

// rateLimitCounter stores how many requests a key has used in the current window.
type rateLimitCounter struct {
	// count is the number of allowed requests already consumed.
	count int
	// resetAt is the instant when this window expires.
	resetAt time.Time
}

// rateLimitOptions configures one fixed-window limiter.
type rateLimitOptions struct {
	// window is how long a counter stays active.
	window time.Duration
	// maximum is the number of requests allowed per key per window.
	maximum int
	// key derives the bucket name from a request.
	key func(*http.Request) string
	// onLimit writes the response when a request is over the limit.
	onLimit func(http.ResponseWriter, *http.Request, rateLimitState)
	// now supplies the current time so tests can freeze the clock.
	now func() time.Time
}

// rateLimitState is the snapshot returned for one consume attempt.
type rateLimitState struct {
	// limit is the configured maximum for this window.
	limit int
	// remaining is how many requests are left after this decision.
	remaining int
	// resetAt is when the current window ends.
	resetAt time.Time
	// retryAfterSeconds is how long the client should wait before retrying.
	retryAfterSeconds int
}

// fixedWindowLimiter keeps per-key counters for one rate-limit policy.
type fixedWindowLimiter struct {
	// options is the policy this limiter enforces.
	options rateLimitOptions
	// counters maps a client key to its current window counter.
	counters map[string]rateLimitCounter
	// countersMutex serializes reads and writes of counters.
	countersMutex sync.Mutex
	// nextSweepAt is the next time expired counters may be deleted.
	nextSweepAt time.Time
}

// newFixedWindowLimiter validates options and builds an empty limiter.
func newFixedWindowLimiter(options rateLimitOptions) *fixedWindowLimiter {
	// Panic immediately if the window or maximum is not usable.
	validateRateLimitOptions(options)
	// Default the clock to the real current time.
	if options.now == nil {
		options.now = time.Now
	}
	// Default the bucket key to the client IP.
	if options.key == nil {
		options.key = clientIPKey
	}
	// Return a limiter with an empty counter map and a scheduled sweep.
	return &fixedWindowLimiter{
		// Keep the validated options, including any defaults just applied.
		options: options,
		// Start with no client counters.
		counters: make(map[string]rateLimitCounter),
		// Schedule the first expired-counter sweep one window from now.
		nextSweepAt: options.now().Add(options.window),
	}
}

// validateRateLimitOptions panics when a limiter would never reset or never allow a request.
func validateRateLimitOptions(options rateLimitOptions) {
	// A non-positive window would make reset math meaningless.
	if options.window <= 0 {
		panic("rate-limit window must be positive")
	}
	// A non-positive maximum would reject every request or divide badly.
	if options.maximum <= 0 {
		panic("rate-limit maximum must be positive")
	}
}

// consume records one request and reports whether it is over the limit.
func (limiter *fixedWindowLimiter) consume(request *http.Request) (rateLimitState, bool) {
	// Read the current time once so the whole decision uses the same instant.
	now := limiter.options.now()
	// Derive the counter key, usually the client IP.
	key := limiter.options.key(request)

	// Lock the map for the rest of this decision.
	limiter.countersMutex.Lock()
	// Unlock even if a later step panics.
	defer limiter.countersMutex.Unlock()
	// Drop counters whose windows have already ended.
	limiter.sweepExpiredCounters(now)

	// Look up the counter for this key.
	counter, exists := limiter.counters[key]
	// Start a new window when the key is new or its previous window has ended.
	if !exists || !now.Before(counter.resetAt) {
		counter = rateLimitCounter{resetAt: now.Add(limiter.options.window)}
	}
	// Round the time until reset up to at least one second.
	retryAfterSeconds := max(1, int(math.Ceil(counter.resetAt.Sub(now).Seconds())))
	// Reject the request when this window is already full.
	if counter.count >= limiter.options.maximum {
		// Return a full-window snapshot and true to mean "limited".
		return rateLimitState{
			// Report the configured maximum.
			limit: limiter.options.maximum,
			// Nothing remains once the maximum has been reached.
			remaining: 0,
			// Tell the client when this window ends.
			resetAt: counter.resetAt,
			// Tell the client how many seconds to wait.
			retryAfterSeconds: retryAfterSeconds,
		}, true
	}

	// Count this allowed request against the window.
	counter.count++
	// Store the updated counter for later requests from the same key.
	limiter.counters[key] = counter
	// Return the updated snapshot and false to mean "allowed".
	return rateLimitState{
		// Report the configured maximum.
		limit: limiter.options.maximum,
		// Remaining is the maximum minus the count just incremented.
		remaining: limiter.options.maximum - counter.count,
		// Keep the same window end time.
		resetAt: counter.resetAt,
		// Include retry-after even on allowed requests so headers can use it.
		retryAfterSeconds: retryAfterSeconds,
	}, false
}

// sweepExpiredCounters deletes stale counters, but at most once per window.
func (limiter *fixedWindowLimiter) sweepExpiredCounters(now time.Time) {
	// Skip the scan until the scheduled sweep time.
	if now.Before(limiter.nextSweepAt) {
		return
	}
	// Inspect every stored counter.
	for counterKey, counter := range limiter.counters {
		// Delete a counter whose window end is not still in the future.
		if !now.Before(counter.resetAt) {
			delete(limiter.counters, counterKey)
		}
	}
	// Schedule the next scan one window from this sweep.
	limiter.nextSweepAt = now.Add(limiter.options.window)
}

// reject writes rate-limit headers and either a custom or JSON 429 response.
func (limiter *fixedWindowLimiter) reject(responseWriter http.ResponseWriter, request *http.Request, state rateLimitState) {
	// Set RateLimit-Limit, RateLimit-Remaining, and RateLimit-Reset.
	setRateLimitHeaders(responseWriter, state)
	// Tell the client how many seconds to wait before retrying.
	responseWriter.Header().Set("Retry-After", strconv.Itoa(state.retryAfterSeconds))
	// Use the custom rejection writer when one was configured.
	if limiter.options.onLimit != nil {
		limiter.options.onLimit(responseWriter, request, state)
		// Do not also write the default JSON body.
		return
	}
	// Otherwise respond with a JSON 429.
	httpx.RespondWithJSON(responseWriter, http.StatusTooManyRequests, map[string]string{"error": "Too many requests"})
}

// fixedWindowRateLimiter currently validates options and then does not limit.
func fixedWindowRateLimiter(options rateLimitOptions) middleware {
	// Panic if the window or maximum is invalid.
	validateRateLimitOptions(options)
	// Return a wrapper that ignores the limiter and calls next directly.
	return func(next http.Handler) http.Handler {
		// Pass the handler through unchanged.
		return next
	}
}

// setRateLimitHeaders writes the standard RateLimit-* response headers.
func setRateLimitHeaders(responseWriter http.ResponseWriter, state rateLimitState) {
	// RateLimit-Limit is the maximum requests allowed in the window.
	responseWriter.Header().Set("RateLimit-Limit", strconv.Itoa(state.limit))
	// RateLimit-Remaining is how many requests are left in the window.
	responseWriter.Header().Set("RateLimit-Remaining", strconv.Itoa(state.remaining))
	// RateLimit-Reset is the unix time when the window ends, rounded up to the next second.
	responseWriter.Header().Set("RateLimit-Reset", strconv.FormatInt(state.resetAt.Unix()+boolToInt64(state.resetAt.Nanosecond() > 0), 10))
}

// clientIPKey returns the client host from RemoteAddr, without the port.
func clientIPKey(request *http.Request) string {
	// Split "host:port" into host and port.
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	// Use the host when the address was in host:port form.
	if err == nil && host != "" {
		return host
	}
	// Fall back to the raw RemoteAddr when it has no port.
	if request.RemoteAddr != "" {
		return request.RemoteAddr
	}
	// Use a shared bucket when the server has no client address.
	return "unknown"
}

// clientIPKeyWithTrustedProxies returns a key function that may trust X-Forwarded-For.
func clientIPKeyWithTrustedProxies(trustedProxyHops int) func(*http.Request) string {
	// Close over the hop count so each request can use the same trust setting.
	return func(request *http.Request) string {
		// Only inspect forwarded addresses when at least one proxy hop is trusted.
		if trustedProxyHops > 0 {
			// Split the header into the chain of forwarding addresses.
			forwardedAddresses := strings.Split(request.Header.Get("X-Forwarded-For"), ",")
			// Pick the address added by the furthest trusted proxy.
			selectedIndex := len(forwardedAddresses) - trustedProxyHops
			// Use that entry only when the index lands inside the list.
			if selectedIndex >= 0 && selectedIndex < len(forwardedAddresses) {
				// Trim spaces around the selected address.
				if selectedAddress := strings.TrimSpace(forwardedAddresses[selectedIndex]); selectedAddress != "" {
					// Use the forwarded address as the rate-limit key.
					return selectedAddress
				}
			}
		}
		// Fall back to the direct connection address.
		return clientIPKey(request)
	}
}

// boolToInt64 converts true to 1 and false to 0.
func boolToInt64(value bool) int64 {
	// Return 1 so a non-zero nanosecond count rounds the unix timestamp up.
	if value {
		return 1
	}
	// Return 0 when no rounding is needed.
	return 0
}
