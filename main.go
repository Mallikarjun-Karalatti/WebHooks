package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	mathrand "math/rand"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------- Global Configuration & Constants ----------

const (
	GatewayPort         = 8091
	MerchantPort        = 8092
	WebhookSecret       = "whsec_quickbite_demo_123"
	DefaultToleranceSec = 300 // 5 minutes tolerance for replay protection
	MaxRetryAttempts    = 5
	BankDelay           = 1500 * time.Millisecond
	GatewayTimeout      = 5 * time.Second
)

// ---------- QuickPay Gateway Domain ----------

// Payment represents a payment resource tracked by the gateway.
type Payment struct {
	PaymentID  string `json:"paymentId"`
	OrderID    string `json:"orderId"`
	Amount     int64  `json:"amount"`
	Status     string `json:"status"` // PENDING, SUCCEEDED, FAILED
	WebhookURL string `json:"webhookUrl,omitempty"`
}

// WebhookEvent represents the JSON payload dispatched to merchant webhooks.
type WebhookEvent struct {
	ID        string  `json:"id"`
	Type      string  `json:"type"` // payment.succeeded or payment.failed
	CreatedAt int64   `json:"createdAt"`
	Data      Payment `json:"data"`
}

// DeliveryAttempt records an individual HTTP attempt to deliver a webhook.
type DeliveryAttempt struct {
	EventID string `json:"eventId"`
	Attempt int    `json:"attempt"`
	Result  any    `json:"result"` // HTTP status code int or error string
	At      int64  `json:"at"`
}

// PaymentGateway encapsulates the QuickPay mock payment processor.
type PaymentGateway struct {
	mu            sync.RWMutex
	payments      map[string]*Payment
	deliveries    []DeliveryAttempt
	seq           atomic.Int64
	duplicateMode bool
	jitterEnabled bool
	client        *http.Client
	bankDelay     time.Duration
	baseRetryGap  time.Duration
}

// NewPaymentGateway initializes a PaymentGateway instance.
func NewPaymentGateway(duplicateMode bool) *PaymentGateway {
	gw := &PaymentGateway{
		payments:      make(map[string]*Payment),
		deliveries:    make([]DeliveryAttempt, 0),
		duplicateMode: duplicateMode,
		client: &http.Client{
			Timeout: GatewayTimeout,
		},
		bankDelay:    BankDelay,
		baseRetryGap: 1 * time.Second,
	}
	gw.seq.Store(5000)
	return gw
}

// SignPayload computes the RFC-compliant QuickPay-Signature header value:
// t=<unixSeconds>,v1=<HMAC-SHA256(secret, "<unixSeconds>.<body>")>
func SignPayload(secret string, unixSeconds int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	prefix := fmt.Sprintf("%d.", unixSeconds)
	mac.Write([]byte(prefix))
	mac.Write(body)
	sigHex := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("t=%d,v1=%s", unixSeconds, sigHex)
}

// RecordDelivery appends a delivery log entry.
func (gw *PaymentGateway) RecordDelivery(eventID string, attempt int, result any) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	entry := DeliveryAttempt{
		EventID: eventID,
		Attempt: attempt,
		Result:  result,
		At:      time.Now().UnixMilli(),
	}
	gw.deliveries = append(gw.deliveries, entry)
	log.Printf("[gateway-webhook] event=%s attempt=%d result=%v", eventID, attempt, result)
}

// DeliverWithRetries dispatches a webhook with exponential backoff.
func (gw *PaymentGateway) DeliverWithRetries(ctx context.Context, webhookURL, eventID string, body []byte) {
	delay := gw.baseRetryGap

	for attempt := 1; attempt <= MaxRetryAttempts; attempt++ {
		nowSec := time.Now().Unix()
		sig := SignPayload(WebhookSecret, nowSec, body)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
		if err != nil {
			gw.RecordDelivery(eventID, attempt, err.Error())
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("QuickPay-Signature", sig)

		resp, err := gw.client.Do(req)
		if err != nil {
			gw.RecordDelivery(eventID, attempt, err.Error())
		} else {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			gw.RecordDelivery(eventID, attempt, resp.StatusCode)
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return // Successful delivery
			}
		}

		if attempt < MaxRetryAttempts {
			sleepDuration := delay
			if gw.jitterEnabled {
				// Full jitter: delay * (0.5 + rand(0..1))
				jitterFactor := 0.5 + mathrand.Float64()
				sleepDuration = time.Duration(float64(delay) * jitterFactor)
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(sleepDuration):
			}
			delay *= 2
		}
	}

	log.Printf("[gateway-webhook] %s: exhausted all %d attempts to %s", eventID, MaxRetryAttempts, webhookURL)
}

func (gw *PaymentGateway) Settle(paymentID, webhookURL string) {
	gw.mu.Lock()
	payment, exists := gw.payments[paymentID]
	if !exists {
		gw.mu.Unlock()
		return
	}

	isSuccess := payment.Amount <= 10000
	if isSuccess {
		payment.Status = "SUCCEEDED"
	} else {
		payment.Status = "FAILED"
	}
	snapshot := *payment
	gw.mu.Unlock()

	// Build webhook event payload
	var randBytes [4]byte
	rand.Read(randBytes[:])
	eventID := fmt.Sprintf("evt_%s", hex.EncodeToString(randBytes[:]))

	eventType := "payment.succeeded"
	if !isSuccess {
		eventType = "payment.failed"
	}

	event := WebhookEvent{
		ID:        eventID,
		Type:      eventType,
		CreatedAt: time.Now().UnixMilli(),
		Data:      snapshot,
	}

	body, err := json.Marshal(event)
	if err != nil {
		log.Printf("[gateway-settle] json marshal error: %v", err)
		return
	}

	log.Printf("[bank] payment=%s status=%s -> dispatching event=%s", snapshot.PaymentID, snapshot.Status, eventID)

	go gw.DeliverWithRetries(context.Background(), webhookURL, eventID, body)
	if gw.duplicateMode {
		go gw.DeliverWithRetries(context.Background(), webhookURL, eventID, body)
	}
}

// Routes builds the HTTP handler for the gateway service.
func (gw *PaymentGateway) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /payments", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			OrderID    string `json:"orderId"`
			Amount     int64  `json:"amount"`
			WebhookURL string `json:"webhookUrl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.OrderID == "" || req.Amount <= 0 || req.WebhookURL == "" {
			http.Error(w, `{"error":"orderId, positive amount and webhookUrl are required"}`, http.StatusBadRequest)
			return
		}

		pid := fmt.Sprintf("pay_%d", gw.seq.Add(1))
		payment := &Payment{
			PaymentID:  pid,
			OrderID:    req.OrderID,
			Amount:     req.Amount,
			Status:     "PENDING",
			WebhookURL: req.WebhookURL,
		}

		gw.mu.Lock()
		gw.payments[pid] = payment
		gw.mu.Unlock()

		// Schedule settlement simulation
		time.AfterFunc(gw.bankDelay, func() {
			gw.Settle(pid, req.WebhookURL)
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(payment)
	})

	mux.HandleFunc("GET /payments/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		gw.mu.RLock()
		payment, exists := gw.payments[id]
		gw.mu.RUnlock()

		if !exists {
			http.Error(w, `{"error":"no such payment"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(payment)
	})

	mux.HandleFunc("GET /deliveries", func(w http.ResponseWriter, r *http.Request) {
		gw.mu.RLock()
		res := make([]DeliveryAttempt, len(gw.deliveries))
		copy(res, gw.deliveries)
		gw.mu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
	})

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"service": "QuickPay",
			"try":     "POST /payments, GET /deliveries",
		})
	})

	return mux
}

// ---------- QuickBite Merchant Domain ----------

// Order represents an order resource placed at QuickBite.
type Order struct {
	OrderID   string `json:"orderId"`
	Amount    int64  `json:"amount"`
	Status    string `json:"status"` // PENDING_PAYMENT, PAID, PAYMENT_FAILED
	PaymentID string `json:"paymentId,omitempty"`
	CreatedAt int64  `json:"createdAt"`
}

// MerchantApp encapsulates the QuickBite restaurant backend receiving webhooks.
type MerchantApp struct {
	mu               sync.RWMutex
	orders           map[string]*Order
	processedEvents  map[string]int64 // eventID -> processed timestamp for TTL expiration
	seq              atomic.Int64
	receivedCount    atomic.Int64
	duplicatesCount  atomic.Int64
	rejectedCount    atomic.Int64
	flakyFailures    atomic.Int32
	gatewayBaseURL   string
	selfWebhookURL   string
	client           *http.Client
	toleranceSec     int64
	reconcileStopCh  chan struct{}
}

// NewMerchantApp initializes a MerchantApp instance.
func NewMerchantApp(gatewayBaseURL string, flakyFailures int32) *MerchantApp {
	app := &MerchantApp{
		orders:          make(map[string]*Order),
		processedEvents: make(map[string]int64),
		gatewayBaseURL:  gatewayBaseURL,
		selfWebhookURL:  fmt.Sprintf("http://localhost:%d/webhooks/quickpay", MerchantPort),
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		toleranceSec:    DefaultToleranceSec,
		reconcileStopCh: make(chan struct{}),
	}
	app.seq.Store(700)
	app.flakyFailures.Store(flakyFailures)
	return app
}

// ParseSignatureHeader extracts timestamp (t) and signature (v1) from header value:
// t=1730000000,v1=5f2b...
func ParseSignatureHeader(header string) (int64, string, error) {
	if header == "" {
		return 0, "", errors.New("missing signature header")
	}

	parts := strings.Split(header, ",")
	var t int64 = -1
	var v1 string

	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			switch kv[0] {
			case "t":
				val, err := strconv.ParseInt(kv[1], 10, 64)
				if err == nil {
					t = val
				}
			case "v1":
				v1 = kv[1]
			}
		}
	}

	if t == -1 || v1 == "" {
		return 0, "", errors.New("malformed signature header")
	}
	return t, v1, nil
}

// VerifySignature validates HMAC-SHA256 signature and timestamp tolerance in constant time.
func (app *MerchantApp) VerifySignature(rawBody []byte, sigHeader string) (bool, string) {
	t, v1, err := ParseSignatureHeader(sigHeader)
	if err != nil {
		return false, err.Error()
	}

	// 1. Replay attack check: check timestamp drift
	nowSec := time.Now().Unix()
	if math.Abs(float64(nowSec-t)) > float64(app.toleranceSec) {
		return false, "timestamp outside tolerance window"
	}

	// 2. Expected signature calculation: HMAC-SHA256(secret, "<t>.<body>")
	mac := hmac.New(sha256.New, []byte(WebhookSecret))
	prefix := fmt.Sprintf("%d.", t)
	mac.Write([]byte(prefix))
	mac.Write(rawBody)
	expectedHex := hex.EncodeToString(mac.Sum(nil))

	// 3. Constant-time comparison to prevent timing side-channel attacks
	if subtle.ConstantTimeCompare([]byte(expectedHex), []byte(v1)) != 1 {
		return false, "signature mismatch"
	}

	return true, ""
}

// ReconcileStaleOrders queries the gateway for orders stuck in PENDING_PAYMENT.
func (app *MerchantApp) ReconcileStaleOrders(ctx context.Context, ageThreshold time.Duration) int {
	app.mu.RLock()
	var pendingList []struct {
		orderID   string
		paymentID string
	}
	now := time.Now().UnixMilli()
	for id, ord := range app.orders {
		if ord.Status == "PENDING_PAYMENT" && ord.PaymentID != "" {
			if time.Duration(now-ord.CreatedAt)*time.Millisecond >= ageThreshold {
				pendingList = append(pendingList, struct {
					orderID   string
					paymentID string
				}{orderID: id, paymentID: ord.PaymentID})
			}
		}
	}
	app.mu.RUnlock()

	reconciled := 0
	for _, item := range pendingList {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/payments/%s", app.gatewayBaseURL, item.paymentID), nil)
		if err != nil {
			continue
		}
		resp, err := app.client.Do(req)
		if err != nil {
			continue
		}
		var p Payment
		err = json.NewDecoder(resp.Body).Decode(&p)
		resp.Body.Close()
		if err != nil {
			continue
		}

		if p.Status == "SUCCEEDED" || p.Status == "FAILED" {
			app.mu.Lock()
			if ord, ok := app.orders[item.orderID]; ok && ord.Status == "PENDING_PAYMENT" {
				if p.Status == "SUCCEEDED" {
					ord.Status = "PAID"
				} else {
					ord.Status = "PAYMENT_FAILED"
				}
				reconciled++
				log.Printf("[reconciliation] order=%s resolved to %s via payment lookup", item.orderID, ord.Status)
			}
			app.mu.Unlock()
		}
	}
	return reconciled
}

// StartReconciliationWorker runs a background cron-like reconciler.
func (app *MerchantApp) StartReconciliationWorker(interval, ageThreshold time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-app.reconcileStopCh:
				ticker.Stop()
				return
			case <-ticker.C:
				app.ReconcileStaleOrders(context.Background(), ageThreshold)
			}
		}
	}()
}

// StopReconciliationWorker cleanly halts the background reconciler.
func (app *MerchantApp) StopReconciliationWorker() {
	close(app.reconcileStopCh)
}

// Routes builds the HTTP handler for the merchant service.
func (app *MerchantApp) Routes() http.Handler {
	mux := http.NewServeMux()

	// POST /orders
	mux.HandleFunc("POST /orders", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Amount int64 `json:"amount"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Amount <= 0 {
			http.Error(w, `{"error":"amount must be a positive number"}`, http.StatusBadRequest)
			return
		}

		orderID := fmt.Sprintf("ord_%d", app.seq.Add(1))
		order := &Order{
			OrderID:   orderID,
			Amount:    req.Amount,
			Status:    "PENDING_PAYMENT",
			CreatedAt: time.Now().UnixMilli(),
		}

		app.mu.Lock()
		app.orders[orderID] = order
		app.mu.Unlock()

		// Request payment creation from QuickPay gateway
		webhookURL := app.selfWebhookURL
		if webhookURL == "" {
			webhookURL = fmt.Sprintf("http://localhost:%d/webhooks/quickpay", MerchantPort)
		}
		gatewayReqBody, _ := json.Marshal(map[string]any{
			"orderId":    orderID,
			"amount":     req.Amount,
			"webhookUrl": webhookURL,
		})

		resp, err := app.client.Post(fmt.Sprintf("%s/payments", app.gatewayBaseURL), "application/json", bytes.NewReader(gatewayReqBody))
		if err != nil {
			app.mu.Lock()
			delete(app.orders, orderID)
			app.mu.Unlock()
			http.Error(w, `{"error":"payment gateway unreachable"}`, http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		var paymentResp Payment
		if err := json.NewDecoder(resp.Body).Decode(&paymentResp); err == nil && paymentResp.PaymentID != "" {
			app.mu.Lock()
			order.PaymentID = paymentResp.PaymentID
			app.mu.Unlock()
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(order)
	})

	// GET /orders/{id}
	mux.HandleFunc("GET /orders/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		app.mu.RLock()
		order, exists := app.orders[id]
		app.mu.RUnlock()

		if !exists {
			http.Error(w, `{"error":"no such order"}`, http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(order)
	})

	// POST /webhooks/quickpay
	mux.HandleFunc("POST /webhooks/quickpay", func(w http.ResponseWriter, r *http.Request) {
		app.receivedCount.Add(1)

		// Read raw body bytes verbatim for signature verification
		rawBody, err := io.ReadAll(r.Body)
		if err != nil {
			app.rejectedCount.Add(1)
			http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)
			return
		}

		// Chaos mode: flaky merchant fails first N webhooks with 503
		if app.flakyFailures.Load() > 0 {
			if app.flakyFailures.Add(-1) >= 0 {
				log.Println("[merchant-webhook] chaos: simulating transient 503 Service Unavailable")
				http.Error(w, `{"error":"temporarily unavailable"}`, http.StatusServiceUnavailable)
				return
			}
		}

		// TODO(3): Verify HMAC-SHA256 signature and timestamp tolerance
		sigHeader := r.Header.Get("QuickPay-Signature")
		ok, reason := app.VerifySignature(rawBody, sigHeader)
		if !ok {
			app.rejectedCount.Add(1)
			log.Printf("[merchant-webhook] signature rejected: %s", reason)
			http.Error(w, fmt.Sprintf(`{"error":"unauthorized: %s"}`, reason), http.StatusUnauthorized)
			return
		}

		// Parse event payload
		var event WebhookEvent
		if err := json.Unmarshal(rawBody, &event); err != nil {
			http.Error(w, `{"error":"malformed JSON payload"}`, http.StatusBadRequest)
			return
		}

		// TODO(4): Idempotency deduplication
		app.mu.Lock()
		if _, alreadySeen := app.processedEvents[event.ID]; alreadySeen {
			app.mu.Unlock()
			app.duplicatesCount.Add(1)
			log.Printf("[merchant-webhook] duplicate event ignored: %s", event.ID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"result":"ok","duplicate":true}`))
			return
		}
		app.processedEvents[event.ID] = time.Now().UnixMilli()
		app.mu.Unlock()

		// TODO(5): Apply state transition
		orderID := event.Data.OrderID
		if orderID != "" {
			app.mu.Lock()
			order, exists := app.orders[orderID]
			if exists {
				switch event.Type {
				case "payment.succeeded":
					order.Status = "PAID"
				case "payment.failed":
					order.Status = "PAYMENT_FAILED"
				}
				log.Printf("[merchant-webhook] applied event=%s: order=%s status=%s", event.ID, orderID, order.Status)
			} else {
				log.Printf("[merchant-webhook] event=%s received for unknown order=%s (ignoring)", event.ID, orderID)
			}
			app.mu.Unlock()
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result":"ok"}`))
	})

	// GET /stats
	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int64{
			"received":          app.receivedCount.Load(),
			"duplicatesIgnored": app.duplicatesCount.Load(),
			"rejected":          app.rejectedCount.Load(),
		})
	})

	return mux
}

// ---------- Main Entrypoint ----------

func main() {
	var (
		runGateway   = flag.Bool("gateway", false, "Run QuickPay payment gateway service on port 8091")
		runMerchant  = flag.Bool("merchant", false, "Run QuickBite merchant app on port 8092")
		duplicate    = flag.Bool("duplicate", false, "Gateway chaos: deliver every event twice")
		flaky        = flag.Bool("flaky", false, "Merchant chaos: fail first 2 webhooks with 503")
		enableJitter = flag.Bool("jitter", false, "Gateway: apply random jitter to exponential backoff")
	)
	flag.Parse()

	// Default to running both services if neither is specifically chosen
	if !*runGateway && !*runMerchant {
		*runGateway = true
		*runMerchant = true
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = ctx

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	var servers []*http.Server

	if *runGateway {
		gw := NewPaymentGateway(*duplicate)
		gw.jitterEnabled = *enableJitter
		gwServer := &http.Server{
			Addr:    fmt.Sprintf(":%d", GatewayPort),
			Handler: gw.Routes(),
		}
		servers = append(servers, gwServer)

		go func() {
			log.Printf("QuickPay Payment Gateway listening on http://localhost:%d (duplicate=%v, jitter=%v)", GatewayPort, *duplicate, *enableJitter)
			if err := gwServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("Gateway server error: %v", err)
			}
		}()
	}

	if *runMerchant {
		var initialFlaky int32
		if *flaky {
			initialFlaky = 2
		}
		merchant := NewMerchantApp(fmt.Sprintf("http://localhost:%d", GatewayPort), initialFlaky)
		merchantServer := &http.Server{
			Addr:    fmt.Sprintf(":%d", MerchantPort),
			Handler: merchant.Routes(),
		}
		servers = append(servers, merchantServer)

		go func() {
			log.Printf("QuickBite Merchant App listening on http://localhost:%d (flaky=%v)", MerchantPort, *flaky)
			if err := merchantServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("Merchant server error: %v", err)
			}
		}()
	}

	<-sigChan
	log.Println("\nShutdown signal received. Shutting down gracefully...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()

	for _, srv := range servers {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("Error shutting down server on %s: %v", srv.Addr, err)
		}
	}
	log.Println("All services stopped.")
}
