package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// computeHMAC generates the hex HMAC-SHA256 signature for test requests.
func computeHMAC(secret, message string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// signedHeader creates a valid QuickPay-Signature header with timestamp t.
func signedHeader(secret string, t int64, body []byte) string {
	sig := computeHMAC(secret, fmt.Sprintf("%d.%s", t, string(body)))
	return fmt.Sprintf("t=%d,v1=%s", t, sig)
}

// TestGatewaySignatureFormat verifies the header format and HMAC calculation.
func TestGatewaySignatureFormat(t *testing.T) {
	body := []byte(`{"id":"evt_1","type":"payment.succeeded"}`)
	nowSec := time.Now().Unix()
	header := SignPayload(WebhookSecret, nowSec, body)

	tParsed, v1, err := ParseSignatureHeader(header)
	if err != nil {
		t.Fatalf("failed to parse generated signature: %v", err)
	}
	if tParsed != nowSec {
		t.Errorf("expected timestamp %d, got %d", nowSec, tParsed)
	}
	if len(v1) != 64 {
		t.Errorf("expected 64 hex characters for HMAC-SHA256, got len=%d: %s", len(v1), v1)
	}
}

// TestGatewayDeliverWithRetries verifies exponential backoff retry mechanism.
func TestGatewayDeliverWithRetries(t *testing.T) {
	var hits []int64
	var sigs []string
	var mu sync.Mutex

	flakyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, time.Now().UnixMilli())
		sigs = append(sigs, r.Header.Get("QuickPay-Signature"))
		count := len(hits)
		mu.Unlock()

		if count < 3 {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer flakyServer.Close()

	gw := NewPaymentGateway(false)
	gw.baseRetryGap = 800 * time.Millisecond // fast testing gap
	eventBody := []byte(`{"id":"evt_retry_test","type":"payment.succeeded"}`)

	gw.DeliverWithRetries(context.Background(), flakyServer.URL, "evt_retry_test", eventBody)

	mu.Lock()
	defer mu.Unlock()

	if len(hits) != 3 {
		t.Fatalf("expected exactly 3 attempts (fail, fail, ok), got %d", len(hits))
	}

	gap1 := hits[1] - hits[0]
	gap2 := hits[2] - hits[1]

	if gap1 < 700 {
		t.Errorf("first retry came too quickly: %d ms, expected ~800 ms", gap1)
	}
	if float64(gap2) < float64(gap1)*1.4 {
		t.Errorf("backoff did not grow sufficiently: gap1=%d ms, gap2=%d ms", gap1, gap2)
	}

	if sigs[0] == "" || !strings.Contains(sigs[0], "v1=") {
		t.Errorf("invalid signature header on first attempt: %s", sigs[0])
	}
}

// TestMerchantSignatureVerification verifies all 5 security test cases from Check.java.
func TestMerchantSignatureVerification(t *testing.T) {
	merchant := NewMerchantApp("http://localhost:8091", 0)
	h := merchant.Routes()

	eventTemplate := `{"id":"evt_forged1","type":"payment.succeeded","data":{"orderId":"ord_x"}}`
	nowSec := time.Now().Unix()

	// 1. Forged signature -> 401
	{
		forgedSig := fmt.Sprintf("t=%d,v1=%s", nowSec, strings.Repeat("0", 64))
		req := httptest.NewRequest(http.MethodPost, "/webhooks/quickpay", strings.NewReader(eventTemplate))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("QuickPay-Signature", forgedSig)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("forged signature: expected 401, got %d", rec.Code)
		}
	}

	// 2. Missing signature header -> 401
	{
		req := httptest.NewRequest(http.MethodPost, "/webhooks/quickpay", strings.NewReader(eventTemplate))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("missing signature: expected 401, got %d", rec.Code)
		}
	}

	// 3. Signed with wrong secret -> 401
	{
		wrongSecretSig := signedHeader("wrong_secret_key", nowSec, []byte(eventTemplate))
		req := httptest.NewRequest(http.MethodPost, "/webhooks/quickpay", strings.NewReader(eventTemplate))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("QuickPay-Signature", wrongSecretSig)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("wrong secret: expected 401, got %d", rec.Code)
		}
	}

	// 4. Valid signature but 10 minutes old (replay attack) -> 401
	{
		tenMinOld := nowSec - 600
		oldSig := signedHeader(WebhookSecret, tenMinOld, []byte(eventTemplate))
		req := httptest.NewRequest(http.MethodPost, "/webhooks/quickpay", strings.NewReader(eventTemplate))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("QuickPay-Signature", oldSig)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("replay attack: expected 401, got %d", rec.Code)
		}
	}

	// 5. Body tampered after signing -> 401
	{
		original := `{"id":"evt_forged1","type":"payment.failed","data":{"orderId":"ord_x"}}`
		sig := signedHeader(WebhookSecret, nowSec, []byte(original))
		tampered := strings.Replace(original, "failed", "succeeded", 1)

		req := httptest.NewRequest(http.MethodPost, "/webhooks/quickpay", strings.NewReader(tampered))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("QuickPay-Signature", sig)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("tampered payload: expected 401, got %d", rec.Code)
		}
	}
}

// TestMerchantIdempotencyAndApplication verifies deduplication and order state update.
func TestMerchantIdempotencyAndApplication(t *testing.T) {
	merchant := NewMerchantApp("http://localhost:8091", 0)
	h := merchant.Routes()

	// Seed an order
	orderID := "ord_499"
	merchant.orders[orderID] = &Order{
		OrderID:   orderID,
		Amount:    499,
		Status:    "PENDING_PAYMENT",
		CreatedAt: time.Now().UnixMilli(),
	}

	eventID := fmt.Sprintf("evt_test_%d", time.Now().UnixNano())
	payload := fmt.Sprintf(`{"id":"%s","type":"payment.succeeded","data":{"orderId":"%s"}}`, eventID, orderID)
	nowSec := time.Now().Unix()
	sig := signedHeader(WebhookSecret, nowSec, []byte(payload))

	// 1. First delivery -> 200 OK, status changes to PAID
	{
		req := httptest.NewRequest(http.MethodPost, "/webhooks/quickpay", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("QuickPay-Signature", sig)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("first delivery: expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		if merchant.orders[orderID].Status != "PAID" {
			t.Errorf("expected order status PAID, got %s", merchant.orders[orderID].Status)
		}
	}

	// 2. Duplicate delivery -> 200 OK, duplicate counter increments
	beforeDup := merchant.duplicatesCount.Load()
	{
		req := httptest.NewRequest(http.MethodPost, "/webhooks/quickpay", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("QuickPay-Signature", sig)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("duplicate delivery: expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		afterDup := merchant.duplicatesCount.Load()
		if afterDup != beforeDup+1 {
			t.Errorf("expected duplicate count to increase by 1: before=%d, after=%d", beforeDup, afterDup)
		}
	}

	// 3. Webhook for unknown order -> 200 OK
	{
		ghostPayload := `{"id":"evt_ghost_1","type":"payment.succeeded","data":{"orderId":"ord_ghost"}}`
		ghostSig := signedHeader(WebhookSecret, nowSec, []byte(ghostPayload))
		req := httptest.NewRequest(http.MethodPost, "/webhooks/quickpay", strings.NewReader(ghostPayload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("QuickPay-Signature", ghostSig)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("ghost order webhook: expected 200, got %d", rec.Code)
		}
	}
}

// TestEndToEndFlow tests the full cycle: order -> gateway payment -> webhook callback -> PAID.
func TestEndToEndFlow(t *testing.T) {
	gw := NewPaymentGateway(false)
	gw.bankDelay = 100 * time.Millisecond // accelerated bank delay for test
	gwServer := httptest.NewServer(gw.Routes())
	defer gwServer.Close()

	merchant := NewMerchantApp(gwServer.URL, 0)
	merchantServer := httptest.NewServer(merchant.Routes())
	defer merchantServer.Close()
	merchant.selfWebhookURL = merchantServer.URL + "/webhooks/quickpay"

	// 1. Test successful payment (amount 499 <= 10000)
	{
		orderReq := `{"amount":499}`
		req, _ := http.NewRequest(http.MethodPost, merchantServer.URL+"/orders", strings.NewReader(orderReq))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("failed to create order: %v", err)
		}
		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 201 Created, got %d: %s", resp.StatusCode, string(body))
		}

		var created Order
		json.NewDecoder(resp.Body).Decode(&created)
		resp.Body.Close()

		if created.Status != "PENDING_PAYMENT" {
			t.Errorf("expected initial status PENDING_PAYMENT, got %s", created.Status)
		}

		// Wait for webhook callback to process
		deadline := time.Now().Add(3 * time.Second)
		var finalStatus string
		for time.Now().Before(deadline) {
			merchant.mu.RLock()
			ord := merchant.orders[created.OrderID]
			if ord != nil {
				finalStatus = ord.Status
			}
			merchant.mu.RUnlock()

			if finalStatus == "PAID" {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}

		if finalStatus != "PAID" {
			t.Fatalf("order %s did not become PAID within deadline, status=%s", created.OrderID, finalStatus)
		}
	}

	// 2. Test failed payment (amount 20000 > 10000)
	{
		orderReq := `{"amount":20000}`
		req, _ := http.NewRequest(http.MethodPost, merchantServer.URL+"/orders", strings.NewReader(orderReq))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("failed to create order: %v", err)
		}
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("expected 201 Created, got %d", resp.StatusCode)
		}

		var created Order
		json.NewDecoder(resp.Body).Decode(&created)
		resp.Body.Close()

		// Wait for webhook callback to process
		deadline := time.Now().Add(3 * time.Second)
		var finalStatus string
		for time.Now().Before(deadline) {
			merchant.mu.RLock()
			ord := merchant.orders[created.OrderID]
			if ord != nil {
				finalStatus = ord.Status
			}
			merchant.mu.RUnlock()

			if finalStatus == "PAYMENT_FAILED" {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}

		if finalStatus != "PAYMENT_FAILED" {
			t.Fatalf("order %s did not become PAYMENT_FAILED, status=%s", created.OrderID, finalStatus)
		}
	}
}

// TestFlakyMerchantRecovery tests the chaos mode where merchant returns 503 twice before succeeding.
func TestFlakyMerchantRecovery(t *testing.T) {
	gw := NewPaymentGateway(false)
	gw.bankDelay = 50 * time.Millisecond
	gw.baseRetryGap = 100 * time.Millisecond // rapid retries for test
	gwServer := httptest.NewServer(gw.Routes())
	defer gwServer.Close()

	// Flaky merchant fails first 2 requests
	merchant := NewMerchantApp(gwServer.URL, 2)
	merchantServer := httptest.NewServer(merchant.Routes())
	defer merchantServer.Close()
	merchant.selfWebhookURL = merchantServer.URL + "/webhooks/quickpay"

	orderReq := `{"amount":499}`
	resp, err := http.Post(merchantServer.URL+"/orders", "application/json", strings.NewReader(orderReq))
	if err != nil {
		t.Fatalf("failed to create order: %v", err)
	}
	var created Order
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()

	// Wait for retry recovery to finish
	deadline := time.Now().Add(5 * time.Second)
	var finalStatus string
	for time.Now().Before(deadline) {
		merchant.mu.RLock()
		ord := merchant.orders[created.OrderID]
		if ord != nil {
			finalStatus = ord.Status
		}
		merchant.mu.RUnlock()

		if finalStatus == "PAID" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if finalStatus != "PAID" {
		t.Fatalf("flaky merchant did not recover to PAID, status=%s", finalStatus)
	}
}

// TestCheckJavaParity replicates the exact end-to-end assertions in Check.java.
func TestCheckJavaParity(t *testing.T) {
	// Initialize Gateway on :8091 and Merchant on :8092
	gw := NewPaymentGateway(false)
	gw.bankDelay = 1500 * time.Millisecond // match Java Check.java bank delay
	gw.baseRetryGap = 1000 * time.Millisecond
	gwServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", GatewayPort),
		Handler: gw.Routes(),
	}
	defer gwServer.Close()

	merchant := NewMerchantApp(fmt.Sprintf("http://localhost:%d", GatewayPort), 0)
	merchantServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", MerchantPort),
		Handler: merchant.Routes(),
	}
	defer merchantServer.Close()

	// Start servers on actual ports
	go gwServer.ListenAndServe()
	go merchantServer.ListenAndServe()

	// Give servers a brief moment to bind
	time.Sleep(100 * time.Millisecond)

	baseURLGW := fmt.Sprintf("http://localhost:%d", GatewayPort)
	baseURLMerchant := fmt.Sprintf("http://localhost:%d", MerchantPort)

	// Section: Gateway TODO(1) sign + TODO(2) retries
	{
		var hits []int64
		var sigs []string
		var mu sync.Mutex

		flakyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits = append(hits, time.Now().UnixMilli())
			sigs = append(sigs, r.Header.Get("QuickPay-Signature"))
			count := len(hits)
			mu.Unlock()

			if count < 3 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer flakyServer.Close()

		reqBody := fmt.Sprintf(`{"orderId":"ord_test","amount":100,"webhookUrl":"%s"}`, flakyServer.URL)
		resp, err := http.Post(baseURLGW+"/payments", "application/json", strings.NewReader(reqBody))
		if err != nil {
			t.Fatalf("failed to post payment to gateway: %v", err)
		}
		resp.Body.Close()

		deadline := time.Now().Add(9 * time.Second)
		for {
			mu.Lock()
			count := len(hits)
			mu.Unlock()
			if count >= 3 || time.Now().After(deadline) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		time.Sleep(1500 * time.Millisecond) // ensure no 4th attempt arrives

		mu.Lock()
		hitCount := len(hits)
		var gap1, gap2 int64
		if hitCount >= 3 {
			gap1 = hits[1] - hits[0]
			gap2 = hits[2] - hits[1]
		}
		firstSig := ""
		if len(sigs) > 0 {
			firstSig = sigs[0]
		}
		mu.Unlock()

		if hitCount != 3 {
			t.Fatalf("expected exactly 3 attempts, got %d", hitCount)
		}
		if gap1 < 800 {
			t.Errorf("first retry came after %d ms, expected ~1000", gap1)
		}
		if float64(gap2) < float64(gap1)*1.4 {
			t.Errorf("backoff should grow: gaps were %d ms then %d ms", gap1, gap2)
		}
		if !strings.HasPrefix(firstSig, "t=") || !strings.Contains(firstSig, ",v1=") {
			t.Errorf("invalid signature header format: %s", firstSig)
		}
	}

	// Section: Merchant End to End
	var paidOrderID string
	{
		// 1. Amount 499 -> PAID
		resp, err := http.Post(baseURLMerchant+"/orders", "application/json", strings.NewReader(`{"amount":499}`))
		if err != nil {
			t.Fatalf("failed to create order: %v", err)
		}
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("expected 201, got %d", resp.StatusCode)
		}
		var ord Order
		json.NewDecoder(resp.Body).Decode(&ord)
		resp.Body.Close()
		paidOrderID = ord.OrderID

		if ord.Status != "PENDING_PAYMENT" {
			t.Errorf("expected PENDING_PAYMENT, got %s", ord.Status)
		}

		// Wait for status to become PAID
		deadline := time.Now().Add(8 * time.Second)
		isPaid := false
		for time.Now().Before(deadline) {
			res, err := http.Get(baseURLMerchant + "/orders/" + paidOrderID)
			if err == nil {
				var cur Order
				json.NewDecoder(res.Body).Decode(&cur)
				res.Body.Close()
				if cur.Status == "PAID" {
					isPaid = true
					break
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
		if !isPaid {
			t.Errorf("order %s never became PAID", paidOrderID)
		}

		// 2. Amount 20000 -> PAYMENT_FAILED
		respFail, err := http.Post(baseURLMerchant+"/orders", "application/json", strings.NewReader(`{"amount":20000}`))
		if err != nil {
			t.Fatalf("failed to create order: %v", err)
		}
		var failOrd Order
		json.NewDecoder(respFail.Body).Decode(&failOrd)
		respFail.Body.Close()

		deadlineFail := time.Now().Add(8 * time.Second)
		isFailed := false
		for time.Now().Before(deadlineFail) {
			res, err := http.Get(baseURLMerchant + "/orders/" + failOrd.OrderID)
			if err == nil {
				var cur Order
				json.NewDecoder(res.Body).Decode(&cur)
				res.Body.Close()
				if cur.Status == "PAYMENT_FAILED" {
					isFailed = true
					break
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
		if !isFailed {
			t.Errorf("order %s never became PAYMENT_FAILED", failOrd.OrderID)
		}
	}

	// Section: Merchant TODO(4) idempotency + TODO(5) apply
	{
		// Duplicate delivered twice
		statsResBefore, _ := http.Get(baseURLMerchant + "/stats")
		var statsBefore map[string]int
		json.NewDecoder(statsResBefore.Body).Decode(&statsBefore)
		statsResBefore.Body.Close()

		dupEventID := fmt.Sprintf("evt_dup_%d", time.Now().UnixNano())
		dupBody := fmt.Sprintf(`{"id":"%s","type":"payment.succeeded","data":{"orderId":"%s"}}`, dupEventID, paidOrderID)
		nowSec := time.Now().Unix()
		sig := signedHeader(WebhookSecret, nowSec, []byte(dupBody))

		req1, _ := http.NewRequest(http.MethodPost, baseURLMerchant+"/webhooks/quickpay", strings.NewReader(dupBody))
		req1.Header.Set("Content-Type", "application/json")
		req1.Header.Set("QuickPay-Signature", sig)
		resp1, _ := http.DefaultClient.Do(req1)
		resp1.Body.Close()
		if resp1.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp1.StatusCode)
		}

		req2, _ := http.NewRequest(http.MethodPost, baseURLMerchant+"/webhooks/quickpay", strings.NewReader(dupBody))
		req2.Header.Set("Content-Type", "application/json")
		req2.Header.Set("QuickPay-Signature", sig)
		resp2, _ := http.DefaultClient.Do(req2)
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp2.StatusCode)
		}

		statsResAfter, _ := http.Get(baseURLMerchant + "/stats")
		var statsAfter map[string]int
		json.NewDecoder(statsResAfter.Body).Decode(&statsAfter)
		statsResAfter.Body.Close()

		if statsAfter["duplicatesIgnored"] != statsBefore["duplicatesIgnored"]+1 {
			t.Errorf("expected duplicatesIgnored +1: before=%d after=%d", statsBefore["duplicatesIgnored"], statsAfter["duplicatesIgnored"])
		}

		// Unknown order -> 200
		ghostBody := fmt.Sprintf(`{"id":"evt_ghost_%d","type":"payment.succeeded","data":{"orderId":"ord_ghost"}}`, time.Now().UnixNano())
		ghostSig := signedHeader(WebhookSecret, nowSec, []byte(ghostBody))
		reqGhost, _ := http.NewRequest(http.MethodPost, baseURLMerchant+"/webhooks/quickpay", strings.NewReader(ghostBody))
		reqGhost.Header.Set("Content-Type", "application/json")
		reqGhost.Header.Set("QuickPay-Signature", ghostSig)
		respGhost, _ := http.DefaultClient.Do(reqGhost)
		respGhost.Body.Close()
		if respGhost.StatusCode != http.StatusOK {
			t.Errorf("expected 200 for ghost order, got %d", respGhost.StatusCode)
		}
	}
}

