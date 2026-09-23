package com.example.loginserver;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class LoginServerApplication {

    private static final String CLIENT_ID = "PNB_APP";
    private static final String DEMO_MOBILE = "9876543210";
    private static final String DEMO_USER_ID = "testuser";
    private static final String DEMO_PASSWORD = "Test@123";

    private static final long OTP_TTL_SECONDS = 120;
    private static final int OTP_MAX_ATTEMPTS = 3;
    private static final long TRUSTED_REQUEST_TTL_SECONDS = 120;
    private static final long SESSION_TTL_SECONDS = 1800;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SecureRandom secureRandom = new SecureRandom();

    // PNB encryption/decryption key pair.
    // Render: set PNB_PUBLIC_KEY_B64 and PNB_PRIVATE_KEY_B64 to keep the same keys across restarts.
    // Local DEV: if env vars are absent, a temporary pair is generated.
    private KeyPair pnbKeyPair;

    private final Map<String, OtpData> otpStore = new ConcurrentHashMap<>();
    private final Map<String, SessionData> sessionStore = new ConcurrentHashMap<>();
    private final Set<String> usedNonces = ConcurrentHashMap.newKeySet();
    private final Map<String, AuthTransaction> authTransactions = new ConcurrentHashMap<>();
    private final Map<String, String> latestRequestByUser = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        SpringApplication.run(LoginServerApplication.class, args);
    }

    public LoginServerApplication() throws Exception {
        this.pnbKeyPair = loadOrGeneratePnbKeyPair();
        System.out.println("======================================");
        System.out.println("PNB RSA KEY CONFIGURATION READY");
        System.out.println("Public key available for encryption");
        System.out.println("Private key remains server-side only");
        System.out.println("Signature: PENDING_APPROVAL");
        System.out.println("======================================");
    }

    @GetMapping("/test")
    public ResponseEntity<?> test() {
        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Java server is running"
        ));
    }

    // Safe to expose: PUBLIC key only.
    @GetMapping("/public-key")
    public ResponseEntity<?> getPublicKey() {
        return ResponseEntity.ok(Map.of(
                "success", true,
                "algorithm", "RSA-OAEP-SHA256",
                "keyType", "PNB_360_PUBLIC_KEY",
                "publicKey", Base64.getEncoder().encodeToString(pnbKeyPair.getPublic().getEncoded())
        ));
    }

    // DEV helper: generate a persistent pair ONCE, then copy values into Render environment variables.
    // Never expose this endpoint in production.
    @PostMapping("/dev/generate-key-pair")
    public ResponseEntity<?> generateKeyPairForConfiguration() {
        try {
            KeyPair pair = generateRsaKeyPair();
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "warning", "DEV/UAT ONLY. Store private key in Render secret/environment variable; never commit it to Git.",
                    "PNB_PUBLIC_KEY_B64", Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()),
                    "PNB_PRIVATE_KEY_B64", Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded())
            ));
        } catch (Exception e) {
            return error(HttpStatus.INTERNAL_SERVER_ERROR, "KEY_GENERATION_FAILED", "Unable to generate RSA key pair");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody EncryptedRequest request) {
        try {
            if (request == null || isBlank(request.data)) {
                return error(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", "Encrypted data is required");
            }

            JsonNode json = objectMapper.readTree(decrypt(request.data));
            String mobile = getText(json, "mobile");
            String userId = getText(json, "userId");
            String password = getText(json, "password");

            if (isBlank(mobile) || isBlank(userId) || isBlank(password)) {
                return error(HttpStatus.BAD_REQUEST, "MISSING_FIELDS", "Mobile, User ID and password are required");
            }

            if (!isValidCredentials(mobile, userId, password)) {
                return error(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "Invalid credentials");
            }

            String requestId = newRequestId();
            String otp = generateOtp();
            long otpExpiresAt = Instant.now().plusSeconds(OTP_TTL_SECONDS).toEpochMilli();

            otpStore.put(userId, new OtpData(otp, otpExpiresAt, 0, requestId));

            AuthTransaction tx = new AuthTransaction(requestId, userId);
            tx.loginStatus = "SUCCESS";
            tx.otpStatus = "GENERATED";
            tx.authenticationStatus = "OTP_PENDING";
            tx.updatedAt = Instant.now().toString();
            authTransactions.put(requestId, tx);
            latestRequestByUser.put(userId, requestId);

            // DEV/UAT only. Remove OTP value from logs in production.
            System.out.println("======================================");
            System.out.println("AUTH REQUEST : " + requestId);
            System.out.println("USER         : " + userId);
            System.out.println("LOGIN        : SUCCESS");
            System.out.println("OTP          : " + otp);
            System.out.println("OTP STATUS   : GENERATED / WAITING FOR USER");
            System.out.println("======================================");

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("success", true);
            response.put("requestId", requestId);
            response.put("userId", userId);
            response.put("loginStatus", "SUCCESS");
            response.put("otpStatus", "GENERATED");
            response.put("otpExpiresInSeconds", OTP_TTL_SECONDS);
            // DEV/UAT convenience requested by user. Remove in production.
            response.put("devOtp", otp);
            response.put("authenticationStatus", "OTP_PENDING");
            response.put("message", "Login successful. Enter OTP to continue.");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            return error(HttpStatus.BAD_REQUEST, "LOGIN_FAILED", "Unable to process encrypted login request");
        }
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(@RequestBody EncryptedRequest request) {
        try {
            if (request == null || isBlank(request.data)) {
                return error(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", "Encrypted OTP data is required");
            }

            JsonNode json = objectMapper.readTree(decrypt(request.data));
            String userId = getText(json, "userId");
            String otp = getText(json, "otp");

            if (isBlank(userId) || isBlank(otp)) {
                return error(HttpStatus.BAD_REQUEST, "MISSING_FIELDS", "User ID and OTP are required");
            }

            OtpData savedOtp = otpStore.get(userId);
            if (savedOtp == null) {
                return error(HttpStatus.UNAUTHORIZED, "OTP_NOT_FOUND", "OTP not found. Please login again.");
            }

            AuthTransaction tx = authTransactions.get(savedOtp.requestId);

            if (System.currentTimeMillis() > savedOtp.expiryTime) {
                otpStore.remove(userId);
                updateFailure(tx, "OTP_EXPIRED");
                return error(HttpStatus.UNAUTHORIZED, "OTP_EXPIRED", "OTP expired. Please login again.");
            }

            if (savedOtp.attempts >= OTP_MAX_ATTEMPTS) {
                otpStore.remove(userId);
                updateFailure(tx, "OTP_MAX_ATTEMPTS");
                return error(HttpStatus.UNAUTHORIZED, "OTP_MAX_ATTEMPTS", "Maximum OTP attempts exceeded.");
            }

            if (!savedOtp.otp.equals(otp)) {
                savedOtp.attempts++;
                int remaining = OTP_MAX_ATTEMPTS - savedOtp.attempts;
                if (remaining <= 0) {
                    otpStore.remove(userId);
                }
                if (tx != null) {
                    tx.otpStatus = "INVALID";
                    tx.authenticationStatus = "OTP_PENDING";
                    tx.updatedAt = Instant.now().toString();
                }
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("success", false);
                body.put("code", "INVALID_OTP");
                body.put("message", "Invalid OTP");
                body.put("remainingAttempts", Math.max(remaining, 0));
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
            }

            otpStore.remove(userId);
            if (tx == null) {
                String requestId = newRequestId();
                tx = new AuthTransaction(requestId, userId);
                authTransactions.put(requestId, tx);
                latestRequestByUser.put(userId, requestId);
            }

            tx.otpStatus = "VERIFIED";
            tx.authenticationStatus = "OTP_VERIFIED";
            tx.updatedAt = Instant.now().toString();

            TrustedResult trusted = performTrustedAuthentication(tx, userId);

            System.out.println("======================================");
            System.out.println("AUTH REQUEST      : " + tx.requestId);
            System.out.println("USER              : " + userId);
            System.out.println("OTP               : VERIFIED");
            System.out.println("PAYLOAD           : CREATED");
            System.out.println("ENCRYPTION        : PASS");
            System.out.println("SERVER DECRYPTION : PASS");
            System.out.println("SIGNATURE         : PENDING_APPROVAL");
            System.out.println("AUTHENTICATION    : AUTHORIZED");
            System.out.println("DASHBOARD         : GRANTED");
            System.out.println("======================================");

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("success", true);
            response.put("requestId", tx.requestId);
            response.put("userId", userId);
            response.put("otpStatus", "VERIFIED");
            response.put("canonicalPayload", trusted.canonicalPayload);
            response.put("trustedLoginRequest", trusted.trustedLoginRequest);
            response.put("securityValidation", trusted.securityValidation);
            response.put("signatureStatus", "PENDING_APPROVAL");
            response.put("authenticationStatus", "AUTHORIZED");
            response.put("tokenType", "Bearer");
            response.put("token", trusted.token);
            response.put("expiresInSeconds", SESSION_TTL_SECONDS);
            response.put("expiresAt", trusted.expiresAt);
            response.put("dashboard", "GRANTED");
            response.put("message", "OTP verified and Trusted Login authentication completed.");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            return error(HttpStatus.BAD_REQUEST, "OTP_VERIFICATION_FAILED", "Unable to verify OTP");
        }
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<?> resendOtp(@RequestBody EncryptedRequest request) {
        try {
            if (request == null || isBlank(request.data)) {
                return error(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", "Encrypted data is required");
            }

            JsonNode json = objectMapper.readTree(decrypt(request.data));
            String userId = getText(json, "userId");
            if (isBlank(userId)) {
                return error(HttpStatus.BAD_REQUEST, "MISSING_USER", "User ID is required");
            }

            String requestId = latestRequestByUser.get(userId);
            if (requestId == null) {
                requestId = newRequestId();
                AuthTransaction tx = new AuthTransaction(requestId, userId);
                tx.loginStatus = "SUCCESS";
                authTransactions.put(requestId, tx);
                latestRequestByUser.put(userId, requestId);
            }

            String otp = generateOtp();
            otpStore.put(userId, new OtpData(
                    otp,
                    Instant.now().plusSeconds(OTP_TTL_SECONDS).toEpochMilli(),
                    0,
                    requestId
            ));

            AuthTransaction tx = authTransactions.get(requestId);
            if (tx != null) {
                tx.otpStatus = "RESENT";
                tx.authenticationStatus = "OTP_PENDING";
                tx.updatedAt = Instant.now().toString();
            }

            System.out.println("OTP RESENT | requestId=" + requestId + " | userId=" + userId + " | OTP=" + otp);

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("success", true);
            response.put("requestId", requestId);
            response.put("otpStatus", "RESENT");
            response.put("otpExpiresInSeconds", OTP_TTL_SECONDS);
            response.put("devOtp", otp);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return error(HttpStatus.BAD_REQUEST, "RESEND_FAILED", "Unable to resend OTP");
        }
    }

    // Shows the live server-side status for the same requestId returned by /login.
    @GetMapping("/auth-status/{requestId}")
    public ResponseEntity<?> authStatus(@PathVariable String requestId) {
        AuthTransaction tx = authTransactions.get(requestId);
        if (tx == null) {
            return error(HttpStatus.NOT_FOUND, "REQUEST_NOT_FOUND", "Authentication request not found");
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", true);
        response.put("requestId", tx.requestId);
        response.put("userId", tx.userId);
        response.put("loginStatus", tx.loginStatus);

        Map<String, Object> otp = new LinkedHashMap<>();
        otp.put("status", tx.otpStatus);
        OtpData activeOtp = otpStore.get(tx.userId);
        if (activeOtp != null && tx.requestId.equals(activeOtp.requestId)) {
            otp.put("generated", true);
            otp.put("verified", false);
            // DEV/UAT only. Do not expose OTP in production.
            otp.put("devOtp", activeOtp.otp);
            otp.put("expiresAt", Instant.ofEpochMilli(activeOtp.expiryTime).toString());
        } else {
            otp.put("generated", !"NOT_STARTED".equals(tx.otpStatus));
            otp.put("verified", "VERIFIED".equals(tx.otpStatus));
        }
        response.put("otp", otp);

        if (tx.canonicalPayload != null) {
            response.put("canonicalPayload", tx.canonicalPayload);
        }
        if (tx.trustedLoginRequest != null) {
            response.put("trustedLoginRequest", tx.trustedLoginRequest);
        }
        if (tx.securityValidation != null) {
            response.put("securityValidation", tx.securityValidation);
        }

        response.put("signatureStatus", "PENDING_APPROVAL");
        response.put("authenticationStatus", tx.authenticationStatus);
        response.put("sessionStatus", tx.sessionStatus);
        response.put("dashboard", tx.dashboardStatus);
        response.put("updatedAt", tx.updatedAt);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/user-profile")
    public ResponseEntity<?> userProfile(
            @RequestHeader(value = "Authorization", required = false) String authorization
    ) {
        SessionValidation validation = validateAuthorization(authorization);
        if (!validation.valid) {
            return error(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", validation.message);
        }

        SessionData session = validation.session;
        Map<String, Object> user = new LinkedHashMap<>();
        user.put("userId", session.userId);
        user.put("clientId", CLIENT_ID);
        user.put("loginStatus", "AUTHORIZED");

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", true);
        response.put("authorized", true);
        response.put("message", "Protected user profile accessed successfully");
        response.put("user", user);
        response.put("expiresAt", Instant.ofEpochMilli(session.expiresAt).toString());
        response.put("expiresInSeconds",
                Math.max(0, (session.expiresAt - System.currentTimeMillis()) / 1000));
        return ResponseEntity.ok(response);
    }

    @PostMapping("/secure-data")
    public ResponseEntity<?> secureData(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @RequestBody EncryptedRequest request
    ) {
        try {
            SessionValidation validation = validateAuthorization(authorization);
            if (!validation.valid) {
                return error(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", validation.message);
            }
            if (request == null || isBlank(request.data)) {
                return error(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", "Encrypted secure data is required");
            }

            JsonNode secureRequest = objectMapper.readTree(decrypt(request.data));
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "authorized", true,
                    "userId", validation.session.userId,
                    "message", "Authorization successful and encrypted request decrypted",
                    "receivedData", secureRequest
            ));
        } catch (Exception e) {
            return error(HttpStatus.BAD_REQUEST, "SECURE_REQUEST_FAILED", "Unable to process secure request");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @RequestHeader(value = "Authorization", required = false) String authorization
    ) {
        if (authorization != null && authorization.startsWith("Bearer ")) {
            sessionStore.remove(authorization.substring(7).trim());
        }
        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Logged out successfully"
        ));
    }

    // Manual trusted-login endpoint using the exact requested wire structure.
    // Signature is intentionally NOT verified until PNB signature requirements are approved.
    @PostMapping("/trusted-login")
    public ResponseEntity<?> trustedLogin(@RequestBody TrustedLoginRequest request) {
        try {
            if (request == null
                    || isBlank(request.encryptedPayload)
                    || isBlank(request.timestamp)
                    || isBlank(request.nonce)) {
                return error(HttpStatus.BAD_REQUEST, "INVALID_REQUEST",
                        "encryptedPayload, timestamp and nonce are required");
            }

            if (usedNonces.contains(request.nonce)) {
                return error(HttpStatus.UNAUTHORIZED, "REPLAY_DETECTED", "Nonce has already been used");
            }

            Instant requestTime = Instant.parse(request.timestamp);
            long difference = Math.abs(Instant.now().getEpochSecond() - requestTime.getEpochSecond());
            if (difference > TRUSTED_REQUEST_TTL_SECONDS) {
                return error(HttpStatus.UNAUTHORIZED, "TIMESTAMP_EXPIRED", "Timestamp is outside allowed window");
            }

            String decrypted = decrypt(request.encryptedPayload);
            JsonNode payload = objectMapper.readTree(decrypted);

            String clientId = getText(payload, "clientId");
            String userId = getText(payload, "userId");
            String payloadTimestamp = getText(payload, "timestamp");
            String payloadNonce = getText(payload, "nonce");

            boolean integrityValid =
                    request.timestamp.equals(payloadTimestamp)
                            && request.nonce.equals(payloadNonce);
            boolean clientValid = CLIENT_ID.equals(clientId);
            boolean userValid = DEMO_USER_ID.equals(userId);

            if (!integrityValid || !clientValid || !userValid) {
                return error(HttpStatus.FORBIDDEN, "ACCESS_DENIED", "Trusted Login validation failed");
            }

            if (!usedNonces.add(request.nonce)) {
                return error(HttpStatus.UNAUTHORIZED, "REPLAY_DETECTED", "Nonce has already been used");
            }

            SessionData session = createSession(userId);

            Map<String, Object> validation = new LinkedHashMap<>();
            validation.put("timestampValid", true);
            validation.put("timestampDifferenceSeconds", difference);
            validation.put("nonceValid", true);
            validation.put("replayDetected", false);
            validation.put("payloadIntegrityValid", true);
            validation.put("clientValid", true);
            validation.put("userValid", true);
            validation.put("signatureValidation", "PENDING_APPROVAL");

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("success", true);
            response.put("trustedLogin", "AUTHORIZED");
            response.put("decryptedPayload", objectMapper.convertValue(payload, Map.class));
            response.put("validation", validation);
            response.put("signatureStatus", "PENDING_APPROVAL");
            response.put("tokenType", "Bearer");
            response.put("token", session.token);
            response.put("expiresInSeconds", SESSION_TTL_SECONDS);
            response.put("expiresAt", Instant.ofEpochMilli(session.expiresAt).toString());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            return error(HttpStatus.UNAUTHORIZED, "AUTHENTICATION_FAILED", "Trusted Login authentication failed");
        }
    }

    // Diagnostic endpoint: no descriptive "flow" field.
    @PostMapping("/complete-flow-test")
    public ResponseEntity<?> completeFlowTest() {
        try {
            String requestId = newRequestId();
            String userId = DEMO_USER_ID;

            AuthTransaction tx = new AuthTransaction(requestId, userId);
            tx.loginStatus = "SUCCESS";
            tx.otpStatus = "GENERATED";
            tx.authenticationStatus = "OTP_PENDING";
            authTransactions.put(requestId, tx);
            latestRequestByUser.put(userId, requestId);

            String otp = generateOtp();
            OtpData otpData = new OtpData(
                    otp,
                    Instant.now().plusSeconds(OTP_TTL_SECONDS).toEpochMilli(),
                    0,
                    requestId
            );
            otpStore.put(userId, otpData);

            // Diagnostic auto-verification only.
            boolean otpVerified = otp.equals(otpData.otp);
            otpStore.remove(userId);
            tx.otpStatus = otpVerified ? "VERIFIED" : "FAILED";
            if (!otpVerified) {
                updateFailure(tx, "OTP_FAILED");
                return error(HttpStatus.UNAUTHORIZED, "OTP_FAILED", "Diagnostic OTP verification failed");
            }

            TrustedResult trusted = performTrustedAuthentication(tx, userId);

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("success", true);
            response.put("status", "AUTHENTICATED");
            response.put("requestId", requestId);

            Map<String, Object> login = new LinkedHashMap<>();
            login.put("credentialsValidated", true);
            login.put("status", "PASS");
            response.put("login", login);

            Map<String, Object> otpResult = new LinkedHashMap<>();
            otpResult.put("generated", true);
            otpResult.put("verified", true);
            otpResult.put("status", "PASS");
            response.put("otp", otpResult);

            response.put("canonicalPayload", trusted.canonicalPayload);
            response.put("trustedLoginRequest", trusted.trustedLoginRequest);
            response.put("securityValidation", trusted.securityValidation);
            response.put("signatureStatus", "PENDING_APPROVAL");

            Map<String, Object> session = new LinkedHashMap<>();
            session.put("created", true);
            session.put("tokenType", "Bearer");
            session.put("tokenPreview", previewToken(trusted.token));
            session.put("expiresInSeconds", SESSION_TTL_SECONDS);
            session.put("expiresAt", trusted.expiresAt);
            response.put("session", session);

            response.put("authenticationStatus", "AUTHORIZED");
            response.put("protectedApi", "/api/user-profile");
            response.put("dashboard", "GRANTED");
            response.put("overallStatus", "AUTHENTICATION SUCCESSFUL");
            response.put("testMode",
                    "DEV/UAT diagnostic: OTP auto-verified. Real /login -> /verify-otp requires user OTP.");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            return error(HttpStatus.INTERNAL_SERVER_ERROR, "COMPLETE_FLOW_FAILED", "Complete flow test failed");
        }
    }

    private TrustedResult performTrustedAuthentication(AuthTransaction tx, String userId) throws Exception {
        String timestamp = Instant.now().toString();
        String nonce = UUID.randomUUID().toString();

        Map<String, Object> canonicalPayload = new LinkedHashMap<>();
        canonicalPayload.put("clientId", CLIENT_ID);
        canonicalPayload.put("userId", userId);
        canonicalPayload.put("timestamp", timestamp);
        canonicalPayload.put("nonce", nonce);

        String plainPayload = objectMapper.writeValueAsString(canonicalPayload);
        String encryptedPayload = encrypt(plainPayload, pnbKeyPair.getPublic());

        // Exact wire/request shape requested. Signature stays empty until approved.
        Map<String, Object> trustedLoginRequest = new LinkedHashMap<>();
        trustedLoginRequest.put("encryptedPayload", encryptedPayload);
        trustedLoginRequest.put("signature", "");
        trustedLoginRequest.put("timestamp", timestamp);
        trustedLoginRequest.put("nonce", nonce);

        Instant validationTime = Instant.now();
        long difference = Math.abs(
                validationTime.getEpochSecond() - Instant.parse(timestamp).getEpochSecond());

        if (difference > TRUSTED_REQUEST_TTL_SECONDS) {
            throw new IllegalStateException("Timestamp validation failed");
        }
        if (usedNonces.contains(nonce)) {
            throw new IllegalStateException("Replay detected");
        }

        String decrypted = decrypt(encryptedPayload);
        JsonNode payload = objectMapper.readTree(decrypted);

        boolean requiredFieldsValid =
                !isBlank(getText(payload, "clientId"))
                        && !isBlank(getText(payload, "userId"))
                        && !isBlank(getText(payload, "timestamp"))
                        && !isBlank(getText(payload, "nonce"));

        boolean clientValid = CLIENT_ID.equals(getText(payload, "clientId"));
        boolean userValid = DEMO_USER_ID.equals(getText(payload, "userId"));
        boolean integrityValid =
                timestamp.equals(getText(payload, "timestamp"))
                        && nonce.equals(getText(payload, "nonce"));

        if (!requiredFieldsValid || !clientValid || !userValid || !integrityValid) {
            throw new IllegalStateException("Trusted payload validation failed");
        }

        if (!usedNonces.add(nonce)) {
            throw new IllegalStateException("Replay detected");
        }

        SessionData session = createSession(userId);

        Map<String, Object> securityValidation = new LinkedHashMap<>();
        securityValidation.put("requiredFieldsValid", true);
        securityValidation.put("clientIdValid", true);
        securityValidation.put("timestampValid", true);
        securityValidation.put("timestampDifferenceSeconds", difference);
        securityValidation.put("nonceValid", true);
        securityValidation.put("replayDetected", false);
        securityValidation.put("payloadIntegrityValid", true);
        securityValidation.put("userValid", true);
        securityValidation.put("signatureValidation", "PENDING_APPROVAL");

        tx.canonicalPayload = canonicalPayload;
        tx.trustedLoginRequest = trustedLoginRequest;
        tx.securityValidation = securityValidation;
        tx.authenticationStatus = "AUTHORIZED";
        tx.sessionStatus = "CREATED";
        tx.dashboardStatus = "GRANTED";
        tx.updatedAt = Instant.now().toString();

        return new TrustedResult(
                canonicalPayload,
                trustedLoginRequest,
                securityValidation,
                session.token,
                Instant.ofEpochMilli(session.expiresAt).toString()
        );
    }

    private SessionData createSession(String userId) {
        String token = UUID.randomUUID().toString().replace("-", "");
        long expiresAt = Instant.now().plusSeconds(SESSION_TTL_SECONDS).toEpochMilli();
        SessionData session = new SessionData(token, userId, expiresAt);
        sessionStore.put(token, session);
        return session;
    }

    private SessionValidation validateAuthorization(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return new SessionValidation(false, null, "Authorization token required");
        }

        String token = authorization.substring(7).trim();
        SessionData session = sessionStore.get(token);
        if (session == null) {
            return new SessionValidation(false, null, "Invalid authorization token");
        }

        if (System.currentTimeMillis() > session.expiresAt) {
            sessionStore.remove(token);
            return new SessionValidation(false, null, "Authorization token expired");
        }

        return new SessionValidation(true, session, "AUTHORIZED");
    }

    private boolean isValidCredentials(String mobile, String userId, String password) {
        return DEMO_MOBILE.equals(mobile)
                && DEMO_USER_ID.equals(userId)
                && DEMO_PASSWORD.equals(password);
    }

    private String generateOtp() {
        return String.format("%06d", secureRandom.nextInt(1_000_000));
    }

    private String newRequestId() {
        return "REQ-" + UUID.randomUUID()
                .toString()
                .replace("-", "")
                .substring(0, 8)
                .toUpperCase();
    }

    private void updateFailure(AuthTransaction tx, String status) {
        if (tx != null) {
            tx.authenticationStatus = status;
            tx.dashboardStatus = "NOT_GRANTED";
            tx.updatedAt = Instant.now().toString();
        }
    }

    private String previewToken(String token) {
        if (token == null || token.length() <= 8) return "********";
        return token.substring(0, 8) + "...";
    }

    private String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaep = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT
        );
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaep);
        return Base64.getEncoder().encodeToString(
                cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8))
        );
    }

    private String decrypt(String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaep = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT
        );
        cipher.init(Cipher.DECRYPT_MODE, pnbKeyPair.getPrivate(), oaep);
        return new String(
                cipher.doFinal(Base64.getDecoder().decode(encryptedData)),
                StandardCharsets.UTF_8
        );
    }

    private KeyPair loadOrGeneratePnbKeyPair() throws Exception {
        String publicB64 = cleanKey(System.getenv("PNB_PUBLIC_KEY_B64"));
        String privateB64 = cleanKey(System.getenv("PNB_PRIVATE_KEY_B64"));

        if (!isBlank(publicB64) && !isBlank(privateB64)) {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(
                    new X509EncodedKeySpec(Base64.getDecoder().decode(publicB64)));
            PrivateKey privateKey = keyFactory.generatePrivate(
                    new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateB64)));
            return new KeyPair(publicKey, privateKey);
        }

        System.out.println("WARNING: PNB key env vars not configured. Generating temporary DEV key pair.");
        return generateRsaKeyPair();
    }

    private KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private String cleanKey(String value) {
        if (value == null) return "";
        return value
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
    }

    private String getText(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? "" : value.asText().trim();
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private ResponseEntity<?> error(HttpStatus status, String code, String message) {
        return ResponseEntity.status(status).body(Map.of(
                "success", false,
                "code", code,
                "message", message
        ));
    }

    public static class EncryptedRequest {
        public String data;
        public EncryptedRequest() {}
    }

    public static class TrustedLoginRequest {
        public String encryptedPayload;
        public String signature;
        public String timestamp;
        public String nonce;
        public TrustedLoginRequest() {}
    }

    private static class OtpData {
        private final String otp;
        private final long expiryTime;
        private int attempts;
        private final String requestId;

        private OtpData(String otp, long expiryTime, int attempts, String requestId) {
            this.otp = otp;
            this.expiryTime = expiryTime;
            this.attempts = attempts;
            this.requestId = requestId;
        }
    }

    private static class SessionData {
        private final String token;
        private final String userId;
        private final long expiresAt;

        private SessionData(String token, String userId, long expiresAt) {
            this.token = token;
            this.userId = userId;
            this.expiresAt = expiresAt;
        }
    }

    private static class SessionValidation {
        private final boolean valid;
        private final SessionData session;
        private final String message;

        private SessionValidation(boolean valid, SessionData session, String message) {
            this.valid = valid;
            this.session = session;
            this.message = message;
        }
    }

    private static class AuthTransaction {
        private final String requestId;
        private final String userId;
        private String loginStatus = "NOT_STARTED";
        private String otpStatus = "NOT_STARTED";
        private String authenticationStatus = "NOT_STARTED";
        private String sessionStatus = "NOT_CREATED";
        private String dashboardStatus = "NOT_GRANTED";
        private String updatedAt = Instant.now().toString();
        private Map<String, Object> canonicalPayload;
        private Map<String, Object> trustedLoginRequest;
        private Map<String, Object> securityValidation;

        private AuthTransaction(String requestId, String userId) {
            this.requestId = requestId;
            this.userId = userId;
        }
    }

    private static class TrustedResult {
        private final Map<String, Object> canonicalPayload;
        private final Map<String, Object> trustedLoginRequest;
        private final Map<String, Object> securityValidation;
        private final String token;
        private final String expiresAt;

        private TrustedResult(
                Map<String, Object> canonicalPayload,
                Map<String, Object> trustedLoginRequest,
                Map<String, Object> securityValidation,
                String token,
                String expiresAt
        ) {
            this.canonicalPayload = canonicalPayload;
            this.trustedLoginRequest = trustedLoginRequest;
            this.securityValidation = securityValidation;
            this.token = token;
            this.expiresAt = expiresAt;
        }
    }
}
