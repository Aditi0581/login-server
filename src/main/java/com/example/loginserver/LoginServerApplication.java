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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;

import java.security.spec.MGF1ParameterSpec;

import java.time.Instant;

import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class LoginServerApplication {

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final SecureRandom secureRandom = new SecureRandom();

    private KeyPair keyPair;

    // Demo "Your App" signing key pair.
    // Production: app private key must remain outside the PNB server.
    private KeyPair appKeyPair;

    // Demo anti-replay cache. Production should use Redis/shared persistent cache.
    private final Set<String> usedNonces = ConcurrentHashMap.newKeySet();

    // userId -> OTP information
    private final Map<String, OtpData> otpStore =
            new ConcurrentHashMap<>();

    // token -> userId
    private final Map<String, String> tokenStore =
            new ConcurrentHashMap<>();


    // ========================================================
    // APPLICATION START
    // ========================================================

    public static void main(String[] args) {

        SpringApplication.run(
                LoginServerApplication.class,
                args
        );
    }


    // ========================================================
    // CONSTRUCTOR - GENERATE RSA KEY PAIR
    // ========================================================

    public LoginServerApplication() throws Exception {

        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048);

        keyPair =
                generator.generateKeyPair();

        KeyPairGenerator appGenerator =
                KeyPairGenerator.getInstance("RSA");

        appGenerator.initialize(2048);

        appKeyPair =
                appGenerator.generateKeyPair();

        System.out.println();
        System.out.println(
                "======================================"
        );
        System.out.println(
                "RSA KEY PAIR GENERATED"
        );
        System.out.println(
                "Public key can be sent to Flutter"
        );
        System.out.println(
                "Private key remains on server"
        );
        System.out.println(
                "======================================"
        );
        System.out.println();
    }


    // ========================================================
    // TEST API
    // ========================================================

    @GetMapping("/test")
    public ResponseEntity<?> test() {

        return ResponseEntity.ok(
                Map.of(
                        "success", true,
                        "message",
                        "Java server is running"
                )
        );
    }


    // ========================================================
    // PUBLIC KEY API
    // ========================================================

    @GetMapping("/public-key")
    public ResponseEntity<?> getPublicKey() {

        String publicKey =
                Base64.getEncoder()
                        .encodeToString(
                                keyPair
                                        .getPublic()
                                        .getEncoded()
                        );

        return ResponseEntity.ok(
                Map.of(
                        "success", true,
                        "algorithm",
                        "RSA-OAEP-SHA256",
                        "publicKey",
                        publicKey
                )
        );
    }


    // ========================================================
    // LOGIN API
    // ========================================================

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody EncryptedRequest request
    ) {

        try {

            if (request == null ||
                    request.data == null ||
                    request.data.isBlank()) {

                return ResponseEntity
                        .badRequest()
                        .body(
                                Map.of(
                                        "success",
                                        false,

                                        "message",
                                        "Encrypted data is required"
                                )
                        );
            }


            // =================================================
            // DECRYPT LOGIN DATA USING PRIVATE KEY
            // =================================================

            String decrypted =
                    decrypt(
                            request.data
                    );

            System.out.println(
                    "Decrypted login request: "
                            + decrypted
            );


            JsonNode json =
                    objectMapper.readTree(
                            decrypted
                    );


            String mobile =
                    getText(
                            json,
                            "mobile"
                    );

            String userId =
                    getText(
                            json,
                            "userId"
                    );

            String password =
                    getText(
                            json,
                            "password"
                    );


            // =================================================
            // VALIDATE FIELDS
            // =================================================

            if (mobile.isBlank() ||
                    userId.isBlank() ||
                    password.isBlank()) {

                return ResponseEntity
                        .badRequest()
                        .body(
                                Map.of(
                                        "success",
                                        false,

                                        "message",
                                        "Mobile, User ID and password are required"
                                )
                        );
            }


            // =================================================
            // DEMO LOGIN VALIDATION
            // =================================================

            boolean validLogin =
                    mobile.equals(
                            "9876543210"
                    )
                            &&
                            userId.equals(
                                    "testuser"
                            )
                            &&
                            password.equals(
                                    "Test@123"
                            );


            if (!validLogin) {

                return ResponseEntity
                        .status(
                                HttpStatus.UNAUTHORIZED
                        )
                        .body(
                                Map.of(
                                        "success",
                                        false,

                                        "message",
                                        "Invalid credentials"
                                )
                        );
            }


            // =================================================
            // RANDOM 6 DIGIT OTP
            // =================================================

            String otp =
                    String.format(
                            "%06d",
                            secureRandom.nextInt(
                                    1_000_000
                            )
                    );


            // =================================================
            // OTP EXPIRY = 2 MINUTES
            // =================================================

            long expiryTime =
                    Instant.now()
                            .plusSeconds(120)
                            .toEpochMilli();


            OtpData otpData =
                    new OtpData(
                            otp,
                            expiryTime,
                            0
                    );


            otpStore.put(
                    userId,
                    otpData
            );

             System.out.println("DEBUG LOGIN INSTANCE : " + System.identityHashCode(this));
System.out.println("DEBUG LOGIN USER     : [" + userId + "]");
System.out.println("DEBUG OTP STORE SIZE : " + otpStore.size());
System.out.println("DEBUG OTP KEYS       : " + otpStore.keySet());
            // =================================================
            // DEVELOPMENT OTP OUTPUT
            // =================================================

            System.out.println();
            System.out.println(
                    "======================================"
            );
            System.out.println(
                    "OTP GENERATED"
            );
            System.out.println(
                    "User ID : " + userId
            );
            System.out.println(
                    "OTP     : " + otp
            );
            System.out.println(
                    "Expiry  : 2 minutes"
            );
            System.out.println(
                    "======================================"
            );
            System.out.println();


            return ResponseEntity.ok(
                    Map.of(
                            "success",
                            true,

                            "message",
                            "Login successful. OTP generated.",

                            "userId",
                            userId,

                            "otpExpiresIn",
                            120
                    )
            );


        } catch (Exception e) {

            e.printStackTrace();

            return ResponseEntity
                    .status(
                            HttpStatus.BAD_REQUEST
                    )
                    .body(
                            Map.of(
                                    "success",
                                    false,

                                    "message",
                                    "Unable to process encrypted login request"
                            )
                    );
        }
    }


    // ========================================================
    // VERIFY OTP
    // ========================================================

    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(
            @RequestBody EncryptedRequest request
    ) {

        try {

            if (request == null ||
                    request.data == null ||
                    request.data.isBlank()) {

                return ResponseEntity
                        .badRequest()
                        .body(
                                Map.of(
                                        "success",
                                        false,

                                        "message",
                                        "Encrypted OTP data is required"
                                )
                        );
            }


            // =================================================
            // DECRYPT OTP REQUEST
            // =================================================

            String decrypted =
                    decrypt(
                            request.data
                    );


            System.out.println(
                    "Decrypted OTP request: "
                            + decrypted
            );


            JsonNode json =
                    objectMapper.readTree(
                            decrypted
                    );


            String userId =
                    getText(
                            json,
                            "userId"
                    );


            String otp =
                    getText(
                            json,
                            "otp"
                    );


            if (userId.isBlank() ||
                    otp.isBlank()) {

                return ResponseEntity
                        .badRequest()
                        .body(
                                Map.of(
                                        "success",
                                        false,

                                        "message",
                                        "User ID and OTP are required"
                                )
                        );
            }


            // =================================================
            // FIND OTP
            // =================================================
System.out.println();
System.out.println("======================================");
System.out.println("OTP STORE DEBUG - BEFORE VERIFY");
System.out.println("DEBUG VERIFY INSTANCE : " + System.identityHashCode(this));
System.out.println("DEBUG VERIFY USER     : [" + userId + "]");
System.out.println("DEBUG OTP STORE SIZE  : " + otpStore.size());
System.out.println("DEBUG OTP KEYS        : " + otpStore.keySet());
System.out.println("======================================");
System.out.println();

            OtpData savedOtp =
                    otpStore.get(
                            userId
                    );


            if (savedOtp == null) {

                return ResponseEntity
                        .status(
                                HttpStatus.UNAUTHORIZED
                        )
                        .body(
                                Map.of(
                                        "success",
                                        false,

                                        "message",
                                        "OTP not found. Please login again."
                                )
                        );
            }


            // =================================================
            // OTP EXPIRY CHECK
            // =================================================

            if (System.currentTimeMillis()
                    > savedOtp.expiryTime) {

                otpStore.remove(
                        userId
                );


                return ResponseEntity
                        .status(
                                HttpStatus.UNAUTHORIZED
                        )
                        .body(
                                Map.of(
                                        "success",
                                        false,

                                        "message",
                                        "OTP expired. Please login again."
                                )
                        );
            }


            // =================================================
            // MAXIMUM ATTEMPTS CHECK
            // =================================================

            if (savedOtp.attempts >= 3) {

                otpStore.remove(
                        userId
                );


                return ResponseEntity
                        .status(
                                HttpStatus.UNAUTHORIZED
                        )
                        .body(
                                Map.of(
                                        "success",
                                        false,

                                        "message",
                                        "Maximum OTP attempts exceeded."
                                )
                        );
            }


            // =================================================
            // WRONG OTP
            // =================================================

            if (!savedOtp.otp.equals(
                    otp
            )) {

                savedOtp.attempts++;


                int remainingAttempts =
                        3 - savedOtp.attempts;


                if (remainingAttempts <= 0) {

                    otpStore.remove(
                            userId
                    );
                }


                return ResponseEntity
                        .status(
                                HttpStatus.UNAUTHORIZED
                        )
                        .body(
                                Map.of(
                                        "success",
                                        false,

                                        "message",
                                        "Invalid OTP",

                                        "remainingAttempts",
                                        Math.max(
                                                remainingAttempts,
                                                0
                                        )
                                )
                        );
            }


            // =================================================
            // OTP CORRECT
            // =================================================

            otpStore.remove(
                    userId
            );


            // =================================================
            // GENERATE AUTHORIZATION TOKEN
            // =================================================

            String token =
                    UUID.randomUUID()
                            .toString()
                            .replace(
                                    "-",
                                    ""
                            );


            tokenStore.put(
                    token,
                    userId
            );


            System.out.println();
            System.out.println(
                    "======================================"
            );
            System.out.println(
                    "OTP VERIFIED"
            );
            System.out.println(
                    "User ID : " + userId
            );
            System.out.println(
                    "Authorization token generated"
            );
            System.out.println(
                    "======================================"
            );
            System.out.println();


            return ResponseEntity.ok(
                    Map.of(
                            "success",
                            true,

                            "message",
                            "OTP verified successfully",

                            "userId",
                            userId,

                            "token",
                            token
                    )
            );


        } catch (Exception e) {

            e.printStackTrace();

            return ResponseEntity
                    .status(
                            HttpStatus.BAD_REQUEST
                    )
                    .body(
                            Map.of(
                                    "success",
                                    false,

                                    "message",
                                    "Unable to verify OTP"
                            )
                    );
        }
    }


    // ========================================================
    // RESEND OTP
    // ========================================================

    @PostMapping("/resend-otp")
    public ResponseEntity<?> resendOtp(
            @RequestBody EncryptedRequest request
    ) {

        try {

            if (request == null ||
                    request.data == null ||
                    request.data.isBlank()) {

                return ResponseEntity
                        .badRequest()
                        .body(
                                Map.of(
                                        "success",
                                        false,

                                        "message",
                                        "Encrypted data is required"
                                )
                        );
            }


            String decrypted =
                    decrypt(
                            request.data
                    );


            JsonNode json =
                    objectMapper.readTree(
                            decrypted
                    );


            String userId =
                    getText(
                            json,
                            "userId"
                    );


            if (userId.isBlank()) {

                return ResponseEntity
                        .badRequest()
                        .body(
                                Map.of(
                                        "success",
                                        false,

                                        "message",
                                        "User ID is required"
                                )
                        );
            }


            // =================================================
            // GENERATE NEW RANDOM OTP
            // =================================================

            String otp =
                    String.format(
                            "%06d",
                            secureRandom.nextInt(
                                    1_000_000
                            )
                    );


            long expiryTime =
                    Instant.now()
                            .plusSeconds(120)
                            .toEpochMilli();


            otpStore.put(
                    userId,
                    new OtpData(
                            otp,
                            expiryTime,
                            0
                    )
            );


            System.out.println();
            System.out.println(
                    "======================================"
            );
            System.out.println(
                    "OTP RESENT"
            );
            System.out.println(
                    "User ID : " + userId
            );
            System.out.println(
                    "OTP     : " + otp
            );
            System.out.println(
                    "Expiry  : 2 minutes"
            );
            System.out.println(
                    "======================================"
            );
            System.out.println();


            return ResponseEntity.ok(
                    Map.of(
                            "success",
                            true,

                            "message",
                            "New OTP generated",

                            "otpExpiresIn",
                            120
                    )
            );


        } catch (Exception e) {

            e.printStackTrace();

            return ResponseEntity
                    .badRequest()
                    .body(
                            Map.of(
                                    "success",
                                    false,

                                    "message",
                                    "Unable to resend OTP"
                            )
                    );
        }
    }


    // ========================================================
    // SECURE / PROTECTED API
    // ========================================================

    @PostMapping("/secure-data")
    public ResponseEntity<?> secureData(

            @RequestHeader(
                    value = "Authorization",
                    required = false
            )
            String authorization,

            @RequestBody EncryptedRequest request
    ) {

        try {

            // =================================================
            // CHECK AUTHORIZATION HEADER
            // =================================================

            if (authorization == null ||
                    !authorization.startsWith(
                            "Bearer "
                    )) {

                return ResponseEntity
                        .status(
                                HttpStatus.UNAUTHORIZED
                        )
                        .body(
                                Map.of(
                                        "success",
                                        false,

                                        "message",
                                        "Authorization token required"
                                )
                        );
            }


            String token =
                    authorization
                            .substring(7)
                            .trim();


            String userId =
                    tokenStore.get(
                            token
                    );


            // =================================================
            // INVALID TOKEN
            // =================================================

            if (userId == null) {

                return ResponseEntity
                        .status(
                                HttpStatus.UNAUTHORIZED
                        )
                        .body(
                                Map.of(
                                        "success",
                                        false,

                                        "message",
                                        "Invalid authorization token"
                                )
                        );
            }


            if (request == null ||
                    request.data == null ||
                    request.data.isBlank()) {

                return ResponseEntity
                        .badRequest()
                        .body(
                                Map.of(
                                        "success",
                                        false,

                                        "message",
                                        "Encrypted secure data is required"
                                )
                        );
            }


            // =================================================
            // PRIVATE KEY DECRYPTION
            // =================================================

            String decryptedData =
                    decrypt(
                            request.data
                    );


            JsonNode secureRequest =
                    objectMapper.readTree(
                            decryptedData
                    );


            System.out.println();
            System.out.println(
                    "======================================"
            );
            System.out.println(
                    "AUTHORIZED SECURE API CALL"
            );
            System.out.println(
                    "User ID : " + userId
            );
            System.out.println(
                    "Encrypted request received"
            );
            System.out.println(
                    "Decrypted data : "
                            + decryptedData
            );
            System.out.println(
                    "======================================"
            );
            System.out.println();


            return ResponseEntity.ok(
                    Map.of(
                            "success",
                            true,

                            "authorized",
                            true,

                            "userId",
                            userId,

                            "message",
                            "Authorization successful and encrypted request decrypted",

                            "receivedData",
                            secureRequest
                    )
            );


        } catch (Exception e) {

            e.printStackTrace();

            return ResponseEntity
                    .badRequest()
                    .body(
                            Map.of(
                                    "success",
                                    false,

                                    "message",
                                    "Unable to process secure request"
                            )
                    );
        }
    }


    // ========================================================
    // LOGOUT
    // ========================================================

    @PostMapping("/logout")
    public ResponseEntity<?> logout(

            @RequestHeader(
                    value = "Authorization",
                    required = false
            )
            String authorization
    ) {

        if (authorization != null &&
                authorization.startsWith(
                        "Bearer "
                )) {

            String token =
                    authorization
                            .substring(7)
                            .trim();


            tokenStore.remove(
                    token
            );
        }


        return ResponseEntity.ok(
                Map.of(
                        "success",
                        true,

                        "message",
                        "Logged out successfully"
                )
        );
    }




    // ========================================================
    // TRUSTED LOGIN - SINGLE API DEMO
    // ========================================================

    @GetMapping("/app-public-key")
    public ResponseEntity<?> getAppPublicKey() {
        String publicKey = Base64.getEncoder()
                .encodeToString(appKeyPair.getPublic().getEncoded());

        return ResponseEntity.ok(Map.of(
                "success", true,
                "purpose", "Trusted Login signature verification",
                "algorithm", "SHA256withRSA",
                "publicKey", publicKey
        ));
    }


    // Single endpoint for Postman/demo testing.
    // It simulates BOTH logical sides from the integration document:
    // 1) Your App creates timestamp/nonce, encrypts and signs.
    // 2) PNB side verifies signature, decrypts, validates and authorizes.
    // Production must keep client signing and PNB verification on separate sides.
    @PostMapping("/trusted-login")
    public ResponseEntity<?> trustedLogin(@RequestBody TrustedLoginPayload request) {
        try {
            if (request == null || isBlank(request.clientId) || isBlank(request.userId)) {
                return trustedLoginRejected(HttpStatus.BAD_REQUEST, "INVALID_REQUEST",
                        "clientId and userId are required");
            }

            String clientId = request.clientId.trim();
            String userId = request.userId.trim();

            // App side: create canonical payload.
            String timestamp = Instant.now().toString();
            String nonce = UUID.randomUUID().toString();

            Map<String, Object> canonicalPayload = new java.util.LinkedHashMap<>();
            canonicalPayload.put("clientId", clientId);
            canonicalPayload.put("userId", userId);
            canonicalPayload.put("timestamp", timestamp);
            canonicalPayload.put("nonce", nonce);

            String plainPayload = objectMapper.writeValueAsString(canonicalPayload);

            // App side: encrypt with PNB public key.
            String encryptedPayload = encrypt(plainPayload, keyPair.getPublic());

            // App side: sign encryptedPayload|timestamp|nonce with App private key.
            String signingInput = encryptedPayload + "|" + timestamp + "|" + nonce;
            String signature = sign(signingInput, appKeyPair.getPrivate());

            // PNB side: timestamp validation.
            Instant validationTime = Instant.now();
            Instant requestTime = Instant.parse(timestamp);
            long skewSeconds = Math.abs(
                    validationTime.getEpochSecond() - requestTime.getEpochSecond());

            if (skewSeconds > 120) {
                return trustedLoginRejected(HttpStatus.UNAUTHORIZED,
                        "TIMESTAMP_EXPIRED", "Session expired");
            }

            // PNB side: replay pre-check.
            if (usedNonces.contains(nonce)) {
                return trustedLoginRejected(HttpStatus.UNAUTHORIZED,
                        "REPLAY_DETECTED", "Session expired");
            }

            // PNB side: verify signature with registered App public key.
            boolean signatureValid = verifySignature(
                    signingInput, signature, appKeyPair.getPublic());

            if (!signatureValid) {
                return trustedLoginRejected(HttpStatus.UNAUTHORIZED,
                        "SIGNATURE_INVALID", "Authentication failed");
            }

            // PNB side: decrypt with PNB private key.
            String decryptedPayload = decrypt(encryptedPayload);
            JsonNode payload = objectMapper.readTree(decryptedPayload);

            String decryptedClientId = getText(payload, "clientId");
            String decryptedUserId = getText(payload, "userId");
            String decryptedTimestamp = getText(payload, "timestamp");
            String decryptedNonce = getText(payload, "nonce");

            if (!clientId.equals(decryptedClientId)
                    || !userId.equals(decryptedUserId)
                    || !timestamp.equals(decryptedTimestamp)
                    || !nonce.equals(decryptedNonce)) {
                return trustedLoginRejected(HttpStatus.UNAUTHORIZED,
                        "PAYLOAD_INVALID", "Invalid request");
            }

            // Demo identity validation.
            if (!clientId.equals("PNB_APP") || !userId.equals("123456")) {
                return trustedLoginRejected(HttpStatus.FORBIDDEN,
                        "ACCESS_DENIED", "Access denied");
            }

            // Atomic nonce claim.
            if (!usedNonces.add(nonce)) {
                return trustedLoginRejected(HttpStatus.UNAUTHORIZED,
                        "REPLAY_DETECTED", "Session expired");
            }

            // Generate authorization token.
            String token = UUID.randomUUID().toString().replace("-", "");
            tokenStore.put(token, userId);

            // Public keys are safe to display for this demo.
            String pnbPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())
                    + "\n-----END PUBLIC KEY-----";

            String appPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getEncoder().encodeToString(appKeyPair.getPublic().getEncoded())
                    + "\n-----END PUBLIC KEY-----";

            Map<String, Object> requestDetails = new java.util.LinkedHashMap<>();
            requestDetails.put("clientId", clientId);
            requestDetails.put("userId", userId);

            Map<String, Object> keys = new java.util.LinkedHashMap<>();
            keys.put("pnbPublicKey", pnbPublicKey);
            keys.put("pnbPrivateKey", "NOT EXPOSED");
            keys.put("appPublicKey", appPublicKey);
            keys.put("appPrivateKey", "NOT EXPOSED");

            Map<String, Object> keyUsage = new java.util.LinkedHashMap<>();
            keyUsage.put("encryption", "PNB Public Key");
            keyUsage.put("decryption", "PNB Private Key");
            keyUsage.put("digitalSignature", "App Private Key");
            keyUsage.put("signatureVerification", "App Public Key");

            Map<String, Object> encryption = new java.util.LinkedHashMap<>();
            encryption.put("algorithm", "RSA-OAEP");
            encryption.put("hash", "SHA-256");
            encryption.put("mgf", "MGF1-SHA256");
            encryption.put("encryptedWith", "PNB Public Key");
            encryption.put("decryptedWith", "PNB Private Key");
            encryption.put("encryptedPayload", encryptedPayload);

            Map<String, Object> digitalSignature = new java.util.LinkedHashMap<>();
            digitalSignature.put("signingInputFormat",
                    "base64(encryptedPayload)|timestamp|nonce");
            digitalSignature.put("signingInput", signingInput);
            digitalSignature.put("algorithm", "SHA256withRSA");
            digitalSignature.put("padding",
                    "PKCS#1 v1.5 DEMO - CONFIRM WITH PNB_360");
            digitalSignature.put("signedWith", "App Private Key");
            digitalSignature.put("verifiedWith", "App Public Key");
            digitalSignature.put("signature", signature);
            digitalSignature.put("verification", "PASSED");

            Map<String, Object> timestampValidation = new java.util.LinkedHashMap<>();
            timestampValidation.put("requestTimestamp", timestamp);
            timestampValidation.put("validationServerTimestamp",
                    validationTime.toString());
            timestampValidation.put("format", "UTC ISO-8601");
            timestampValidation.put("allowedWindowSeconds", 120);
            timestampValidation.put("differenceSeconds", skewSeconds);
            timestampValidation.put("status", "PASSED");

            Map<String, Object> replayProtection = new java.util.LinkedHashMap<>();
            replayProtection.put("nonce", nonce);
            replayProtection.put("nonceUnique", true);
            replayProtection.put("previouslyUsed", false);
            replayProtection.put("storedAfterValidation", true);
            replayProtection.put("storage",
                    "In-memory demo cache - use shared TTL store in production");
            replayProtection.put("status", "PASSED");

            Map<String, Object> decryptedPayloadDetails =
                    new java.util.LinkedHashMap<>();
            decryptedPayloadDetails.put("clientId", decryptedClientId);
            decryptedPayloadDetails.put("userId", decryptedUserId);
            decryptedPayloadDetails.put("timestamp", decryptedTimestamp);
            decryptedPayloadDetails.put("nonce", decryptedNonce);

            Map<String, Object> validations = new java.util.LinkedHashMap<>();
            validations.put("requestStructure", "PASSED");
            validations.put("timestampValidation", "PASSED");
            validations.put("nonceValidation", "PASSED");
            validations.put("replayProtection", "PASSED");
            validations.put("signatureVerification", "PASSED");
            validations.put("payloadDecryption", "PASSED");
            validations.put("payloadIntegrity", "PASSED");
            validations.put("clientValidation", "PASSED");
            validations.put("userValidation", "PASSED");
            validations.put("authorization", "PASSED");

            Map<String, Object> authorization = new java.util.LinkedHashMap<>();
            authorization.put("status", "AUTHORIZED");
            authorization.put("type", "Bearer Token");
            authorization.put("token", token);

            String requestId = "REQ-" +
                    java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
                            .withZone(java.time.ZoneOffset.UTC)
                            .format(java.time.Instant.now()) +
                    "-" + java.util.UUID.randomUUID().toString().substring(0, 8).toUpperCase();

            Map<String, Object> connection = new java.util.LinkedHashMap<>();
            connection.put("serverReachable", true);
            connection.put("requestReceived", true);
            connection.put("httpStatus", 200);

            Map<String, Object> authentication = new java.util.LinkedHashMap<>();
            authentication.put("clientId", clientId);
            authentication.put("userId", userId);
            authentication.put("signatureVerified", true);
            authentication.put("signatureAlgorithm", "RSA-SHA256");
            authentication.put("signaturePadding", "PKCS1v15");

            Map<String, Object> professionalEncryption = new java.util.LinkedHashMap<>();
            professionalEncryption.put("algorithm", "RSA-OAEP-SHA256");
            professionalEncryption.put("encryptedPayloadGenerated", true);
            professionalEncryption.put("encryptedPayload", encryptedPayload);
            professionalEncryption.put("decryptionSuccessful", true);

            Map<String, Object> professionalDecryptedPayload = new java.util.LinkedHashMap<>();
            professionalDecryptedPayload.put("clientId", decryptedClientId);
            professionalDecryptedPayload.put("userId", decryptedUserId);
            professionalDecryptedPayload.put("timestamp", decryptedTimestamp);
            professionalDecryptedPayload.put("nonce", decryptedNonce);

            Map<String, Object> securityValidation = new java.util.LinkedHashMap<>();
            securityValidation.put("timestamp", timestamp);
            securityValidation.put("timestampValid", true);
            securityValidation.put("nonce", nonce);
            securityValidation.put("nonceValid", true);
            securityValidation.put("replayDetected", false);
            securityValidation.put("clientValid", true);
            securityValidation.put("payloadIntegrityValid", true);

            Map<String, Object> keyInformation = new java.util.LinkedHashMap<>();
            keyInformation.put("encryptionKey", "PNB Public Key");
            keyInformation.put("decryptionKey", "PNB Private Key");
            keyInformation.put("signingKey", "App Private Key");
            keyInformation.put("verificationKey", "App Public Key");
            keyInformation.put("privateKeysExposed", false);

            Map<String, Object> professionalAuthorization = new java.util.LinkedHashMap<>();
            professionalAuthorization.put("userValid", true);
            professionalAuthorization.put("accessGranted", true);

            Map<String, Object> session = new java.util.LinkedHashMap<>();
            session.put("created", true);
            session.put("tokenType", "Bearer");
            session.put("sessionToken", token);

            Map<String, Object> response = new java.util.LinkedHashMap<>();
            response.put("success", true);
            response.put("status", "AUTHENTICATED");
            response.put("message", "Trusted login successful");
            response.put("requestId", requestId);
            response.put("connection", connection);
            response.put("authentication", authentication);
            response.put("encryption", professionalEncryption);
            response.put("decryptedPayload", professionalDecryptedPayload);
            response.put("securityValidation", securityValidation);
            response.put("keyInformation", keyInformation);
            response.put("authorization", professionalAuthorization);
            response.put("session", session);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            return trustedLoginRejected(HttpStatus.UNAUTHORIZED,
                    "AUTHENTICATION_FAILED", "Authentication failed");
        }
    }


    private ResponseEntity<?> trustedLoginRejected(
            HttpStatus status,
            String code,
            String message
    ) {
        return ResponseEntity.status(status).body(Map.of(
                "success", false,
                "trustedLogin", "REJECTED",
                "code", code,
                "message", message
        ));
    }


    // ========================================================
    // COMPLETE FLOW TEST API
    // DEMO / STATUS ENDPOINT ONLY
    // ========================================================

  @PostMapping("/complete-flow-test")
public ResponseEntity<?> completeFlowTest() {

    try {

        Map<String, Object> response =
                new java.util.LinkedHashMap<>();

        // ====================================================
        // SERVER CONNECTIVITY
        // ====================================================

        response.put("success", true);

        response.put(
                "serverConnectivity",
                "CONNECTED"
        );

        response.put(
                "server",
                "Render Java Spring Boot Server"
        );

        response.put(
                "serverStatus",
                "RUNNING"
        );

        response.put(
                "apiBasePath",
                "/api"
        );


        // ====================================================
        // RSA KEY STATUS
        // ====================================================

        boolean publicKeyAvailable =
                keyPair != null &&
                keyPair.getPublic() != null;

        boolean privateKeyAvailable =
                keyPair != null &&
                keyPair.getPrivate() != null;

        response.put(
                "encryptionAlgorithm",
                "RSA-OAEP-SHA256"
        );

        response.put(
                "publicKeyAvailable",
                publicKeyAvailable
        );

        response.put(
                "privateKeyAvailableOnServer",
                privateKeyAvailable
        );

        response.put(
                "privateKeyExposedToClient",
                false
        );


        // ====================================================
        // ENCRYPTION INFORMATION
        // ====================================================

        Map<String, Object> encryption =
                new java.util.LinkedHashMap<>();

        encryption.put(
                "status",
                publicKeyAvailable
                        ? "READY"
                        : "NOT READY"
        );

        encryption.put(
                "algorithm",
                "RSA-OAEP-SHA256"
        );

        encryption.put(
                "performedBy",
                "Client / Flutter / Postman helper"
        );

        encryption.put(
                "keyUsed",
                "Public Key"
        );

        encryption.put(
                "purpose",
                "Convert sensitive plain JSON into encrypted Base64 data before sending to server"
        );

        response.put(
                "encryption",
                encryption
        );


        // ====================================================
        // DECRYPTION INFORMATION
        // ====================================================

        Map<String, Object> decryption =
                new java.util.LinkedHashMap<>();

        decryption.put(
                "status",
                privateKeyAvailable
                        ? "READY"
                        : "NOT READY"
        );

        decryption.put(
                "algorithm",
                "RSA-OAEP-SHA256"
        );

        decryption.put(
                "performedBy",
                "Java Spring Boot Server"
        );

        decryption.put(
                "keyUsed",
                "Private Key"
        );

        decryption.put(
                "privateKeyLocation",
                "Server Only"
        );

        decryption.put(
                "purpose",
                "Decrypt encrypted client request inside server"
        );

        response.put(
                "decryption",
                decryption
        );


        // ====================================================
        // CONNECTION FLOW
        // ====================================================

        Map<String, Object> connection =
                new java.util.LinkedHashMap<>();

        connection.put(
                "client",
                "Flutter / Postman"
        );

        connection.put(
                "server",
                "Render Spring Boot Backend"
        );

        connection.put(
                "connectionStatus",
                "CONNECTED"
        );

        connection.put(
                "transportSecurity",
                "HTTPS"
        );

        connection.put(
                "requestFormat",
                "JSON"
        );

        connection.put(
                "encryptedPayloadField",
                "data"
        );

        response.put(
                "clientServerConnection",
                connection
        );


        // ====================================================
        // LOGIN
        // ====================================================

        Map<String, Object> login =
                new java.util.LinkedHashMap<>();

        login.put(
                "endpoint",
                "/api/login"
        );

        login.put(
                "status",
                "CONFIGURED"
        );

        login.put(
                "requestSecurity",
                "RSA encrypted payload"
        );

        login.put(
                "serverAction",
                "Decrypt request and validate login credentials"
        );

        response.put(
                "login",
                login
        );


        // ====================================================
        // OTP
        // ====================================================

        Map<String, Object> otp =
                new java.util.LinkedHashMap<>();

        otp.put(
                "generation",
                "CONFIGURED"
        );

        otp.put(
                "type",
                "Random 6 digit OTP"
        );

        otp.put(
                "expirySeconds",
                120
        );

        otp.put(
                "maximumAttempts",
                3
        );

        otp.put(
                "verificationEndpoint",
                "/api/verify-otp"
        );

        otp.put(
                "resendEndpoint",
                "/api/resend-otp"
        );

        otp.put(
                "activeOtpRecords",
                otpStore.size()
        );

        response.put(
                "otp",
                otp
        );


        // ====================================================
        // AUTHORIZATION
        // ====================================================

        Map<String, Object> authorization =
                new java.util.LinkedHashMap<>();

        authorization.put(
                "status",
                "CONFIGURED"
        );

        authorization.put(
                "type",
                "Bearer Token"
        );

        authorization.put(
                "generatedAfter",
                "Successful OTP verification"
        );

        authorization.put(
                "activeTokens",
                tokenStore.size()
        );

        response.put(
                "authorization",
                authorization
        );


        // ====================================================
        // PROTECTED API
        // ====================================================

        Map<String, Object> protectedApi =
                new java.util.LinkedHashMap<>();

        protectedApi.put(
                "endpoint",
                "/api/secure-data"
        );

        protectedApi.put(
                "status",
                "CONFIGURED"
        );

        protectedApi.put(
                "authorizationRequired",
                true
        );

        protectedApi.put(
                "authorizationType",
                "Bearer Token"
        );

        protectedApi.put(
                "payloadEncryption",
                "RSA-OAEP-SHA256"
        );

        response.put(
                "protectedApi",
                protectedApi
        );


        // ====================================================
        // LOGOUT
        // ====================================================

        Map<String, Object> logout =
                new java.util.LinkedHashMap<>();

        logout.put(
                "endpoint",
                "/api/logout"
        );

        logout.put(
                "status",
                "CONFIGURED"
        );

        logout.put(
                "action",
                "Remove authorization token from server"
        );

        response.put(
                "logout",
                logout
        );


        // ====================================================
        // TRUSTED LOGIN / SSO STATUS
        // ====================================================

        Map<String, Object> trustedLoginStatus =
                new java.util.LinkedHashMap<>();

        trustedLoginStatus.put("endpoint", "/api/trusted-login");
        trustedLoginStatus.put("status", "DEMO CONFIGURED");
        trustedLoginStatus.put("encryption", "RSA-OAEP-SHA256");
        trustedLoginStatus.put("digitalSignature", "SHA256withRSA");
        trustedLoginStatus.put(
                "signaturePadding",
                "PKCS#1 v1.5 DEMO - CONFIRM WITH PNB_360"
        );
        trustedLoginStatus.put(
                "timestampValidation",
                "CONFIGURED - 120 seconds"
        );
        trustedLoginStatus.put(
                "nonceValidation",
                "CONFIGURED - in-memory demo cache"
        );
        trustedLoginStatus.put(
                "replayProtection",
                "CONFIGURED - in-memory demo cache"
        );
        trustedLoginStatus.put(
                "clientIdValidation",
                "CONFIGURED - demo client PNB_APP"
        );
        trustedLoginStatus.put(
                "appPublicKeyAvailable",
                appKeyPair != null &&
                        appKeyPair.getPublic() != null
        );
        trustedLoginStatus.put(
                "productionKeyManagement",
                "PENDING - secure external key storage and PNB key exchange required"
        );

        response.put("trustedLogin", trustedLoginStatus);


        // ====================================================
        // COMPLETE FLOW
        // ====================================================

        response.put(
                "completeFlow",
                "Client -> Render Server -> Get Public Key -> Encrypt Request -> Send Encrypted Data -> Server Private Key Decryption -> Login -> OTP Generation -> OTP Verification -> Bearer Token -> Protected API -> Logout"
        );

        response.put(
                "overallStatus",
                publicKeyAvailable && privateKeyAvailable
                        ? "SECURE BACKEND READY"
                        : "KEY CONFIGURATION ERROR"
        );

        response.put(
                "message",
                "Client is connected to the backend server and RSA encryption/decryption, OTP authentication and Bearer token authorization are configured."
        );


        return ResponseEntity.ok(response);

    } catch (Exception e) {

        e.printStackTrace();

        return ResponseEntity
                .status(
                        HttpStatus.INTERNAL_SERVER_ERROR
                )
                .body(
                        Map.of(
                                "success",
                                false,
                                "serverConnectivity",
                                "ERROR",
                                "message",
                                "Complete flow status check failed"
                        )
                );
    }
}



    // ========================================================
    // TRUSTED LOGIN CRYPTO HELPERS
    // ========================================================

    private String encrypt(
            String plainText,
            java.security.PublicKey publicKey
    ) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");

        OAEPParameterSpec oaep = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT
        );

        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaep);

        byte[] encrypted = cipher.doFinal(
                plainText.getBytes(StandardCharsets.UTF_8)
        );

        return Base64.getEncoder().encodeToString(encrypted);
    }


    private String sign(
            String signingInput,
            java.security.PrivateKey privateKey
    ) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(signingInput.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder()
                .encodeToString(signer.sign());
    }


    private boolean verifySignature(
            String signingInput,
            String signatureBase64,
            java.security.PublicKey publicKey
    ) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(signingInput.getBytes(StandardCharsets.UTF_8));

        return verifier.verify(
                Base64.getDecoder().decode(signatureBase64)
        );
    }


    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }


    // ========================================================
    // RSA PRIVATE KEY DECRYPTION
    // ========================================================

    private String decrypt(
            String encryptedData
    ) throws Exception {

        byte[] encryptedBytes =
                Base64.getDecoder()
                        .decode(
                                encryptedData
                        );


        Cipher cipher =
                Cipher.getInstance(
                        "RSA/ECB/OAEPPadding"
                );


        OAEPParameterSpec oaepParameterSpec =
                new OAEPParameterSpec(

                        "SHA-256",

                        "MGF1",

                        MGF1ParameterSpec.SHA256,

                        PSource.PSpecified.DEFAULT
                );


        cipher.init(

                Cipher.DECRYPT_MODE,

                keyPair.getPrivate(),

                oaepParameterSpec
        );


        byte[] decryptedBytes =
                cipher.doFinal(
                        encryptedBytes
                );


        return new String(
                decryptedBytes,
                StandardCharsets.UTF_8
        );
    }


    // ========================================================
    // JSON HELPER
    // ========================================================

    private String getText(
            JsonNode node,
            String field
    ) {

        JsonNode value =
                node.get(
                        field
                );


        if (value == null ||
                value.isNull()) {

            return "";
        }


        return value
                .asText()
                .trim();
    }



    // ========================================================
    // TRUSTED LOGIN REQUEST MODELS
    // ========================================================

    public static class TrustedLoginRequest {
        public String encryptedPayload;
        public String signature;
        public String timestamp;
        public String nonce;

        public TrustedLoginRequest() {
        }
    }


    public static class TrustedLoginPayload {
        public String clientId;
        public String userId;
        public String timestamp;
        public String nonce;

        public TrustedLoginPayload() {
        }
    }


    // ========================================================
    // ENCRYPTED REQUEST MODEL
    // ========================================================

    public static class EncryptedRequest {

        public String data;


        public EncryptedRequest() {
        }


        public String getData() {

            return data;
        }


        public void setData(
                String data
        ) {

            this.data = data;
        }
    }


    // ========================================================
    // OTP DATA MODEL
    // ========================================================

    private static class OtpData {

        private final String otp;

        private final long expiryTime;

        private int attempts;


        public OtpData(
                String otp,
                long expiryTime,
                int attempts
        ) {

            this.otp =
                    otp;

            this.expiryTime =
                    expiryTime;

            this.attempts =
                    attempts;
        }
    }
}
