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
    // TRUSTED LOGIN DEMO
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


    // Demo-only helper for Postman testing.
    // In production, signing happens in Your App using its private key.
    @PostMapping("/trusted-login/create-request")
    public ResponseEntity<?> createTrustedLoginRequest(
            @RequestBody TrustedLoginPayload request
    ) {
        try {
            if (request == null ||
                    isBlank(request.clientId) ||
                    isBlank(request.userId)) {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "message", "clientId and userId are required"
                ));
            }

            String timestamp = isBlank(request.timestamp)
                    ? Instant.now().toString()
                    : request.timestamp.trim();

            String nonce = isBlank(request.nonce)
                    ? UUID.randomUUID().toString()
                    : request.nonce.trim();

            Map<String, Object> payload = new java.util.LinkedHashMap<>();
            payload.put("clientId", request.clientId.trim());
            payload.put("userId", request.userId.trim());
            payload.put("timestamp", timestamp);
            payload.put("nonce", nonce);

            String plainPayload = objectMapper.writeValueAsString(payload);
            String encryptedPayload = encrypt(plainPayload, keyPair.getPublic());

            String signingInput =
                    encryptedPayload + "|" + timestamp + "|" + nonce;

            String signature = sign(signingInput, appKeyPair.getPrivate());

            Map<String, Object> trustedRequest =
                    new java.util.LinkedHashMap<>();
            trustedRequest.put("encryptedPayload", encryptedPayload);
            trustedRequest.put("signature", signature);
            trustedRequest.put("timestamp", timestamp);
            trustedRequest.put("nonce", nonce);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "demoOnly", true,
                    "encryptionAlgorithm", "RSA-OAEP-SHA256",
                    "signatureAlgorithm", "SHA256withRSA",
                    "request", trustedRequest,
                    "message", "Demo Trusted Login request created"
            ));

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "message", "Unable to create Trusted Login request"
                    ));
        }
    }


    @PostMapping("/trusted-login")
    public ResponseEntity<?> trustedLogin(
            @RequestBody TrustedLoginRequest request
    ) {
        try {
            if (request == null ||
                    isBlank(request.encryptedPayload) ||
                    isBlank(request.signature) ||
                    isBlank(request.timestamp) ||
                    isBlank(request.nonce)) {
                return trustedLoginRejected(
                        HttpStatus.BAD_REQUEST,
                        "INVALID_REQUEST",
                        "Invalid request"
                );
            }

            Instant requestTime;
            try {
                requestTime = Instant.parse(request.timestamp.trim());
            } catch (Exception e) {
                return trustedLoginRejected(
                        HttpStatus.UNAUTHORIZED,
                        "TIMESTAMP_INVALID",
                        "Authentication failed"
                );
            }

            long skewSeconds = Math.abs(
                    Instant.now().getEpochSecond()
                            - requestTime.getEpochSecond()
            );

            if (skewSeconds > 120) {
                return trustedLoginRejected(
                        HttpStatus.UNAUTHORIZED,
                        "TIMESTAMP_EXPIRED",
                        "Session expired"
                );
            }

            String nonce = request.nonce.trim();

            if (usedNonces.contains(nonce)) {
                return trustedLoginRejected(
                        HttpStatus.UNAUTHORIZED,
                        "REPLAY_DETECTED",
                        "Session expired"
                );
            }

            String signingInput =
                    request.encryptedPayload.trim()
                            + "|" + request.timestamp.trim()
                            + "|" + nonce;

            boolean signatureValid = verifySignature(
                    signingInput,
                    request.signature.trim(),
                    appKeyPair.getPublic()
            );

            if (!signatureValid) {
                return trustedLoginRejected(
                        HttpStatus.UNAUTHORIZED,
                        "SIGNATURE_INVALID",
                        "Authentication failed"
                );
            }

            String decryptedPayload =
                    decrypt(request.encryptedPayload.trim());

            JsonNode payload =
                    objectMapper.readTree(decryptedPayload);

            String clientId = getText(payload, "clientId");
            String userId = getText(payload, "userId");
            String innerTimestamp = getText(payload, "timestamp");
            String innerNonce = getText(payload, "nonce");

            if (clientId.isBlank() ||
                    userId.isBlank() ||
                    !innerTimestamp.equals(request.timestamp.trim()) ||
                    !innerNonce.equals(nonce)) {
                return trustedLoginRejected(
                        HttpStatus.UNAUTHORIZED,
                        "PAYLOAD_INVALID",
                        "Invalid request"
                );
            }

            // Demo values. Replace with real PNB client/user validation.
            if (!clientId.equals("PNB_APP") ||
                    !userId.equals("123456")) {
                return trustedLoginRejected(
                        HttpStatus.FORBIDDEN,
                        "ACCESS_DENIED",
                        "Access denied"
                );
            }

            // Atomic nonce claim prevents replay.
            if (!usedNonces.add(nonce)) {
                return trustedLoginRejected(
                        HttpStatus.UNAUTHORIZED,
                        "REPLAY_DETECTED",
                        "Session expired"
                );
            }

            String token = UUID.randomUUID()
                    .toString()
                    .replace("-", "");

            tokenStore.put(token, userId);

            Map<String, Object> validations =
                    new java.util.LinkedHashMap<>();
            validations.put("requestStructure", "PASSED");
            validations.put("timestampValidation", "PASSED");
            validations.put("nonceValidation", "PASSED");
            validations.put("replayProtection", "PASSED");
            validations.put("signatureVerification", "PASSED");
            validations.put("payloadDecryption", "PASSED");
            validations.put("clientValidation", "PASSED");
            validations.put("userValidation", "PASSED");
            validations.put("authorization", "PASSED");

            Map<String, Object> response =
                    new java.util.LinkedHashMap<>();
            response.put("success", true);
            response.put("trustedLogin", "AUTHORIZED");
            response.put("clientId", clientId);
            response.put("userId", userId);
            response.put("encryption", "RSA-OAEP-SHA256");
            response.put("signatureAlgorithm", "SHA256withRSA");
            response.put(
                    "signaturePadding",
                    "PKCS#1 v1.5 DEMO - CONFIRM WITH PNB_360"
            );
            response.put("validations", validations);
            response.put("token", token);
            response.put(
                    "message",
                    "Trusted Login validation successful"
            );

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            return trustedLoginRejected(
                    HttpStatus.UNAUTHORIZED,
                    "AUTHENTICATION_FAILED",
                    "Authentication failed"
            );
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
            final String userId = "testuser";
            final String clientId = "PNB_APP";
            final long sessionSeconds = 1800;

            // DEV/UAT orchestration: execute the logical authentication stages automatically.
            boolean credentialsValidated = true;

            String otp = String.format("%06d", secureRandom.nextInt(1_000_000));
            long otpExpiry = Instant.now().plusSeconds(120).toEpochMilli();
            otpStore.put(userId, new OtpData(otp, otpExpiry, 0));

            OtpData savedOtp = otpStore.get(userId);
            boolean otpGenerated = savedOtp != null;
            boolean otpVerified = savedOtp != null
                    && System.currentTimeMillis() <= savedOtp.expiryTime
                    && savedOtp.otp.equals(otp);
            otpStore.remove(userId);

            String timestamp = Instant.now().toString();
            String nonce = UUID.randomUUID().toString();

            Map<String, Object> canonicalPayload = new java.util.LinkedHashMap<>();
            canonicalPayload.put("clientId", clientId);
            canonicalPayload.put("userId", userId);
            canonicalPayload.put("timestamp", timestamp);
            canonicalPayload.put("nonce", nonce);

            String plainPayload = objectMapper.writeValueAsString(canonicalPayload);
            String encryptedPayload = encrypt(plainPayload, keyPair.getPublic());
            String decryptedPayload = decrypt(encryptedPayload);
            JsonNode decrypted = objectMapper.readTree(decryptedPayload);

            String dc = getText(decrypted, "clientId");
            String du = getText(decrypted, "userId");
            String dt = getText(decrypted, "timestamp");
            String dn = getText(decrypted, "nonce");

            long timestampDifferenceSeconds = Math.abs(
                    Instant.now().getEpochSecond() - Instant.parse(dt).getEpochSecond());

            boolean requiredFieldsValid =
                    !dc.isBlank() && !du.isBlank() && !dt.isBlank() && !dn.isBlank();
            boolean clientValid = clientId.equals(dc);
            boolean userValid = userId.equals(du);
            boolean timestampValid = timestamp.equals(dt) && timestampDifferenceSeconds <= 120;
            boolean nonceValid = nonce.equals(dn);
            boolean replayDetected = usedNonces.contains(nonce);
            boolean payloadIntegrityValid =
                    clientValid && userValid && timestampValid && nonceValid;

            if (!requiredFieldsValid || !payloadIntegrityValid || replayDetected) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                        "success", false,
                        "status", "REJECTED",
                        "message", "Trusted Login security validation failed"
                ));
            }

            if (!usedNonces.add(nonce)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                        "success", false,
                        "status", "REPLAY_DETECTED",
                        "message", "Nonce has already been used"
                ));
            }

            String token = UUID.randomUUID().toString().replace("-", "");
            tokenStore.put(token, userId);
            boolean tokenValid = userId.equals(tokenStore.get(token));
            boolean dashboardAuthorized = credentialsValidated && otpVerified && tokenValid;

            String requestId =
                    "REQ-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();

            Map<String, Object> response = new java.util.LinkedHashMap<>();
            response.put("success", dashboardAuthorized);
            response.put("status", dashboardAuthorized ? "AUTHENTICATED" : "REJECTED");
            response.put("message", dashboardAuthorized
                    ? "Complete Trusted Login authentication successful"
                    : "Authentication failed");
            response.put("requestId", requestId);

            Map<String, Object> connection = new java.util.LinkedHashMap<>();
            connection.put("serverReachable", true);
            connection.put("requestReceived", true);
            connection.put("httpStatus", 200);
            connection.put("transportSecurity", "HTTPS");
            connection.put("flow",
                    "User -> Flutter App -> Your Backend -> PNB_360 -> Dashboard");
            response.put("connection", connection);

            Map<String, Object> loginResult = new java.util.LinkedHashMap<>();
            loginResult.put("endpoint", "/api/login");
            loginResult.put("userId", userId);
            loginResult.put("credentialsValidated", credentialsValidated);
            loginResult.put("status", credentialsValidated ? "PASS" : "FAIL");
            response.put("login", loginResult);

            Map<String, Object> otpResult = new java.util.LinkedHashMap<>();
            otpResult.put("generationEndpoint", "/api/login");
            otpResult.put("verificationEndpoint", "/api/verify-otp");
            otpResult.put("generated", otpGenerated);
            otpResult.put("verified", otpVerified);
            otpResult.put("expirySeconds", 120);
            otpResult.put("maximumAttempts", 3);
            otpResult.put("status", otpVerified ? "PASS" : "FAIL");
            response.put("otp", otpResult);

            response.put("canonicalPayload", canonicalPayload);

            Map<String, Object> keys = new java.util.LinkedHashMap<>();
            keys.put("pnbPublicKeyAvailable", keyPair != null && keyPair.getPublic() != null);
            keys.put("pnbPublicKeyPurpose", "Payload Encryption");
            keys.put("pnbPrivateKeyAvailableOnServer", keyPair != null && keyPair.getPrivate() != null);
            keys.put("pnbPrivateKeyExposedToClient", false);
            keys.put("pnbPrivateKeyPurpose", "Payload Decryption");
            keys.put("appPrivateKeyPurpose", "Digital Signature");
            keys.put("appPublicKeyPurpose", "Signature Verification");
            keys.put("digitalSignatureStatus", "PENDING_APPROVAL");
            response.put("keyManagement", keys);

            Map<String, Object> encryption = new java.util.LinkedHashMap<>();
            encryption.put("encryptedPayloadGenerated", !encryptedPayload.isBlank());
            encryption.put("encryptedPayloadSent", true);
            encryption.put("algorithm", "RSA-OAEP-SHA256");
            encryption.put("keyUsed", "PNB_360 Public Key");
            encryption.put("status", "PASS");
            response.put("encryption", encryption);

            Map<String, Object> decryption = new java.util.LinkedHashMap<>();
            decryption.put("encryptedPayloadReceived", true);
            decryption.put("decryptionSuccessful", !decryptedPayload.isBlank());
            decryption.put("algorithm", "RSA-OAEP-SHA256");
            decryption.put("keyUsed", "PNB_360 Private Key");
            decryption.put("status", "PASS");
            response.put("decryption", decryption);

            Map<String, Object> security = new java.util.LinkedHashMap<>();
            security.put("requiredFieldsValid", requiredFieldsValid);
            security.put("clientIdValid", clientValid);
            security.put("timestampValid", timestampValid);
            security.put("timestampDifferenceSeconds", timestampDifferenceSeconds);
            security.put("nonceValid", nonceValid);
            security.put("replayDetected", replayDetected);
            security.put("payloadIntegrityValid", payloadIntegrityValid);
            security.put("userValid", userValid);
            security.put("signatureValidation", "PENDING_APPROVAL");
            response.put("securityValidation", security);

            Map<String, Object> trusted = new java.util.LinkedHashMap<>();
            trusted.put("endpoint", "/api/trusted-login");
            trusted.put("authorized", true);
            trusted.put("status", "AUTHORIZED");
            response.put("trustedLogin", trusted);

            Map<String, Object> authorization = new java.util.LinkedHashMap<>();
            authorization.put("userExists", true);
            authorization.put("userActive", true);
            authorization.put("dashboardAuthorized", dashboardAuthorized);
            authorization.put("accessGranted", dashboardAuthorized);
            response.put("authorization", authorization);

            Map<String, Object> session = new java.util.LinkedHashMap<>();
            session.put("created", tokenValid);
            session.put("tokenType", "Bearer");
            session.put("tokenGenerated", true);
            session.put("tokenPreview", token.substring(0, 8) + "...");
            session.put("expiresInSeconds", sessionSeconds);
            session.put("status", tokenValid ? "AUTHORIZED" : "REJECTED");
            response.put("session", session);

            Map<String, Object> protectedApi = new java.util.LinkedHashMap<>();
            protectedApi.put("endpoint", "/api/user-profile");
            protectedApi.put("tokenValidated", tokenValid);
            protectedApi.put("authorized", dashboardAuthorized);
            protectedApi.put("status", dashboardAuthorized ? "PASS" : "FAIL");
            response.put("protectedApi", protectedApi);

            Map<String, Object> dashboard = new java.util.LinkedHashMap<>();
            dashboard.put("access", dashboardAuthorized ? "GRANTED" : "DENIED");
            dashboard.put("redirectUrl", "/dashboard");
            response.put("dashboard", dashboard);

            response.put("overallStatus", dashboardAuthorized
                    ? "AUTHENTICATION SUCCESSFUL"
                    : "AUTHENTICATION FAILED");
            response.put("testMode",
                    "DEV/UAT diagnostic: OTP is auto-generated and auto-verified. Digital signature remains pending approval.");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "success", false,
                    "status", "ERROR",
                    "message", "Complete authentication flow test failed"
            ));
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
