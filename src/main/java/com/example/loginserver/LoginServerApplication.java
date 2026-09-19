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

import java.security.spec.MGF1ParameterSpec;

import java.time.Instant;

import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class LoginServerApplication {

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final SecureRandom secureRandom = new SecureRandom();

    private KeyPair keyPair;

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