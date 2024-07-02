package com.czertainly.core.security.authn.client;

import com.czertainly.core.security.authn.CzertainlyAuthenticationException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CzertainlyAuthenticationClientTest {
    private static MockWebServer authServiceMock;

    private static CzertainlyAuthenticationClient czertainlyAuthenticationClient;
    // @formatter:off
    String RAW_DATA = "{" +
            "\"authenticated\": true," +
            "\"data\": {" +
            "\"user\": {" +
            "\"username\": \"FrantisekJednicka\"," +
            "\"enabled\": true" +
            "}," +
            "\"roles\": [" +
            "{\"uuid\":\"32281955-eed2-4520-9f42-15b82c96f928\",\"name\":\"ROLE_ADMINISTRATOR\"}," +
            "{\"uuid\":\"32281955-eed2-4520-9f42-15b82c96f930\",\"name\":\"ROLE_USER\"}" +
            "]" +
            "}" +
            "}";

    @BeforeAll
    static void setup() throws IOException {
        authServiceMock = new MockWebServer();
        authServiceMock.start();

        String authServiceBaseUrl = "http://%s:%d".formatted(authServiceMock.getHostName(), authServiceMock.getPort());
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        czertainlyAuthenticationClient = new CzertainlyAuthenticationClient(objectMapper, authServiceBaseUrl);
    }

    @AfterAll
    static void tearDown() throws IOException {
        authServiceMock.close();
        authServiceMock.shutdown();
    }

    @AfterEach
    void cleanup() {
        try {
            // Clear the last request by reading it
            authServiceMock.takeRequest(50, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            // No request found, no cleanup needed
        }
    }

    @Test
    void extractAuthenticationInfoFromResponse() {
        // given
        setUpSuccessfulAuthenticationResponse();

        // when
        AuthenticationInfo info = czertainlyAuthenticationClient.authenticate(new HttpHeaders());

        // then
        assertEquals("FrantisekJednicka", info.getUsername());
        // @formatter:off
        assertEquals("{" +
                        "\"user\":{" +
                        "\"username\":\"FrantisekJednicka\"," +
                        "\"enabled\":true" +
                        "}," +
                        "\"roles\":[" +
                        "{\"uuid\":\"32281955-eed2-4520-9f42-15b82c96f928\",\"name\":\"ROLE_ADMINISTRATOR\"}," +
                        "{\"uuid\":\"32281955-eed2-4520-9f42-15b82c96f930\",\"name\":\"ROLE_USER\"}" +
                        "]" +
                        "}",
                info.getRawData()

        );
        // @formatter:on
        assertEquals(
                List.of("ROLE_ADMINISTRATOR", "ROLE_USER"),
                info.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList())
        );

    }

    @Test
    void throwsAuthenticationExceptionWhenEmptyBodyIsReturned() {
        // given
        setUpEmptyResponse();

        // when
        Executable willThrow = () -> czertainlyAuthenticationClient.authenticate(new HttpHeaders());

        // then
        assertThrows(CzertainlyAuthenticationException.class, willThrow);
    }

    RecordedRequest getLastRequest() throws InterruptedException {
        return authServiceMock.takeRequest(500, TimeUnit.MILLISECONDS);
    }
    // @formatter:on

    void setUpSuccessfulAuthenticationResponse() {
        authServiceMock.enqueue(
                new MockResponse()
                        .setResponseCode(200)
                        .setHeader("content-type", "application/json")
                        .setBody(RAW_DATA)
        );
    }

    void setUpEmptyResponse() {
        authServiceMock.enqueue(
                new MockResponse()
                        .setResponseCode(200)
                        .setHeader("content-type", "application/json")
        );
    }

    void setUpFaultyResponse() {
        authServiceMock.enqueue(
                new MockResponse()
                        .setResponseCode(500)
        );
    }
}