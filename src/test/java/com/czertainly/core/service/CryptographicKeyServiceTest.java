package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.cryptography.key.KeyRequestDto;
import com.czertainly.api.model.client.cryptography.key.KeyRequestType;
import com.czertainly.api.model.connector.cryptography.enums.CryptographicAlgorithm;
import com.czertainly.api.model.connector.cryptography.enums.KeyFormat;
import com.czertainly.api.model.connector.cryptography.enums.KeyType;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.cryptography.key.KeyDetailDto;
import com.czertainly.api.model.core.cryptography.key.KeyDto;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.CryptographicKey;
import com.czertainly.core.dao.entity.CryptographicKeyContent;
import com.czertainly.core.dao.entity.TokenInstanceReference;
import com.czertainly.core.dao.entity.TokenProfile;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.CryptographicKeyContentRepository;
import com.czertainly.core.dao.repository.CryptographicKeyRepository;
import com.czertainly.core.dao.repository.TokenInstanceReferenceRepository;
import com.czertainly.core.dao.repository.TokenProfileRepository;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Optional;

public class CryptographicKeyServiceTest extends BaseSpringBootTest {

    private static final String KEY_NAME = "testKey1";

    @Autowired
    private CryptographicKeyService cryptographicKeyService;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;
    @Autowired
    private CryptographicKeyContentRepository cryptographicKeyContentRepository;

    private TokenInstanceReference tokenInstanceReference;
    private CryptographicKeyContent content;
    private TokenProfile tokenProfile;
    private Connector connector;
    private CryptographicKey key;
    private WireMockServer mockServer;

    @BeforeEach
    public void setUp() {
        mockServer = new WireMockServer(3665);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        connector = new Connector();
        connector.setUrl("http://localhost:3665");
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        tokenInstanceReference = new TokenInstanceReference();
        tokenInstanceReference.setTokenInstanceUuid("1l");
        tokenInstanceReference.setConnector(connector);
        tokenInstanceReferenceRepository.save(tokenInstanceReference);

        tokenProfile = new TokenProfile();
        tokenProfile.setName("profile1");
        tokenProfile.setTokenInstanceReference(tokenInstanceReference);
        tokenProfile.setDescription("sample description");
        tokenProfile.setEnabled(true);
        tokenProfile.setTokenInstanceName("testInstance");
        tokenProfileRepository.save(tokenProfile);

        key = new CryptographicKey();
        key.setName(KEY_NAME);
        key.setTokenProfile(tokenProfile);
        key.setDescription("initial description");
        cryptographicKeyRepository.save(key);

        content = new CryptographicKeyContent();
        content.setLength(1024);
        content.setCryptographicKey(key);
        content.setType(KeyType.PRIVATE_KEY);
        content.setKeyData("some/encrypted/data");
        content.setFormat(KeyFormat.PRKI);
        content.setCryptographicAlgorithm(CryptographicAlgorithm.RSA);
        cryptographicKeyContentRepository.save(content);

        content = new CryptographicKeyContent();
        content.setLength(1024);
        content.setCryptographicKey(key);
        content.setType(KeyType.PUBLIC_KEY);
        content.setKeyData("some/encrypted/data");
        content.setFormat(KeyFormat.SPKI);
        content.setCryptographicAlgorithm(CryptographicAlgorithm.RSA);
        cryptographicKeyContentRepository.save(content);
    }

    @AfterEach
    public void tearDown() {
        mockServer.stop();
    }

    @Test
    public void testListKeys() {
        List<KeyDto> keys = cryptographicKeyService.listKeys(
                Optional.ofNullable(null),
                SecurityFilter.create()
        );
        Assertions.assertNotNull(keys);
        Assertions.assertFalse(keys.isEmpty());
        Assertions.assertEquals(1, keys.size());
        Assertions.assertEquals(key.getUuid().toString(), keys.get(0).getUuid());
    }

    @Test
    public void testGetKeyByUuid() throws NotFoundException {
        KeyDetailDto dto = cryptographicKeyService.getKey(
                tokenInstanceReference.getSecuredParentUuid(),
                key.getUuid().toString()
        );
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(key.getUuid().toString(), dto.getUuid());
    }

    @Test
    public void testGetKeyByUuid_notFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> cryptographicKeyService.getKey(
                        tokenInstanceReference.getSecuredParentUuid(),
                        "abfbc322-29e1-11ed-a261-0242ac120002")
        );
    }

    @Test
    public void testAddKey() throws ConnectorException, AlreadyExistException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/pair/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+"))
                .willReturn(WireMock.okJson("{}")));
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/status"))
                .willReturn(WireMock.okJson("{}")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/pair/attributes/validate"))
                .willReturn(WireMock.ok()));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/pair"))
                .willReturn(WireMock.okJson("{}")));

        KeyRequestDto request = new KeyRequestDto();
        request.setName("testRaProfile2");
        request.setDescription("sampleDescription");
        request.setAttributes(List.of());

        KeyDetailDto dto = cryptographicKeyService.createKey(
                tokenInstanceReference.getSecuredParentUuid(),
                KeyRequestType.KEY_PAIR,
                request
        );
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
    }

    @Test
    public void testAddKey_validationFail() {
        KeyRequestDto request = new KeyRequestDto();
        Assertions.assertThrows(
                ValidationException.class,
                () -> cryptographicKeyService.createKey(
                        tokenInstanceReference.getSecuredParentUuid(),
                        KeyRequestType.KEY_PAIR,
                        request
                )
        );
    }

    @Test
    public void testAddKey_alreadyExist() {
        KeyRequestDto request = new KeyRequestDto();
        request.setName(KEY_NAME); // raProfile with same username exist

        Assertions.assertThrows(
                AlreadyExistException.class,
                () -> cryptographicKeyService.createKey(
                        tokenInstanceReference.getSecuredParentUuid(),
                        KeyRequestType.KEY_PAIR,
                        request
                )
        );
    }

    @Test
    public void testDestroyKey() throws ConnectorException {
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys"))
                .willReturn(WireMock.ok()));

        cryptographicKeyService.destroyKey(
                tokenInstanceReference.getSecuredParentUuid(),
                key.getUuid().toString(),
                List.of()
        );
        Assertions.assertThrows(
                NotFoundException.class,
                () -> cryptographicKeyService.getKey(
                        tokenInstanceReference.getSecuredParentUuid(),
                        key.getUuid().toString()
                )
        );
    }

    @Test
    public void testDestroyKey_notFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> cryptographicKeyService.getKey(
                        tokenInstanceReference.getSecuredParentUuid(),
                        "abfbc322-29e1-11ed-a261-0242ac120002"
                )
        );
    }
}
