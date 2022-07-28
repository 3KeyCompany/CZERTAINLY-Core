package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.authority.AuthorityInstanceRequestDto;
import com.czertainly.api.model.core.authority.AuthorityInstanceDto;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.core.dao.entity.AuthorityInstanceReference;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.Connector2FunctionGroup;
import com.czertainly.core.dao.entity.FunctionGroup;
import com.czertainly.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.czertainly.core.dao.repository.Connector2FunctionGroupRepository;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.FunctionGroupRepository;
import com.czertainly.core.util.MetaDefinitions;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@SpringBootTest
@Transactional
@Rollback
@WithMockUser(roles="SUPERADMINISTRATOR")
public class AuthorityInstanceServiceTest {

    private static final String AUTHORITY_INSTANCE_NAME = "testAuthorityInstance1";

    @Autowired
    private AuthorityInstanceService authorityInstanceService;

    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    private AuthorityInstanceReference authorityInstance;
    private Connector connector;

    private WireMockServer mockServer;

    @BeforeEach
    public void setUp() {
        mockServer = new WireMockServer(3665);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        connector = new Connector();
        connector.setUuid("123");
        connector.setName("authorityInstanceConnector");
        connector.setUrl("http://localhost:3665");
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.AUTHORITY_PROVIDER);
        functionGroup.setName(FunctionGroupCode.AUTHORITY_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of("ApiKey")));
        connector2FunctionGroupRepository.save(c2fg);

        connector.getFunctionGroups().add(c2fg);
        connectorRepository.save(connector);

        authorityInstance = new AuthorityInstanceReference();
        authorityInstance.setName(AUTHORITY_INSTANCE_NAME);
        authorityInstance.setConnector(connector);
        authorityInstance.setKind("sample");
        authorityInstance.setAuthorityInstanceUuid("1l");
        authorityInstance = authorityInstanceReferenceRepository.save(authorityInstance);
    }

    @AfterEach
    public void tearDown() {
        mockServer.stop();
    }

    @Test
    public void testListAuthorityInstances() {
        List<AuthorityInstanceDto> authorityInstances = authorityInstanceService.listAuthorityInstances();
        Assertions.assertNotNull(authorityInstances);
        Assertions.assertFalse(authorityInstances.isEmpty());
        Assertions.assertEquals(1, authorityInstances.size());
        Assertions.assertEquals(authorityInstance.getUuid(), authorityInstances.get(0).getUuid());
    }

    @Test
    public void testGetAuthorityInstance() throws ConnectorException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+"))
                .willReturn(WireMock.okJson("{}")));

        AuthorityInstanceDto dto = authorityInstanceService.getAuthorityInstance(authorityInstance.getUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(authorityInstance.getUuid(), dto.getUuid());
        Assertions.assertNotNull(dto.getConnectorUuid());
        Assertions.assertEquals(authorityInstance.getConnector().getUuid(), dto.getConnectorUuid());
    }

    @Test
    public void testGetAuthorityInstance_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> authorityInstanceService.getAuthorityInstance("wrong-uuid"));
    }

    @Test
    public void testAddAuthorityInstance() throws ConnectorException, AlreadyExistException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/authorityProvider/[^/]+/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/[^/]+/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/authorities"))
                .willReturn(WireMock.okJson("{ \"id\": 2 }")));

        AuthorityInstanceRequestDto request = new AuthorityInstanceRequestDto();
        request.setName("testAuthorityInstance2");
        request.setConnectorUuid(connector.getUuid());
        request.setAttributes(List.of());
        request.setKind("Ejbca");

        AuthorityInstanceDto dto = authorityInstanceService.createAuthorityInstance(request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
        Assertions.assertNotNull(dto.getConnectorUuid());
        Assertions.assertEquals(authorityInstance.getConnector().getUuid(), dto.getConnectorUuid());
    }

    @Test
    public void testAddAuthorityInstance_notFound() {
        AuthorityInstanceRequestDto request = new AuthorityInstanceRequestDto();
        // connector uui not set
        Assertions.assertThrows(NotFoundException.class, () -> authorityInstanceService.createAuthorityInstance(request));
    }

    @Test
    public void testAddAuthorityInstance_alreadyExist() {
        AuthorityInstanceRequestDto request = new AuthorityInstanceRequestDto();
        request.setName(AUTHORITY_INSTANCE_NAME); // authorityInstance with same name exist

        Assertions.assertThrows(AlreadyExistException.class, () -> authorityInstanceService.createAuthorityInstance(request));
    }

    @Test
    public void testEditAuthorityInstance_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> authorityInstanceService.editAuthorityInstance("wrong-uuid", null));
    }

    @Test
    public void testRemoveAuthorityInstance() throws ConnectorException {
        mockServer.stubFor(WireMock
                .delete(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+"))
                .willReturn(WireMock.ok()));

        authorityInstanceService.deleteAuthorityInstance(authorityInstance.getUuid());
        Assertions.assertThrows(NotFoundException.class, () -> authorityInstanceService.getAuthorityInstance(authorityInstance.getUuid()));
    }

    @Test
    public void testGetRaProfileAttributes() throws ConnectorException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/raProfile/attributes"))
                .willReturn(WireMock.ok()));

        authorityInstanceService.listRAProfileAttributes(authorityInstance.getUuid());
    }

    @Test
    public void testGetRaProfileAttributes_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> authorityInstanceService.listRAProfileAttributes("wrong-uuid"));
    }

    @Test
    public void testValidateRaProfileAttributes() throws ConnectorException {
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/raProfile/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        authorityInstanceService.validateRAProfileAttributes(authorityInstance.getUuid(), List.of());
    }

    @Test
    public void testValidateRaProfileAttributes_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> authorityInstanceService.validateRAProfileAttributes("wrong-uuid", null));
    }

    @Test
    public void testRemoveAuthorityInstance_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> authorityInstanceService.deleteAuthorityInstance("wrong-uuid"));
    }

    @Test
    public void testBulkRemove() throws NotFoundException, ConnectorException {
        authorityInstanceService.bulkDeleteAuthorityInstance(List.of(authorityInstance.getUuid()));
        Assertions.assertThrows(NotFoundException.class, () -> authorityInstanceService.getAuthorityInstance(authorityInstance.getUuid()));
    }
}
