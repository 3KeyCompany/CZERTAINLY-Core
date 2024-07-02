package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.connector.ConnectDto;
import com.czertainly.api.model.client.connector.ConnectorRequestDto;
import com.czertainly.api.model.client.connector.ConnectorUpdateRequestDto;
import com.czertainly.api.model.client.connector.InfoResponse;
import com.czertainly.api.model.core.connector.AuthType;
import com.czertainly.api.model.core.connector.ConnectorDto;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.connector.FunctionGroupDto;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.Connector2FunctionGroup;
import com.czertainly.core.dao.entity.FunctionGroup;
import com.czertainly.core.dao.repository.Connector2FunctionGroupRepository;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.FunctionGroupRepository;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.MetaDefinitions;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;

class ConnectorServiceComplexTest extends BaseSpringBootTest {

    @Autowired
    private ConnectorService connectorService;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    @Autowired
    private ObjectMapper objectMapper;

    private WireMockServer mockServer;

    @BeforeEach
    public void setUp() {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());
    }

    @AfterEach
    public void tearDown() {
        mockServer.stop();
    }

    @Test
    void testListConnectors_Empty() throws NotFoundException {
        List<ConnectorDto> connectors = connectorService.listConnectors(SecurityFilter.create(), Optional.empty(), Optional.empty(), Optional.empty());
        Assertions.assertNotNull(connectors);
        Assertions.assertTrue(connectors.isEmpty());
    }

    @Test
    void testListConnectors_One() throws NotFoundException {
        Connector connector = new Connector();
        connector.setName("Demo");
        connectorRepository.save(connector);

        List<ConnectorDto> connectors = connectorService.listConnectors(SecurityFilter.create(), Optional.empty(), Optional.empty(), Optional.empty());
        Assertions.assertNotNull(connectors);
        Assertions.assertFalse(connectors.isEmpty());
        Assertions.assertEquals(1, connectors.size());
    }

    @Test
    void testGetConnector() throws NotFoundException, ConnectorException {

        mockServer.stubFor(WireMock.get("/v1").willReturn(WireMock.okJson("[]")));

        Connector connector = new Connector();
        connector.setName("testConnector");
        connector.setUrl("http://localhost:"+mockServer.port());
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        ConnectorDto dto = connectorService.getConnector(connector.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertNotNull(dto.getUuid());
    }

    @Test
    void testCreateConnector() throws ConnectorException, AlreadyExistException {
        String kindName = "testKind";

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setUuid(UUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"));
        functionGroup.setCode(FunctionGroupCode.CREDENTIAL_PROVIDER);
        functionGroup.setName(FunctionGroupCode.CREDENTIAL_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

        FunctionGroupDto fgDto = functionGroup.mapToDto();
        fgDto.setKinds(Collections.singletonList(kindName));

        ConnectorDto request = new ConnectorDto();
        request.setName("testConnector");
        request.setFunctionGroups(List.of(fgDto));

        ConnectorDto dto = connectorService.createConnector(request, ConnectorStatus.CONNECTED);
        Assertions.assertNotNull(dto);
        Assertions.assertNotNull(dto.getUuid());
        Assertions.assertNotNull(dto.getFunctionGroups());
        Assertions.assertFalse(dto.getFunctionGroups().isEmpty());
        Assertions.assertEquals(1, dto.getFunctionGroups().size());

        FunctionGroupDto loaded = dto.getFunctionGroups().get(0);
        Assertions.assertEquals(FunctionGroupCode.CREDENTIAL_PROVIDER, loaded.getFunctionGroupCode());

        Assertions.assertNotNull(loaded.getKinds());
        Assertions.assertFalse(loaded.getKinds().isEmpty());
        Assertions.assertEquals(1, loaded.getKinds().size());
        Assertions.assertEquals(kindName, loaded.getKinds().get(0));

        // check database
        List<ConnectorDto> connectors = connectorService.listConnectors(SecurityFilter.create(), Optional.empty(), Optional.empty(), Optional.empty());
        Assertions.assertNotNull(connectors);
        Assertions.assertFalse(connectors.isEmpty());
        Assertions.assertEquals(1, connectors.size());
    }

    @Test
    void testSimpleCreateConnector() throws ConnectorException, AlreadyExistException, AttributeException {
        String kindName = "testKind";

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.CREDENTIAL_PROVIDER);
        functionGroup.setName(FunctionGroupCode.CREDENTIAL_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

        FunctionGroupDto fgDto = functionGroup.mapToDto();
        fgDto.setKinds(Collections.singletonList(kindName));

        mockServer.stubFor(WireMock.get("/v1").willReturn(WireMock.okJson("[]")));

        ConnectorRequestDto request = new ConnectorRequestDto();
        request.setName("testConnector");
        request.setAuthType(AuthType.NONE);
        request.setUrl("http://localhost:"+mockServer.port());

        ConnectorDto dto = connectorService.createConnector(request);
        Assertions.assertNotNull(dto);
        Assertions.assertNotNull(dto.getUuid());

        // check database
        List<ConnectorDto> connectors = connectorService.listConnectors(SecurityFilter.create(), Optional.empty(), Optional.empty(), Optional.empty());
        Assertions.assertNotNull(connectors);
        Assertions.assertFalse(connectors.isEmpty());
        Assertions.assertEquals(1, connectors.size());
    }

    @Test
    void testUpdateConnector() throws ConnectorException, AttributeException {
        String kindName = "testKind";

        FunctionGroup caFunctionGroup = new FunctionGroup();
        caFunctionGroup.setCode(FunctionGroupCode.AUTHORITY_PROVIDER);
        caFunctionGroup.setName(FunctionGroupCode.AUTHORITY_PROVIDER.getCode());
        functionGroupRepository.save(caFunctionGroup);

        FunctionGroup discoveryFunctionGroup = new FunctionGroup();
        discoveryFunctionGroup.setCode(FunctionGroupCode.DISCOVERY_PROVIDER);
        discoveryFunctionGroup.setName(FunctionGroupCode.DISCOVERY_PROVIDER.getCode());
        functionGroupRepository.save(discoveryFunctionGroup);

        Connector connector = new Connector();
        connector.setName("testConnector");
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        addFunctionGroupToConnector(caFunctionGroup, Collections.singletonList(kindName), connector);
        addFunctionGroupToConnector(discoveryFunctionGroup, Collections.singletonList(kindName), connector);

        FunctionGroupDto caFgDto = caFunctionGroup.mapToDto();
        caFgDto.setKinds(Collections.singletonList(kindName));
        mockServer.stubFor(WireMock.get("/v1").willReturn(WireMock.okJson("[]")));
        ConnectorUpdateRequestDto request = new ConnectorUpdateRequestDto();
        request.setAuthType(AuthType.NONE);
        request.setUrl("http://localhost:"+mockServer.port());

        ConnectorDto dto = connectorService.editConnector(connector.getSecuredUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertNotNull(dto.getUuid());

        // check database
        List<ConnectorDto> connectors = connectorService.listConnectors(SecurityFilter.create(), Optional.empty(), Optional.empty(), Optional.empty());
        Assertions.assertNotNull(connectors);
        Assertions.assertFalse(connectors.isEmpty());
        Assertions.assertEquals(1, connectors.size());
    }

    private void addFunctionGroupToConnector(FunctionGroup functionGroup, List<String> kinds, Connector connector) throws NotFoundException {
        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setKinds(MetaDefinitions.serializeArrayString(kinds));
        connector2FunctionGroupRepository.save(c2fg);

        connector.getFunctionGroups().add(c2fg);
        connectorRepository.save(connector);
    }

    @Test
    void testReconnectConnector() throws NotFoundException, JsonProcessingException, ConnectorException {
        String kindName = "testKind";

        FunctionGroup caFunctionGroup = new FunctionGroup();
        caFunctionGroup.setCode(FunctionGroupCode.AUTHORITY_PROVIDER);
        caFunctionGroup.setName(FunctionGroupCode.AUTHORITY_PROVIDER.getCode());
        functionGroupRepository.save(caFunctionGroup);

        FunctionGroup discoveryFunctionGroup = new FunctionGroup();
        discoveryFunctionGroup.setCode(FunctionGroupCode.DISCOVERY_PROVIDER);
        discoveryFunctionGroup.setName(FunctionGroupCode.DISCOVERY_PROVIDER.getCode());
        functionGroupRepository.save(discoveryFunctionGroup);

        FunctionGroup credentialProviderFunctionGroup = new FunctionGroup();
        credentialProviderFunctionGroup.setCode(FunctionGroupCode.CREDENTIAL_PROVIDER);
        credentialProviderFunctionGroup.setName(FunctionGroupCode.CREDENTIAL_PROVIDER.getCode());
        functionGroupRepository.save(credentialProviderFunctionGroup);

        Connector connector = new Connector();
        connector.setName("testConnector");
        connector.setUrl("http://localhost:"+mockServer.port());
        connector = connectorRepository.save(connector);

        addFunctionGroupToConnector(caFunctionGroup, Collections.singletonList(kindName), connector);
        addFunctionGroupToConnector(discoveryFunctionGroup, Collections.singletonList(kindName), connector);

        InfoResponse infoResponse = new InfoResponse();
        infoResponse.setFunctionGroupCode(FunctionGroupCode.CREDENTIAL_PROVIDER);
        infoResponse.setEndPoints(Collections.emptyList());
        String jsonBody = objectMapper.writeValueAsString(Collections.singletonList(infoResponse));
        mockServer.stubFor(WireMock.get("/v1")
                .willReturn(WireMock.okJson(jsonBody)));

        List<ConnectDto> dtos = connectorService.reconnect(connector.getSecuredUuid());
        Assertions.assertNotNull(dtos);
        Assertions.assertFalse(dtos.isEmpty());
        Assertions.assertEquals(1, dtos.size());
        Assertions.assertEquals(FunctionGroupCode.CREDENTIAL_PROVIDER, dtos.get(0).getFunctionGroup().getFunctionGroupCode());
    }
}
