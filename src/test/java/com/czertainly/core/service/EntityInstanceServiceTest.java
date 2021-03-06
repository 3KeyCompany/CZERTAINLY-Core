package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.entity.EntityInstanceRequestDto;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.entity.EntityInstanceDto;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.Connector2FunctionGroup;
import com.czertainly.core.dao.entity.EntityInstanceReference;
import com.czertainly.core.dao.entity.FunctionGroup;
import com.czertainly.core.dao.repository.Connector2FunctionGroupRepository;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.EntityInstanceReferenceRepository;
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
public class EntityInstanceServiceTest {

    private static final String ENTITY_INSTANCE_NAME = "testEntityInstance1";

    @Autowired
    private EntityInstanceService entityInstanceService;
    @Autowired
    private EntityInstanceReferenceRepository entityInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    private EntityInstanceReference entityInstance;
    private Connector connector;

    private WireMockServer mockServer;

    @BeforeEach
    public void setUp() {
        mockServer = new WireMockServer(3665);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        connector = new Connector();
        connector.setUuid("41604e8c-6bf7-43d8-9071-121902897af4");
        connector.setName("entityInstanceConnector");
        connector.setUrl("http://localhost:3665");
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.ENTITY_PROVIDER);
        functionGroup.setName(FunctionGroupCode.ENTITY_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of("TestKind")));
        connector2FunctionGroupRepository.save(c2fg);

        connector.getFunctionGroups().add(c2fg);
        connectorRepository.save(connector);

        entityInstance = new EntityInstanceReference();
        entityInstance.setName(ENTITY_INSTANCE_NAME);
        entityInstance.setConnector(connector);
        entityInstance.setKind("TestKind");
        entityInstance.setEntityInstanceUuid("1l");
        entityInstance = entityInstanceReferenceRepository.save(entityInstance);
    }

    @AfterEach
    public void tearDown() {
        mockServer.stop();
    }

    @Test
    public void testListEntityInstances() {
        List<EntityInstanceDto> entityInstances = entityInstanceService.listEntityInstances();
        Assertions.assertNotNull(entityInstances);
        Assertions.assertFalse(entityInstances.isEmpty());
        Assertions.assertEquals(1, entityInstances.size());
        Assertions.assertEquals(entityInstance.getUuid(), entityInstances.get(0).getUuid());
    }

    @Test
    public void testGetEntityInstance() throws ConnectorException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+"))
                .willReturn(WireMock.okJson("{}")));

        EntityInstanceDto dto = entityInstanceService.getEntityInstance(entityInstance.getUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(entityInstance.getUuid(), dto.getUuid());
        Assertions.assertNotNull(dto.getConnectorUuid());
        Assertions.assertEquals(entityInstance.getConnector().getUuid(), dto.getConnectorUuid());
    }

    @Test
    public void testGetEntityInstance_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> entityInstanceService.getEntityInstance("wrong-uuid"));
    }

    @Test
    public void testAddEntityInstance() throws ConnectorException, AlreadyExistException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/entityProvider/[^/]+/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/entityProvider/[^/]+/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/entityProvider/entities"))
                .willReturn(WireMock.okJson("{ \"id\": 2 }")));

        EntityInstanceRequestDto request = new EntityInstanceRequestDto();
        request.setName("testEntityInstance2");
        request.setConnectorUuid(connector.getUuid());
        request.setAttributes(List.of());
        request.setKind("TestKind");

        EntityInstanceDto dto = entityInstanceService.createEntityInstance(request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
        Assertions.assertNotNull(dto.getConnectorUuid());
        Assertions.assertEquals(entityInstance.getConnector().getUuid(), dto.getConnectorUuid());
    }

    @Test
    public void testAddEntityInstance_notFound() {
        EntityInstanceRequestDto request = new EntityInstanceRequestDto();
        // connector uuid not set
        Assertions.assertThrows(NotFoundException.class, () -> entityInstanceService.createEntityInstance(request));
    }

    @Test
    public void testAddEntityInstance_alreadyExist() {
        EntityInstanceRequestDto request = new EntityInstanceRequestDto();
        request.setName(ENTITY_INSTANCE_NAME); // entityInstance with same name already exist

        Assertions.assertThrows(AlreadyExistException.class, () -> entityInstanceService.createEntityInstance(request));
    }

    @Test
    public void testEditEntityInstance_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> entityInstanceService.updateEntityInstance("wrong-uuid", null));
    }

    @Test
    public void testRemoveEntityInstance() throws ConnectorException {
        mockServer.stubFor(WireMock
                .delete(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+"))
                .willReturn(WireMock.ok()));

        entityInstanceService.removeEntityInstance(entityInstance.getUuid());
        Assertions.assertThrows(NotFoundException.class, () -> entityInstanceService.getEntityInstance(entityInstance.getUuid()));
    }

    @Test
    public void testGetLocationAttributes() throws ConnectorException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/location/attributes"))
                .willReturn(WireMock.ok()));

        entityInstanceService.listLocationAttributes(entityInstance.getUuid());
    }

    @Test
    public void testGetLocationAttributes_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> entityInstanceService.listLocationAttributes("wrong-uuid"));
    }

    @Test
    public void testValidateLocationAttributes() throws ConnectorException {
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/location/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        entityInstanceService.validateLocationAttributes(entityInstance.getUuid(), List.of());
    }

    @Test
    public void testValidateLocationAttributes_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> entityInstanceService.validateLocationAttributes("wrong-uuid", null));
    }

    @Test
    public void testRemoveEntityInstance_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> entityInstanceService.removeEntityInstance("wrong-uuid"));
    }
}
