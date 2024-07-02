package com.czertainly.core.service;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.client.certificate.LocationsResponseDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.location.AddLocationRequestDto;
import com.czertainly.api.model.client.location.EditLocationRequestDto;
import com.czertainly.api.model.client.location.IssueToLocationRequestDto;
import com.czertainly.api.model.client.location.PushToLocationRequestDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.common.attribute.v2.properties.DataAttributeProperties;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.location.LocationDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;

public class LocationServiceTest extends BaseSpringBootTest {

    private static final String LOCATION_NAME = "testLocation1";
    private static final String LOCATION_NAME_NOMULTIENTRIES = "testLocation-noMultiEntries";
    private static final String LOCATION_NAME_NOKEYMANAGEMENT = "testLocation-noKeyManagement";

    @Autowired
    private LocationService locationService;
    @Autowired
    private LocationRepository locationRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private EntityInstanceReferenceRepository entityInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;

    private DataAttribute testAttribute;
    private DataAttribute testAttribute2;
    private Location location;
    private Location locationNoMultiEntries;
    private Location locationNoKeyManagement;
    private EntityInstanceReference entityInstanceReference;
    private Certificate certificate;
    private Certificate certificateWithoutLocation;
    private WireMockServer mockServer;
    private AttributeEngine attributeEngine;

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @BeforeEach
    public void setUp() throws NotFoundException, AttributeException {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        CertificateContent certificateContent = new CertificateContent();
        certificateContent = certificateContentRepository.save(certificateContent);

        certificate = new Certificate();
        certificate.setCertificateContent(certificateContent);
        certificate.setSerialNumber("cc4ab59d436a88dae957");
        certificate = certificateRepository.save(certificate);

        certificateWithoutLocation = new Certificate();
        certificateWithoutLocation.setState(CertificateState.ISSUED);
        certificateWithoutLocation.setValidationStatus(CertificateValidationStatus.VALID);
        certificateWithoutLocation.setCertificateContentId(certificateContent.getId());
        certificateWithoutLocation.setSerialNumber("aa4ab59d436a88dae957");
        certificateWithoutLocation = certificateRepository.save(certificateWithoutLocation);

        Connector connector = new Connector();
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        entityInstanceReference = new EntityInstanceReference();
        entityInstanceReference.setEntityInstanceUuid("ad8d8995-f12e-407e-a8d2-9a2fb91772bb");
        entityInstanceReference.setConnector(connector);
        entityInstanceReference = entityInstanceReferenceRepository.save(entityInstanceReference);

        prepareDataAttributesDefinitions();

        location = createLocation();
        locationNoMultiEntries = createLocationNoMultiEntries();
        locationNoKeyManagement = createLocationNoKeyManagement();

        // Use distinct instances of CertificateLocation
        CertificateLocation certificateLocation1 = new CertificateLocation();
        certificateLocation1.setWithKey(true);
        certificateLocation1.setCertificate(certificate);
        certificateLocation1.setLocation(location);

        CertificateLocation certificateLocation2 = new CertificateLocation();
        certificateLocation2.setWithKey(true);
        certificateLocation2.setCertificate(certificate);
        certificateLocation2.setLocation(locationNoMultiEntries);

        CertificateLocation certificateLocation3 = new CertificateLocation();
        certificateLocation3.setWithKey(true);
        certificateLocation3.setCertificate(certificate);
        certificateLocation3.setLocation(locationNoKeyManagement);

        location.getCertificates().add(certificateLocation1);
        locationNoMultiEntries.getCertificates().add(certificateLocation2);
        locationNoKeyManagement.getCertificates().add(certificateLocation3);

        location = locationRepository.save(location);
        locationNoMultiEntries = locationRepository.save(locationNoMultiEntries);
        locationNoKeyManagement = locationRepository.save(locationNoKeyManagement);
    }


    private void prepareDataAttributesDefinitions() throws AttributeException {
        testAttribute = new DataAttribute();
        testAttribute.setUuid("5e9146a6-da8a-403f-99cb-d5d64d93ce1c");
        testAttribute.setName("attribute");

        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("Attribute");
        testAttribute.setDescription("description");
        testAttribute.setContentType(AttributeContentType.STRING);
        testAttribute.setType(AttributeType.DATA);
        properties.setRequired(true);
        properties.setReadOnly(false);
        properties.setVisible(true);
        testAttribute.setProperties(properties);

        testAttribute2 = new DataAttribute();
        testAttribute2.setUuid("c9819613-725e-4f01-89fb-cb896a26e555");
        testAttribute2.setName("sample");

        DataAttributeProperties sampleProps = new DataAttributeProperties();
        sampleProps.setLabel("Sample Attribute");
        testAttribute2.setDescription("Desc");
        testAttribute2.setContentType(AttributeContentType.STRING);
        testAttribute2.setType(AttributeType.DATA);
        sampleProps.setRequired(true);
        sampleProps.setReadOnly(false);
        sampleProps.setVisible(true);
        testAttribute2.setProperties(sampleProps);

        attributeEngine.updateDataAttributeDefinitions(entityInstanceReference.getConnectorUuid(), null, List.of(testAttribute, testAttribute2));
    }

    private Location createLocation() throws AttributeException, NotFoundException {
        Location location = new Location();
        location.setUuid(UUID.randomUUID());
        location.setName(LOCATION_NAME);
        location.setEntityInstanceReference(entityInstanceReference);
        location.setEnabled(true);
        location.setSupportKeyManagement(true);
        location.setSupportMultipleEntries(true);

        List<RequestAttributeDto> requestAttributes = AttributeDefinitionUtils.createAttributes(testAttribute.getUuid(), testAttribute.getName(), List.of(new StringAttributeContent("location")));
        attributeEngine.updateObjectDataAttributesContent(entityInstanceReference.getConnectorUuid(), null, Resource.LOCATION, location.getUuid(), requestAttributes);
        return location;
    }

    private Location createLocationNoMultiEntries() throws AttributeException, NotFoundException {
        Location location = new Location();
        location.setUuid(UUID.randomUUID());
        location.setName(LOCATION_NAME_NOMULTIENTRIES);
        location.setEntityInstanceReferenceUuid(entityInstanceReference.getUuid());
        location.setEnabled(true);
        location.setSupportKeyManagement(true);
        location.setSupportMultipleEntries(false);

        List<RequestAttributeDto> requestAttributes = AttributeDefinitionUtils.createAttributes(testAttribute.getUuid(), testAttribute.getName(), List.of(new StringAttributeContent("location_multi")));
        attributeEngine.updateObjectDataAttributesContent(entityInstanceReference.getConnectorUuid(), null, Resource.LOCATION, location.getUuid(), requestAttributes);

        return location;
    }

    private Location createLocationNoKeyManagement() throws AttributeException, NotFoundException {
        Location location = new Location();
        location.setUuid(UUID.randomUUID());
        location.setName(LOCATION_NAME_NOKEYMANAGEMENT);
        location.setEntityInstanceReference(entityInstanceReference);
        location.setEnabled(true);
        location.setSupportKeyManagement(false);
        location.setSupportMultipleEntries(true);

        List<RequestAttributeDto> requestAttributes = AttributeDefinitionUtils.createAttributes(testAttribute.getUuid(), testAttribute.getName(), List.of(new StringAttributeContent("location_no_key")));
        attributeEngine.updateObjectDataAttributesContent(entityInstanceReference.getConnectorUuid(), null, Resource.LOCATION, location.getUuid(), requestAttributes);

        return location;
    }

    @AfterEach
    public void tearDown() {
        mockServer.stop();
    }

    @Test
    public void testListLocations() {
        LocationsResponseDto locationsResponseDto = locationService.listLocations(SecurityFilter.create(), new SearchRequestDto());
        List<LocationDto> locations = locationsResponseDto.getLocations();
        Assertions.assertNotNull(locations);
        Assertions.assertFalse(locations.isEmpty());
        Assertions.assertEquals(3, locations.size());
    }

    @Test
    public void testGetLocationByUuid() throws NotFoundException {
        LocationDto dto = locationService.getLocation(SecuredParentUUID.fromUUID(location.getEntityInstanceReferenceUuid()), location.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(location.getUuid().toString(), dto.getUuid());
    }

    @Test
    public void testGetLocationByUuid_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> locationService.getLocation(SecuredParentUUID.fromUUID(location.getEntityInstanceReferenceUuid()), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    public void testAddLocation() throws ConnectorException, AlreadyExistException, LocationException, AttributeException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/location/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/location/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations"))
                .willReturn(WireMock.okJson("""
                        {
                          "certificates": [],
                          "multipleEntries": true,
                          "supportKeyManagement": true
                        }""")));

        AddLocationRequestDto request = new AddLocationRequestDto();
        request.setName("testLocation2");
        RequestAttributeDto requestAttributeDto = new RequestAttributeDto();
        requestAttributeDto.setUuid(testAttribute2.getUuid());
        requestAttributeDto.setName(testAttribute2.getName());
        requestAttributeDto.setContent(List.of(new StringAttributeContent("test")));
        request.setAttributes(List.of(requestAttributeDto));

        LocationDto dto = locationService.addLocation(SecuredParentUUID.fromUUID(entityInstanceReference.getUuid()), request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
    }

    @Test
    public void testAddLocation_DuplicateEntity() throws NotFoundException, AlreadyExistException, LocationException {
        AddLocationRequestDto request = new AddLocationRequestDto();
        request.setName("testLocation2");
        RequestAttributeDto attribute = new RequestAttributeDto();
        attribute.setName("attribute");
        attribute.setContent(List.of(new StringAttributeContent("location")));
        request.setAttributes(List.of(attribute));

        Assertions.assertThrows(ValidationException.class, () -> locationService.addLocation(SecuredParentUUID.fromUUID(entityInstanceReference.getUuid()), request));
    }

    @Test
    public void testAddLocation_validationFail() {
        AddLocationRequestDto request = new AddLocationRequestDto();
        Assertions.assertThrows(ValidationException.class, () -> locationService.addLocation(entityInstanceReference.getSecuredParentUuid(), request));
    }

    @Test
    public void testAddLocation_alreadyExist() {
        AddLocationRequestDto request = new AddLocationRequestDto();
        request.setName(LOCATION_NAME); // location with the name that already exists

        Assertions.assertThrows(AlreadyExistException.class, () -> locationService.addLocation(entityInstanceReference.getSecuredParentUuid(), request));
    }

    // TODO
    @Test
    public void testEditLocation() throws ConnectorException, LocationException, AttributeException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/location/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/location/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations"))
                .willReturn(WireMock.okJson("""
                        {
                          "certificates": [],
                          "multipleEntries": true,
                          "supportKeyManagement": true
                        }""")));

        EditLocationRequestDto request = new EditLocationRequestDto();
        request.setDescription("some description");
        request.setAttributes(List.of());

        LocationDto dto = locationService.editLocation(entityInstanceReference.getSecuredParentUuid(), location.getSecuredUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getDescription(), dto.getDescription());
    }

    @Test
    public void testEditLocation_notFound() {
        EditLocationRequestDto request = new EditLocationRequestDto();

        Assertions.assertThrows(NotFoundException.class, () -> locationService.editLocation(entityInstanceReference.getSecuredParentUuid(), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), request));
    }

    @Test
    public void testRemoveLocation_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> locationService.deleteLocation(entityInstanceReference.getSecuredParentUuid(), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    public void testEnableLocation() throws NotFoundException {
        locationService.enableLocation(location.getEntityInstanceReference().getSecuredParentUuid(), location.getSecuredUuid());
        Assertions.assertEquals(true, location.getEnabled());
    }

    @Test
    public void testEnableLocation_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> locationService.enableLocation(entityInstanceReference.getSecuredParentUuid(), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    public void testDisableLocation() throws NotFoundException {
        locationService.disableLocation(location.getEntityInstanceReference().getSecuredParentUuid(), location.getSecuredUuid());
        Assertions.assertEquals(false, location.getEnabled());
    }

    @Test
    public void testDisableLocation_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> locationService.disableLocation(entityInstanceReference.getSecuredParentUuid(), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    // TODO: testing the location push, remove, issue, sync

    @Test
    public void testPushCertificateToLocation_MultiNotSupported() {
        PushToLocationRequestDto request = new PushToLocationRequestDto();
        request.setAttributes(List.of());

        Assertions.assertThrows(LocationException.class, () -> locationService.pushCertificateToLocation(
                entityInstanceReference.getSecuredParentUuid(),
                locationNoMultiEntries.getSecuredUuid(),
                certificateWithoutLocation.getUuid().toString(), request)
        );
    }

    @Test
    public void testIssueCertificateToLocation_KeyManagementNotSupported() {
        IssueToLocationRequestDto request = new IssueToLocationRequestDto();
        request.setCsrAttributes(List.of());
        request.setIssueAttributes(List.of());
        request.setRaProfileUuid("test");

        Assertions.assertThrows(LocationException.class, () -> locationService.issueCertificateToLocation(SecuredParentUUID.fromUUID(locationNoKeyManagement.getEntityInstanceReferenceUuid()),
                locationNoKeyManagement.getSecuredUuid(),
                request.getRaProfileUuid(), request)
        );
    }

    @Test
    public void testIssueCertificateToLocation_MultiNotSupported() {
        IssueToLocationRequestDto request = new IssueToLocationRequestDto();
        request.setCsrAttributes(List.of());
        request.setIssueAttributes(List.of());
        request.setRaProfileUuid("test");

        Assertions.assertThrows(LocationException.class, () -> locationService.issueCertificateToLocation(
                SecuredParentUUID.fromUUID(locationNoMultiEntries.getEntityInstanceReferenceUuid()),
                locationNoMultiEntries.getSecuredUuid(),
                request.getRaProfileUuid(), request)
        );
    }

    @Test
    public void testGetObjectsForResource() {
        List<NameAndUuidDto> dtos = locationService.listResourceObjects(SecurityFilter.create());
        Assertions.assertEquals(3, dtos.size());
    }
}
