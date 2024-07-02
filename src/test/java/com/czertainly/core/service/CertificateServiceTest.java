package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.CertificateOperationException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.certificate.*;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.MetadataAttribute;
import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.common.attribute.v2.properties.MetadataAttributeProperties;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.*;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.MetaDefinitions;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

public class CertificateServiceTest extends BaseSpringBootTest {

    @Autowired
    private CertificateService certificateService;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    @Autowired
    private GroupRepository groupRepository;
    @Autowired
    private ResourceObjectAssociationService associationService;
    @Autowired
    private OwnerAssociationRepository ownerAssociationRepository;

    private AttributeEngine attributeEngine;


    private Certificate certificate;
    private CertificateContent certificateContent;
    private RaProfile raProfile;
    private RaProfile raProfileOld;
    private Group group;

    private X509Certificate x509Cert;

    private AuthorityInstanceReference authorityInstance;
    private Connector connector;
    private WireMockServer mockServer;

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @BeforeEach
    public void setUp() throws GeneralSecurityException, IOException, AttributeException {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        connector = new Connector();
        connector.setName("authorityInstanceConnector");
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.AUTHORITY_PROVIDER);
        functionGroup.setName(FunctionGroupCode.AUTHORITY_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setConnectorUuid(connector.getUuid());
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setFunctionGroupUuid(functionGroup.getUuid());
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of("ApiKey")));
        connector2FunctionGroupRepository.save(c2fg);

        connector.getFunctionGroups().add(c2fg);
        connectorRepository.save(connector);

        authorityInstance = new AuthorityInstanceReference();
        authorityInstance.setName("testAuthorityInstance1");
        authorityInstance.setConnector(connector);
        authorityInstance.setConnectorUuid(connector.getUuid());
        authorityInstance.setKind("sample");
        authorityInstance.setAuthorityInstanceUuid("1l");
        authorityInstance = authorityInstanceReferenceRepository.save(authorityInstance);

        certificateContent = new CertificateContent();
        certificateContent.setContent("123456");
        certificateContent = certificateContentRepository.save(certificateContent);

        raProfileOld = new RaProfile();
        raProfileOld.setName("Test RA profile Old");
        raProfileOld.setAuthorityInstanceReference(authorityInstance);
        raProfileOld = raProfileRepository.save(raProfileOld);

        certificate = new Certificate();
        certificate.setSubjectDn("testCertificate");
        certificate.setIssuerDn("testCercertificatetificate");
        certificate.setSerialNumber("123456789");
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setCertificateContent(certificateContent);
        certificate.setCertificateContentId(certificateContent.getId());
        certificate.setRaProfile(raProfileOld);
        certificate = certificateRepository.save(certificate);

        // Ensure OwnerAssociation is created and associated
        OwnerAssociation ownerAssociation = new OwnerAssociation();
        ownerAssociation.setOwnerUuid(UUID.randomUUID()); // Set a proper UUID
        ownerAssociation.setOwnerUsername("ownerName");
        ownerAssociation.setResource(Resource.CERTIFICATE);
        ownerAssociation.setObjectUuid(certificate.getUuid());
        ownerAssociationRepository.saveAndFlush(ownerAssociation);

        certificate.setOwner(ownerAssociation);
        certificateRepository.save(certificate);

        List<MetadataAttribute> meta = new ArrayList<>();
        MetadataAttribute tst = new MetadataAttribute();
        tst.setType(AttributeType.META);
        tst.setName("Test");
        tst.setContentType(AttributeContentType.STRING);
        tst.setUuid("9f94036e-f050-4c9c-a3b8-f47b1be696aa");
        tst.setProperties(new MetadataAttributeProperties() {{ setLabel("Test meta"); }});
        tst.setContent(List.of(new StringAttributeContent("xyz", "xyz")));
        meta.add(tst);

        UUID connectorUuid = raProfileOld.getAuthorityInstanceReference().getConnectorUuid();
        attributeEngine.updateMetadataAttributes(meta, new ObjectAttributeContentInfo(connectorUuid, Resource.CERTIFICATE, certificate.getUuid()));

        raProfile = new RaProfile();
        raProfile.setName("Test RA profile");
        raProfile.setAuthorityInstanceReference(authorityInstance);
        raProfile = raProfileRepository.save(raProfile);

        group = new Group();
        group = groupRepository.save(group);

        InputStream keyStoreStream = CertificateServiceTest.class.getClassLoader().getResourceAsStream("client1.p12");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(keyStoreStream, "123456".toCharArray());

        x509Cert = (X509Certificate) keyStore.getCertificate("1");
    }

    @Test
    public void testListCertificates() {
        CertificateResponseDto certificateEntities = certificateService.listCertificates(SecurityFilter.create(), new SearchRequestDto());
        Assertions.assertNotNull(certificateEntities);
        Assertions.assertFalse(certificateEntities.getCertificates().isEmpty());
        Assertions.assertEquals(1, certificateEntities.getCertificates().size());
        Assertions.assertEquals(certificate.getUuid().toString(), certificateEntities.getCertificates().get(0).getUuid());
    }

    @Test
    public void testGetCertificate() throws NotFoundException, CertificateException, IOException {
        CertificateDetailDto dto = certificateService.getCertificate(certificate.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(certificate.getUuid().toString(), dto.getUuid());
        Assertions.assertEquals(certificate.getSerialNumber(), dto.getSerialNumber());
    }

    @Test
    public void testGetCertificate_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> certificateService.getCertificate(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    public void testCreateCertificateEntity() {
        Certificate cert = certificateService.createCertificateEntity(x509Cert);

        Assertions.assertNotNull(cert);
        Assertions.assertEquals("CLIENT1", cert.getCommonName());
        Assertions.assertEquals("177e75f42e95ecb98f831eb57de27b0bc8c47643", cert.getSerialNumber());
    }

    @Test
    public void testCheckCreateCertificate() throws CertificateException, AlreadyExistException, NoSuchAlgorithmException {
        Certificate cert = certificateService.checkCreateCertificate(Base64.getEncoder().encodeToString(x509Cert.getEncoded()));

        Assertions.assertNotNull(cert);
        Assertions.assertEquals("CLIENT1", cert.getCommonName());
        Assertions.assertEquals("177e75f42e95ecb98f831eb57de27b0bc8c47643", cert.getSerialNumber());
    }

    @Test
    public void testAddCertificate_certificateException() {
        Assertions.assertThrows(CertificateException.class, () -> certificateService.checkCreateCertificate("certificate"));
    }

    @Test
    public void testRemoveCertificate_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> certificateService.deleteCertificate(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    public void testRevokeCertificate() throws NotFoundException, CertificateException, IOException {
        certificateService.revokeCertificate(certificate.getSerialNumber());

        CertificateDetailDto dto = certificateService.getCertificate(certificate.getSecuredUuid());

        Assertions.assertNotNull(dto);
        Assertions.assertEquals(certificate.getUuid().toString(), dto.getUuid());
        Assertions.assertEquals(certificate.getSerialNumber(), dto.getSerialNumber());
        Assertions.assertEquals(CertificateState.REVOKED, dto.getState());
    }

    @Test
    @Disabled("Revoke doesn't throw NotFoundException")
    public void testRevokeCertificate_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> certificateService.revokeCertificate("abfbc322-29e1-11ed-a261-0242ac120002"));
    }

    @Test
    public void testUploadCertificate() throws CertificateException, AlreadyExistException, NoSuchAlgorithmException, NotFoundException, AttributeException {
        UploadCertificateRequestDto request = new UploadCertificateRequestDto();
        request.setCertificate(Base64.getEncoder().encodeToString(x509Cert.getEncoded()));

        CertificateDetailDto dto = certificateService.upload(request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals("CLIENT1", dto.getCommonName());
        Assertions.assertEquals("177e75f42e95ecb98f831eb57de27b0bc8c47643", dto.getSerialNumber());
    }

    @Test
    public void testUpdateRaProfile() throws NotFoundException, CertificateOperationException, CertificateException, IOException, AttributeException {
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/identify"))
                .willReturn(WireMock.okJson("{\"meta\":[{\"uuid\":\"b42ab690-60fd-11ed-9b6a-0242ac120002\",\"name\":\"ejbcaUsername\",\"description\":\"EJBCA Username\",\"content\":[{\"reference\":\"ShO0lp7qbnE=\",\"data\":\"ShO0lp7qbnE=\"}],\"type\":\"meta\",\"contentType\":\"string\",\"properties\":{\"label\":\"EJBCA Username\",\"visible\":true,\"group\":null,\"global\":false}}]}")));

        CertificateUpdateObjectsDto uuidDto = new CertificateUpdateObjectsDto();
        uuidDto.setRaProfileUuid(raProfile.getUuid().toString());
        certificateService.updateCertificateObjects(certificate.getSecuredUuid(), uuidDto);

        Assertions.assertEquals(raProfile, certificate.getRaProfile());
        CertificateDetailDto certificateDetailDto = certificateService.getCertificate(certificate.getSecuredUuid());

        Assertions.assertEquals(1, certificateDetailDto.getMetadata().size());
        Assertions.assertEquals(connector.getName(), certificateDetailDto.getMetadata().get(0).getConnectorName());
        Assertions.assertEquals(1, certificateDetailDto.getMetadata().get(0).getItems().size());
    }

    @Test
    public void testUpdateRaProfileFails() throws NotFoundException, CertificateOperationException {
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/identify"))
                .willReturn(WireMock.jsonResponse("{\"message\": \"Object of type 'Certificate' not identified.\"}", 404)));

        CertificateUpdateObjectsDto uuidDto = new CertificateUpdateObjectsDto();
        uuidDto.setRaProfileUuid(raProfile.getUuid().toString());

        Assertions.assertThrows(CertificateOperationException.class, () -> certificateService.updateCertificateObjects(certificate.getSecuredUuid(), uuidDto));

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/identify"))
                .willReturn(WireMock.jsonResponse("[\"Object of type 'Certificate' identified but not valid according RA profile attributes.\"]", 422)));

        Assertions.assertThrows(CertificateOperationException.class, () -> certificateService.updateCertificateObjects(certificate.getSecuredUuid(), uuidDto));
    }

    @Test
    public void testUpdateRaProfile_certificateNotFound() {
        CertificateUpdateObjectsDto uuidDto = new CertificateUpdateObjectsDto();
        uuidDto.setRaProfileUuid(raProfile.getUuid().toString());
        Assertions.assertThrows(NotFoundException.class, () -> certificateService.updateCertificateObjects(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), uuidDto));
    }

    @Test
    public void testUpdateRaProfile_raProfileNotFound() {
        CertificateUpdateObjectsDto uuidDto = new CertificateUpdateObjectsDto();
        uuidDto.setRaProfileUuid("abfbc322-29e1-11ed-a261-0242ac120002");
        Assertions.assertThrows(NotFoundException.class, () -> certificateService.updateCertificateObjects(certificate.getSecuredUuid(), uuidDto));
    }

    @Disabled("Because Hibernate generating duplicates in foreign key constraint name")
    @Test
    public void testUpdateCertificateGroup() throws NotFoundException, CertificateOperationException, AttributeException {
        CertificateUpdateObjectsDto uuidDto = new CertificateUpdateObjectsDto();
        uuidDto.setGroupUuids(List.of(group.getUuid().toString()));

        certificateService.updateCertificateObjects(certificate.getSecuredUuid(), uuidDto);

        // use association service to load certificate group associations since groups are not lazy loaded to mapped certificate relation due to scope of transaction in test
        List<UUID> groupUuids = associationService.getGroupUuids(Resource.CERTIFICATE, certificate.getUuid());
        Assertions.assertEquals(1, groupUuids.size());
        Assertions.assertEquals(group.getUuid(), groupUuids.get(0));
    }

    @Test
    public void testUpdateCertificateGroup_certificateNotFound() {
        CertificateUpdateObjectsDto uuidDto = new CertificateUpdateObjectsDto();
        uuidDto.setGroupUuids(List.of(group.getUuid().toString()));
        Assertions.assertThrows(NotFoundException.class, () -> certificateService.updateCertificateObjects(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), uuidDto));
    }

    @Test
    public void testUpdateCertificateGroup_groupNotFound() {
        CertificateUpdateObjectsDto uuidDto = new CertificateUpdateObjectsDto();
        uuidDto.setGroupUuids(List.of(UUID.randomUUID().toString()));
        Assertions.assertThrows(NotFoundException.class, () -> certificateService.updateCertificateObjects(certificate.getSecuredUuid(), uuidDto));
    }


    @Test
    @Disabled("get user from API")
    public void testUpdateOwner() throws NotFoundException, CertificateOperationException, AttributeException {
        mockServer = new WireMockServer(10001);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/users/[^/]+")).willReturn(
                WireMock.okJson("{ \"username\": \"newOwner\"}")
        ));

        CertificateUpdateObjectsDto request = new CertificateUpdateObjectsDto();
        request.setOwnerUuid(UUID.randomUUID().toString());

        certificateService.updateCertificateObjects(certificate.getSecuredUuid(), request);

        // use association service to load certificate owner association since owner is not lazy loaded to mapped certificate relation due to scope of transaction in test
        NameAndUuidDto owner = associationService.getOwner(Resource.CERTIFICATE, certificate.getUuid());
        Assertions.assertNotNull(owner);
        Assertions.assertEquals(request.getOwnerUuid(), owner.getUuid());
        Assertions.assertEquals("newOwner", owner.getName());
    }

    @Test
    @Disabled("get user from API")
    public void testUpdateCertificateOwner_certificateNotFound() {
        CertificateUpdateObjectsDto dto = new CertificateUpdateObjectsDto();
        dto.setOwnerUuid("testOwner");
        Assertions.assertThrows(NotFoundException.class, () -> certificateService.updateCertificateObjects(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), dto));
    }

    //TODO lukas.rejha need to be fixed
    @Disabled
    @Test
    public void testSearchableFields() {
        final List<SearchFieldDataByGroupDto> response = certificateService.getSearchableFieldInformationByGroup();
        Assertions.assertNotNull(response);
        Assertions.assertFalse(response.isEmpty());
    }

    @Test
    @Disabled("Necessary to resolve handling non transactional method inside transactional test. Objects stored in setUp method are not available since transaction will be suspended in bulk delete.")
    public void testBulkRemove() throws NotFoundException {
        RemoveCertificateDto request = new RemoveCertificateDto();
        request.setUuids(List.of(certificate.getUuid().toString()));

        certificateService.bulkDeleteCertificate(SecurityFilter.create(), request);

        Assertions.assertThrows(NotFoundException.class, () -> certificateService.getCertificate(certificate.getSecuredUuid()));
    }

    @Test
    public void testDownloadCertificate() throws NotFoundException, CertificateException, IOException {
        CertificateContent certificateContentDownload = new CertificateContent();
        certificateContentDownload.setContent("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");
        certificateContentDownload = certificateContentRepository.save(certificateContentDownload);
        certificate.setCertificateContent(certificateContentDownload);
        testDownloadInternal(CertificateFormat.RAW, CertificateFormatEncoding.PEM);
        testDownloadInternal(CertificateFormat.RAW, CertificateFormatEncoding.DER);
        testDownloadInternal(CertificateFormat.PKCS7, CertificateFormatEncoding.PEM);
        testDownloadInternal(CertificateFormat.PKCS7, CertificateFormatEncoding.DER);
    }

    private void testDownloadInternal(CertificateFormat format, CertificateFormatEncoding encoding) throws NotFoundException, CertificateException, IOException {
        CertificateDownloadResponseDto certificateDownloadResponseDto = certificateService.downloadCertificate(certificate.getUuid().toString(), format, encoding);
        Assertions.assertDoesNotThrow(() -> (certificateService.createCertificate(certificateDownloadResponseDto.getContent(), CertificateType.X509)));
    }
}
