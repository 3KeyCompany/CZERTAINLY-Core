package com.czertainly.core.service;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.approvalprofile.ApprovalProfileDto;
import com.czertainly.api.model.client.approvalprofile.ApprovalProfileRelationDto;
import com.czertainly.api.model.client.raprofile.AddRaProfileRequestDto;
import com.czertainly.api.model.client.raprofile.EditRaProfileRequestDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.raprofile.RaProfileDto;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.util.MetaDefinitions;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.security.cert.CertificateException;
import java.util.*;

public class RaProfileServiceTest extends ApprovalProfileData {

    private static final String RA_PROFILE_NAME = "testRaProfile1";

    @Autowired
    private com.czertainly.core.service.RaProfileService raProfileService;

    @Autowired
    private ApprovalProfileService approvalProfileService;

    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    @Autowired
    private ApprovalProfileRelationRepository approvalProfileRelationRepository;
    private RaProfile raProfile;
    private Certificate certificate;
    private CertificateContent certificateContent;
    private AuthorityInstanceReference authorityInstanceReference;
    private Connector connector;

    private WireMockServer mockServer;

    @BeforeEach
    public void setUp() {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        connector = new Connector();
        connector.setUuid(UUID.randomUUID());
        connector.setName("authorityInstanceConnector");
        connector.setUrl("http://localhost:"+mockServer.port());
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

        certificateContent = new CertificateContent();
        certificateContent = certificateContentRepository.save(certificateContent);

        certificate = new Certificate();
        certificate.setCertificateContent(certificateContent);
        certificate.setSerialNumber("123456789");
        certificate = certificateRepository.save(certificate);

        authorityInstanceReference = new AuthorityInstanceReference();
        authorityInstanceReference.setAuthorityInstanceUuid("1l");
        authorityInstanceReference.setConnector(connector);
        authorityInstanceReference = authorityInstanceReferenceRepository.save(authorityInstanceReference);

        raProfile = new RaProfile();
        raProfile.setName(RA_PROFILE_NAME);
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        raProfile.setEnabled(true);
        raProfile = raProfileRepository.save(raProfile);
    }

    @AfterEach
    public void tearDown() {
        mockServer.stop();
    }

    @Test
    public void testListRaProfiles() {
        List<RaProfileDto> raProfiles = raProfileService.listRaProfiles(SecurityFilter.create(), Optional.of(true));
        Assertions.assertNotNull(raProfiles);
        Assertions.assertFalse(raProfiles.isEmpty());
        Assertions.assertEquals(1, raProfiles.size());
        Assertions.assertEquals(raProfile.getUuid().toString(), raProfiles.get(0).getUuid());
    }

    @Test
    public void testGetRaProfileByUuid() throws NotFoundException {
        RaProfileDto dto = raProfileService.getRaProfile(raProfile.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(raProfile.getUuid().toString(), dto.getUuid());
    }

    @Test
    public void testGetRaProfileByUuid_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> raProfileService.getRaProfile(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    public void testAddRaProfile() throws ConnectorException, AlreadyExistException, AttributeException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/raProfile/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/caCertificates"))
                .willReturn(WireMock.okJson("""
                        {
                            "certificates": [
                            ]
                        }""")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/raProfile/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        AddRaProfileRequestDto request = new AddRaProfileRequestDto();
        request.setName("testRaProfile2");
        request.setAttributes(List.of());

        RaProfileDto dto = raProfileService.addRaProfile(authorityInstanceReference.getSecuredParentUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
    }

    @Test
    public void testAddRaProfile_validationFail() {
        AddRaProfileRequestDto request = new AddRaProfileRequestDto();
        Assertions.assertThrows(ValidationException.class, () -> raProfileService.addRaProfile(authorityInstanceReference.getSecuredParentUuid(), request));
    }

    @Test
    public void testAddRaProfile_alreadyExist() {
        AddRaProfileRequestDto request = new AddRaProfileRequestDto();
        request.setName(RA_PROFILE_NAME); // raProfile with same username exist

        Assertions.assertThrows(AlreadyExistException.class, () -> raProfileService.addRaProfile(authorityInstanceReference.getSecuredParentUuid(), request));
    }

    @Test
    public void testEditRaProfile() throws ConnectorException, AttributeException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/raProfile/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/raProfile/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        EditRaProfileRequestDto request = new EditRaProfileRequestDto();
        request.setDescription("some description");
        request.setAttributes(List.of());

        RaProfileDto dto = raProfileService.editRaProfile(authorityInstanceReference.getSecuredParentUuid(), raProfile.getSecuredUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getDescription(), dto.getDescription());
    }

    @Test
    public void testEditRaProfile_notFound() {
        EditRaProfileRequestDto request = new EditRaProfileRequestDto();

        Assertions.assertThrows(NotFoundException.class, () -> raProfileService.editRaProfile(authorityInstanceReference.getSecuredParentUuid(), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), request));
    }

    @Test
    public void testRemoveRaProfile() throws NotFoundException {
        raProfileService.deleteRaProfile(raProfile.getSecuredUuid());
        Assertions.assertThrows(NotFoundException.class, () -> raProfileService.getRaProfile(raProfile.getSecuredUuid()));
    }

    @Test
    public void testRemoveRaProfile_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> raProfileService.deleteRaProfile(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    public void testEnableRaProfile() throws NotFoundException, CertificateException {
        raProfileService.enableRaProfile(raProfile.getSecuredParentUuid(), raProfile.getSecuredUuid());
        Assertions.assertEquals(true, raProfile.getEnabled());
    }

    @Test
    public void testEnableRaProfile_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> raProfileService.enableRaProfile(raProfile.getSecuredParentUuid(), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    public void testDisableRaProfile() throws NotFoundException {
        raProfileService.disableRaProfile(raProfile.getSecuredParentUuid(), raProfile.getSecuredUuid());
        Assertions.assertEquals(false, raProfile.getEnabled());
    }

    @Test
    public void testDisableRaProfile_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> raProfileService.disableRaProfile(raProfile.getSecuredParentUuid(), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }


    @Test
    public void testBulkRemove() {
        raProfileService.bulkDeleteRaProfile(List.of(raProfile.getSecuredUuid()));
        Assertions.assertThrows(NotFoundException.class, () -> raProfileService.getRaProfile(raProfile.getSecuredUuid()));
    }

    @Test
    public void testBulkEnable() {
        raProfileService.bulkEnableRaProfile(List.of(raProfile.getSecuredUuid()));
        Assertions.assertTrue(raProfile.getEnabled());
    }

    @Test
    public void testBulkDisable() {
        raProfileService.bulkDisableRaProfile(List.of(raProfile.getSecuredUuid()));
        Assertions.assertFalse(raProfile.getEnabled());
    }

    @Test
    public void testGetObjectsForResource() {
        List<NameAndUuidDto> dtos = raProfileService.listResourceObjects(SecurityFilter.create());
        Assertions.assertEquals(1, dtos.size());
    }

    @Test
    public void testAssociationRaProfileWithApprovalProfile() throws NotFoundException, AlreadyExistException {
        final ApprovalProfile approvalProfile = approvalProfileService.createApprovalProfile(approvalProfileRequestDto);
        final ApprovalProfileRelationDto approvalProfileRelation = raProfileService.associateApprovalProfile(raProfile.getAuthorityInstanceReferenceUuid().toString(), raProfile.getUuid().toString(), approvalProfile.getSecuredUuid());

        Assertions.assertNotNull(approvalProfileRelation);
        Assertions.assertEquals(raProfile.getUuid(), approvalProfileRelation.getResourceUuid());
        Assertions.assertEquals(approvalProfile.getUuid().toString(), approvalProfileRelation.getApprovalProfileUuid());
        Assertions.assertEquals(Resource.RA_PROFILE, approvalProfileRelation.getResource());
    }

    @Test
    public void testDisassociationRaProfileWithApprovalProfile() throws NotFoundException, AlreadyExistException {
        final ApprovalProfile approvalProfile = approvalProfileService.createApprovalProfile(approvalProfileRequestDto);
        final ApprovalProfileRelationDto approvalProfileRelation = raProfileService.associateApprovalProfile(raProfile.getAuthorityInstanceReferenceUuid().toString(), raProfile.getUuid().toString(), approvalProfile.getSecuredUuid());
        Assertions.assertNotNull(approvalProfileRelation);

        raProfileService.disassociateApprovalProfile(raProfile.getAuthorityInstanceReferenceUuid().toString(), raProfile.getUuid().toString(), approvalProfile.getSecuredUuid());

        final Optional<ApprovalProfileRelation> approvalProfileRelationOptional = approvalProfileRelationRepository.findByUuid(SecuredUUID.fromString(approvalProfileRelation.getUuid()));
        Assertions.assertFalse(approvalProfileRelationOptional.isPresent());
    }

    @Test
    public void testListOfApprovalProfilesByRAProfile() throws NotFoundException, AlreadyExistException {
        final SecurityFilter securityFilter = SecurityFilter.create();
        final ApprovalProfile approvalProfile = approvalProfileService.createApprovalProfile(approvalProfileRequestDto);
        final ApprovalProfileRelationDto approvalProfileRelation = raProfileService.associateApprovalProfile(raProfile.getAuthorityInstanceReferenceUuid().toString(), raProfile.getUuid().toString(), approvalProfile.getSecuredUuid());
        Assertions.assertNotNull(approvalProfileRelation);

        final List<ApprovalProfileDto> approvalProfiles = raProfileService.getAssociatedApprovalProfiles(raProfile.getAuthorityInstanceReferenceUuid().toString(), raProfile.getUuid().toString(), securityFilter);

        Assertions.assertEquals(1, approvalProfiles.size());

        final ApprovalProfileDto approvalProfileDto = approvalProfiles.get(0);
        Assertions.assertEquals(approvalProfile.getUuid().toString(), approvalProfileDto.getUuid());
    }

    @Test
    public void testGetAuthorityCertificateChain() throws ConnectorException, AlreadyExistException, AttributeException {
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/caCertificates"))
                .willReturn(WireMock.okJson("""
                        {
                            "certificates": [
                                {
                                    "certificateData": "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",
                                    "uuid": null,
                                    "meta": null,
                                    "certificateType": "X.509"
                                }    ]
                        }""")));
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/raProfile/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/raProfile/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        EditRaProfileRequestDto request = new EditRaProfileRequestDto();
        request.setDescription("some description");
        request.setAttributes(List.of());
        raProfileService.editRaProfile(authorityInstanceReference.getSecuredParentUuid(), raProfile.getSecuredUuid(), request);
        Assertions.assertNotNull(raProfile.getAuthorityCertificateUuid());

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/caCertificates"))
                .willReturn(WireMock.okJson("""
                        {
                            "certificates": [
                            ]
                        }""")));
        raProfileService.editRaProfile(authorityInstanceReference.getSecuredParentUuid(), raProfile.getSecuredUuid(), request);
        Assertions.assertNull(raProfile.getAuthorityCertificateUuid());

        AddRaProfileRequestDto requestAdd = new AddRaProfileRequestDto();
        requestAdd.setName("testRaProfile2");
        requestAdd.setAttributes(List.of());
        RaProfileDto dto = raProfileService.addRaProfile(authorityInstanceReference.getSecuredParentUuid(), requestAdd);
        Assertions.assertEquals(raProfile.getAuthorityCertificateUuid(), raProfileRepository.findByUuid(UUID.fromString(dto.getUuid())).get().getAuthorityCertificateUuid());
    }

    @Test
    public void testListIssueCertificateAttributes() throws ConnectorException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes"))
                .willReturn(WireMock.okJson("""
                        []""")));

        List<BaseAttribute> attributes = raProfileService.listIssueCertificateAttributes(authorityInstanceReference.getSecuredParentUuid(), raProfile.getSecuredUuid());
        Assertions.assertNotNull(attributes);
    }

}
