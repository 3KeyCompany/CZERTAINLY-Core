package com.czertainly.core.service;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.compliance.ComplianceGroupRequestDto;
import com.czertainly.api.model.client.compliance.ComplianceProfileRequestDto;
import com.czertainly.api.model.client.compliance.ComplianceProfileRuleDto;
import com.czertainly.api.model.client.compliance.ComplianceRuleAdditionRequestDto;
import com.czertainly.api.model.client.compliance.ComplianceRuleDeletionRequestDto;
import com.czertainly.api.model.client.compliance.RaProfileAssociationRequestDto;
import com.czertainly.api.model.client.raprofile.SimplifiedRaProfileDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.core.certificate.CertificateType;
import com.czertainly.api.model.core.compliance.ComplianceProfileDto;
import com.czertainly.api.model.core.compliance.ComplianceProfilesListDto;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@SpringBootTest
@Transactional
@Rollback
public class ComplianceProfileServiceTest extends BaseSpringBootTest {

    @Autowired
    private ComplianceProfileRepository complianceProfileRepository;

    @Autowired
    private ComplianceProfileService complianceProfileService;

    @Autowired
    private ComplianceRuleRepository complianceRuleRepository;

    @Autowired
    private ComplianceGroupRepository complianceGroupRepository;

    @Autowired
    private ComplianceProfileRuleRepository complianceProfileRuleRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    private Connector connector;
    private WireMockServer mockServer;
    private ComplianceRule complianceRule;
    private ComplianceProfileRule complianceProfileRule;
    private ComplianceGroup complianceGroup;
    private ComplianceProfile complianceProfile;
    private RaProfile raProfile;
    private AuthorityInstanceReference authorityInstanceReference;


    @BeforeEach
    public void setUp() {

        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        connector = new Connector();
        connector.setName("Sample Connector");
        connector.setUrl("http://localhost:"+mockServer.port());
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        complianceGroup = new ComplianceGroup();
        complianceGroup.setName("testGroup");
        complianceGroup.setKind("default");
        complianceGroup.setDescription("Sample description");
        complianceGroup.setUuid(UUID.fromString("e8965d90-f1fd-11ec-b939-0242ac120003"));
        complianceGroup.setConnector(connector);
        complianceGroup.setConnectorUuid(connector.getUuid());
        complianceGroup = complianceGroupRepository.save(complianceGroup);
        complianceGroup.setConnector(connector);
        complianceGroup.setConnectorUuid(connector.getUuid());

        complianceRule = new ComplianceRule();
        complianceRule.setConnector(connector);
        complianceRule.setConnectorUuid(connector.getUuid());
        complianceRule.setKind("default");
        complianceRule.setName("Rule1");
        complianceRule.setDescription("Description");
        complianceRule.setUuid(UUID.fromString("e8965d90-f1fd-11ec-b939-0242ac120002"));
        complianceRule.setCertificateType(CertificateType.X509);
        complianceRule.setConnectorUuid(connector.getUuid());
        complianceRule.setGroup(complianceGroup);
        complianceRule.setGroupUuid(complianceGroup.getUuid());

        complianceProfile = new ComplianceProfile();
        complianceProfile.setName("TestProfile");
        complianceProfile.setDescription("Sample Description");
        complianceProfileRepository.save(complianceProfile);

        complianceProfileRule = new ComplianceProfileRule();
        complianceProfileRule.setComplianceProfile(complianceProfile);
        complianceProfileRule.setComplianceProfileUuid(complianceProfile.getUuid());
        complianceProfileRule.setComplianceRule(complianceRule);
        complianceProfileRule.setComplianceRuleUuid(complianceRule.getUuid());
        complianceProfileRule = complianceProfileRuleRepository.save(complianceProfileRule);

        complianceProfile.getComplianceRules().add(complianceProfileRule);
        complianceProfile.getGroups().add(complianceGroup);
        complianceProfileRepository.save(complianceProfile);

        complianceRule = new ComplianceRule();
        complianceRule.setConnector(connector);
        complianceRule.setConnectorUuid(connector.getUuid());
        complianceRule.setKind("default");
        complianceRule.setName("Rule2");
        complianceRule.setDescription("Description");
        complianceRule.setUuid(UUID.fromString("e8965d90-f1fd-11ec-b939-0242ac120004"));
        complianceRule.setCertificateType(CertificateType.X509);
        complianceRuleRepository.save(complianceRule);

        ComplianceGroup complianceGroup2 = new ComplianceGroup();
        complianceGroup2.setName("Group2");
        complianceGroup2.setKind("default");
        complianceGroup2.setDescription("Sample description");
        complianceGroup2.setUuid(UUID.fromString("e8965d90-f1fd-11ec-b939-0242ac120005"));
        complianceGroup2.setConnector(connector);
        complianceGroup2.setConnectorUuid(connector.getUuid());
        complianceGroupRepository.save(complianceGroup2);

        authorityInstanceReference = new AuthorityInstanceReference();
        authorityInstanceReference.setAuthorityInstanceUuid("1l");
        authorityInstanceReference.setConnector(connector);
        authorityInstanceReference = authorityInstanceReferenceRepository.save(authorityInstanceReference);

        raProfile = new RaProfile();
        raProfile.setName("TestProfile");
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        raProfile = raProfileRepository.save(raProfile);

        complianceProfile.getRaProfiles().add(raProfile);
        complianceProfileRepository.save(complianceProfile);

        raProfile = new RaProfile();
        raProfile.setName("TestProfile2");
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        raProfile = raProfileRepository.save(raProfile);
    }

    @AfterEach
    public void tearDown() {
        mockServer.stop();
    }

    @Test
    public void testListComplianceProfiles() {
        List<ComplianceProfilesListDto> dtos = complianceProfileService.listComplianceProfiles(SecurityFilter.create());
        Assertions.assertNotNull(dtos);
        Assertions.assertEquals(1, dtos.size());
        Assertions.assertEquals("TestProfile", dtos.get(0).getName());
        Assertions.assertEquals(complianceProfile.getUuid().toString(), dtos.get(0).getUuid());
    }

    @Test
    public void testGetComplianceProfile() throws NotFoundException {
        ComplianceProfileDto complianceProfileDto = complianceProfileService.getComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertNotNull(complianceProfileDto);
        Assertions.assertEquals(complianceProfileDto.getName(), complianceProfile.getName());
        Assertions.assertEquals(complianceProfileDto.getUuid(), complianceProfile.getUuid().toString());
        Assertions.assertEquals(complianceProfileDto.getDescription(), complianceProfile.getDescription());
        Assertions.assertEquals(complianceProfileDto.getRules().size(), complianceProfile.getComplianceRules().size());
        Assertions.assertEquals(complianceProfileDto.getGroups().size(), complianceProfile.getGroups().size());
    }

    @Test
    public void testGetComplianceProfileNotFound() throws NotFoundException {
        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.getComplianceProfile(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    public void createComplianceProfileTest() throws ConnectorException, AlreadyExistException, AttributeException {
        ComplianceProfileRequestDto requestDto = new ComplianceProfileRequestDto();
        requestDto.setName("sample2");
        requestDto.setDescription("sampleDescription");

        ComplianceProfileDto dto = complianceProfileService.createComplianceProfile(requestDto);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(dto.getRules().size(), 0);
        Assertions.assertEquals(dto.getName(), "sample2");
        Assertions.assertEquals(dto.getDescription(), "sampleDescription");
    }

    @Test
    public void createComplianceProfile_AlreadyExistsTest() throws AlreadyExistException {
        ComplianceProfileRequestDto requestDto = new ComplianceProfileRequestDto();
        requestDto.setName("TestProfile");
        requestDto.setDescription("description");

        Assertions.assertThrows(AlreadyExistException.class, () -> complianceProfileService.createComplianceProfile(requestDto));
    }

    @Test
    public void addRuleTest() throws NotFoundException, AlreadyExistException {
        ComplianceRuleAdditionRequestDto dto = new ComplianceRuleAdditionRequestDto();
        dto.setRuleUuid("e8965d90-f1fd-11ec-b939-0242ac120004");
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setKind("default");

        ComplianceProfileRuleDto complianceProfileDto = complianceProfileService.addRule(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto);
        Assertions.assertNotNull(complianceProfileDto);
    }

    @Test
    public void addRule_RuleNotFound() {
        ComplianceRuleAdditionRequestDto dto = new ComplianceRuleAdditionRequestDto();
        dto.setRuleUuid("abfbc322-29e1-11ed-a261-0242ac120002");
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setKind("default");

        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.addRule(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto));
    }

    @Test
    public void addRule_RuleAlreadyExists() {
        ComplianceRuleAdditionRequestDto dto = new ComplianceRuleAdditionRequestDto();
        dto.setRuleUuid("e8965d90-f1fd-11ec-b939-0242ac120002");
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setKind("default");

        Assertions.assertThrows(AlreadyExistException.class, () -> complianceProfileService.addRule(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto));
    }

    @Test
    public void deleteRuleTest() throws NotFoundException, AlreadyExistException {
        ComplianceRuleDeletionRequestDto dto = new ComplianceRuleDeletionRequestDto();
        dto.setRuleUuid("e8965d90-f1fd-11ec-b939-0242ac120002");
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setKind("default");

        ComplianceProfileRuleDto complianceProfileDto = complianceProfileService.removeRule(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto);
        Assertions.assertNotNull(complianceProfileDto);
    }

    @Test
    public void deleteRule_RuleNotFound() {
        ComplianceRuleDeletionRequestDto dto = new ComplianceRuleDeletionRequestDto();
        dto.setRuleUuid("abfbc322-29e1-11ed-a261-0242ac120002");
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setKind("default");

        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.removeRule(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto));
    }

    @Test
    public void addGroupTest() throws NotFoundException, AlreadyExistException {
        ComplianceGroupRequestDto dto = new ComplianceGroupRequestDto();
        dto.setGroupUuid("e8965d90-f1fd-11ec-b939-0242ac120005");
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setKind("default");

        ComplianceProfileDto complianceProfileDto = complianceProfileService.addGroup(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto);
        Assertions.assertNotNull(complianceProfileDto);
    }

    @Test
    public void addGroup_RuleNotFound() {
        ComplianceGroupRequestDto dto = new ComplianceGroupRequestDto();
        dto.setGroupUuid("abfbc322-29e1-11ed-a261-0242ac120002");
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setKind("default");

        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.addGroup(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto));
    }

    @Test
    public void addGroup_AlreadyExists() {
        ComplianceGroupRequestDto dto = new ComplianceGroupRequestDto();
        dto.setGroupUuid("e8965d90-f1fd-11ec-b939-0242ac120003");
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setKind("default");

        Assertions.assertThrows(AlreadyExistException.class, () -> complianceProfileService.addGroup(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto));
    }

    @Test
    public void deleteGroupTest() throws NotFoundException {
        ComplianceGroupRequestDto dto = new ComplianceGroupRequestDto();
        dto.setGroupUuid("e8965d90-f1fd-11ec-b939-0242ac120005");
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setKind("default");

        ComplianceProfileDto complianceProfileDto = complianceProfileService.removeGroup(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto);
        Assertions.assertNotNull(complianceProfileDto);
    }

    @Test
    public void deleteGroup_RuleNotFound() {
        ComplianceGroupRequestDto dto = new ComplianceGroupRequestDto();
        dto.setGroupUuid("abfbc322-29e1-11ed-a261-0242ac120002");
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setKind("default");

        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.removeGroup(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto));
    }

    @Test
    public void removeComplianceProfileTest() throws NotFoundException {
        Assertions.assertThrows(ValidationException.class, () -> complianceProfileService.deleteComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid())));
    }

    @Test
    public void forceRemoveComplianceProfileTest() throws NotFoundException {
        complianceProfileService.forceDeleteComplianceProfiles(List.of(SecuredUUID.fromUUID(complianceProfile.getUuid())));
        Assertions.assertDoesNotThrow(() -> complianceProfileRepository.findAll().size());
    }

    @Test
    public void removeComplianceProfile_NotFound() throws NotFoundException {
        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.deleteComplianceProfile(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    public void getRaProfile() throws NotFoundException {
        List<SimplifiedRaProfileDto> ra = complianceProfileService.getAssociatedRAProfiles(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertNotNull(ra);
        Assertions.assertEquals(1, ra.size());
    }

    @Test
    public void associateRaProfile() throws NotFoundException {
        RaProfileAssociationRequestDto request = new RaProfileAssociationRequestDto();
        request.setRaProfileUuids(List.of(raProfile.getUuid().toString()));
        complianceProfileService.associateProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()), request);
    }

    @Test
    public void getComplianceRulesTest_Invalid() throws NotFoundException {
        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.getComplianceRules("abfbc322-29e1-11ed-a261-0242ac120002", null, null));
    }

    @Test
    public void getComplianceGroupsTest_Invalid() throws NotFoundException {
        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.getComplianceGroups("abfbc322-29e1-11ed-a261-0242ac120002", null));
    }

    @Test
    public void testGetObjectsForResource() {
        List<NameAndUuidDto> dtos = complianceProfileService.listResourceObjects(SecurityFilter.create());
        Assertions.assertEquals(1, dtos.size());
    }
}
