package com.czertainly.core.service;

import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateType;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.UUID;

public class ComplianceServiceTest extends BaseSpringBootTest {

    private static final String RA_PROFILE_NAME = "testRaProfile1";
    private static final String CLIENT_NAME = "testClient1";

    @Autowired
    private com.czertainly.core.service.RaProfileService raProfileService;

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
    private ComplianceService complianceService;
    @Autowired
    private ComplianceGroupRepository complianceGroupRepository;
    @Autowired
    private ComplianceRuleRepository complianceRuleRepository;


    private RaProfile raProfile;
    private Certificate certificate;
    private CertificateContent certificateContent;
    private AuthorityInstanceReference authorityInstanceReference;
    private Connector connector;
    private ComplianceRule complianceRule;
    private ComplianceGroup complianceGroup;

    private WireMockServer mockServer;
    private WireMockServer mockServer1;

    @BeforeEach
    public void setUp() {
        mockServer1 = new WireMockServer(3666);
        mockServer1.start();

        WireMock.configureFor("localhost", mockServer1.port());


        certificateContent = new CertificateContent();
        certificateContent = certificateContentRepository.save(certificateContent);

        certificate = new Certificate();
        certificate.setCertificateContent(certificateContent);
        certificate.setSerialNumber("123456789");
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate = certificateRepository.save(certificate);

        connector = new Connector();
        connector.setUrl("http://localhost:3666");
        connector = connectorRepository.save(connector);

        authorityInstanceReference = new AuthorityInstanceReference();
        authorityInstanceReference.setAuthorityInstanceUuid("1l");
        authorityInstanceReference.setConnector(connector);
        authorityInstanceReference = authorityInstanceReferenceRepository.save(authorityInstanceReference);

        raProfile = new RaProfile();
        raProfile.setName(RA_PROFILE_NAME);
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        raProfile = raProfileRepository.save(raProfile);

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
        complianceGroup.setConnectorUuid(connector.getUuid());
        complianceGroupRepository.save(complianceGroup);

        complianceRule = new ComplianceRule();
        complianceRule.setConnectorUuid(connector.getUuid());
        complianceRule.setKind("default");
        complianceRule.setName("Rule1");
        complianceRule.setDescription("Description");
        complianceRule.setUuid(UUID.fromString("e8965d90-f1fd-11ec-b939-0242ac120002"));
        complianceRule.setCertificateType(CertificateType.X509);
        complianceRule.setGroup(complianceGroup);
        complianceRuleRepository.save(complianceRule);
    }

    @AfterEach
    public void tearDown() {
        mockServer.stop();
        mockServer1.stop();
    }

    @Test
    public void testComplianceCheck() throws ConnectorException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/complianceProvider/[^/]+/compliance"))
                .willReturn(WireMock.okJson("{'status':'ok','rules':['uuid':'121212121212', 'name':'tests', 'status':'ok']}")));
        Assertions.assertDoesNotThrow(() -> complianceService.checkComplianceOfCertificate(certificate));
    }

    @Test
    public void testComplianceCheck_RaProfile() throws ConnectorException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/complianceProvider/[^/]+/compliance"))
                .willReturn(WireMock.okJson("{'status':'ok','rules':['uuid':'121212121212', 'name':'tests', 'status':'ok']}")));
        Assertions.assertDoesNotThrow(() -> complianceService.complianceCheckForRaProfile(SecuredUUID.fromString(raProfile.getUuid().toString())));
    }

    @Test
    public void checkRuleExistsTest(){
        Boolean isExists = complianceService.complianceRuleExists(SecuredUUID.fromString(complianceRule.getUuid().toString()), connector, "default");
        Assertions.assertEquals(true, isExists);
    }

    @Test
    public void checkRuleNotExistsTest(){
        Boolean isExists = complianceService.complianceRuleExists(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), connector, "default");
        Assertions.assertEquals(false, isExists);
    }

    @Test
    public void checkGroupExistsTest(){
        Boolean isExists = complianceService.complianceGroupExists(SecuredUUID.fromString(complianceGroup.getUuid().toString()), connector, "default");
        Assertions.assertEquals(true, isExists);
    }

    @Test
    public void checkGroupNotExistsTest(){
        Boolean isExists = complianceService.complianceGroupExists(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), connector, "default");
        Assertions.assertEquals(false, isExists);
    }
}
