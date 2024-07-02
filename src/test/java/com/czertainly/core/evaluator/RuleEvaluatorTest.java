package com.czertainly.core.evaluator;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.RuleException;
import com.czertainly.api.model.client.attribute.ResponseAttributeDto;
import com.czertainly.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.czertainly.api.model.client.attribute.custom.CustomAttributeDefinitionDetailDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.MetadataAttribute;
import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.common.attribute.v2.properties.MetadataAttributeProperties;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.workflows.ExecutionType;
import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchableFields;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.entity.workflows.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.service.AttributeService;
import com.czertainly.core.service.ResourceObjectAssociationService;
import com.czertainly.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

public class RuleEvaluatorTest extends BaseSpringBootTest {

    @DynamicPropertySource
    static void authServiceProperties(DynamicPropertyRegistry registry) {
        registry.add("auth-service.base-url", () -> "http://localhost:10001");
    }

    @Autowired
    private RuleEvaluator<CryptographicKeyItem> cryptographicKeyRuleEvaluator;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private RuleEvaluator<DiscoveryHistory> discoveryHistoryRuleEvaluator;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private AttributeService attributeService;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private CertificateRuleEvaluator certificateRuleEvaluator;

    @Autowired
    private ResourceObjectAssociationService associationService;

    private Certificate certificate;

    private ConditionItem condition;

    private Trigger trigger;
    private Action action;
    private Execution execution;
    private ExecutionItem executionItem;

    private WireMockServer mockServer;

    @BeforeEach
    public void setUp() {
        certificate = new Certificate();
        certificateRepository.save(certificate);

        condition = new ConditionItem();

        trigger = new Trigger();
        trigger.setResource(Resource.CERTIFICATE);

        executionItem = new ExecutionItem();

        execution = new Execution();
        execution.setResource(Resource.CERTIFICATE);
        execution.setType(ExecutionType.SET_FIELD);
        execution.setItems(List.of(executionItem));

        action = new Action();
        action.setResource(Resource.CERTIFICATE);
        action.setExecutions(List.of(execution));
        trigger.setActions(List.of(action));
    }

    @Test
    public void testCertificateEvaluatorOnProperties() throws RuleException {

        certificate.setCommonName("Common Name");
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        condition.setFieldIdentifier(SearchableFields.COMMON_NAME.toString());
        condition.setOperator(FilterConditionOperator.NOT_EMPTY);
        Assertions.assertTrue(certificateRuleEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setValue("Common Name");
        condition.setOperator(FilterConditionOperator.EQUALS);
        Assertions.assertTrue(certificateRuleEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.NOT_EQUALS);
        certificate.setCommonName("Common NameE");
        Assertions.assertTrue(certificateRuleEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.CONTAINS);
        condition.setValue("Name");
        Assertions.assertTrue(certificateRuleEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.NOT_CONTAINS);
        condition.setValue("abc");
        Assertions.assertTrue(certificateRuleEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.STARTS_WITH);
        condition.setValue("Comm");
        Assertions.assertTrue(certificateRuleEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.ENDS_WITH);
        condition.setValue("eE");
        Assertions.assertTrue(certificateRuleEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        certificate.setCommonName(null);
        condition.setOperator(FilterConditionOperator.EMPTY);
        Assertions.assertTrue(certificateRuleEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        Group group = new Group();
        group.setName("group");
        group = groupRepository.save(group);

        certificate.setGroups(new HashSet<>(List.of(group)));
        certificate = certificateRepository.save(certificate);

        condition.setOperator(FilterConditionOperator.EQUALS);
        condition.setFieldIdentifier(SearchableFields.GROUP_NAME.toString());
        condition.setValue(group.getName());
        Assertions.assertTrue(certificateRuleEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        certificate.setTrustedCa(true);
        condition.setFieldIdentifier(SearchableFields.TRUSTED_CA.toString());
        condition.setOperator(FilterConditionOperator.EQUALS);
        condition.setValue(true);
        Assertions.assertTrue(certificateRuleEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
    }

    @Test
    public void testExceptions() throws RuleException, ParseException {
        Rule rule = new Rule();
        rule.setResource(Resource.CRYPTOGRAPHIC_KEY);
        TriggerHistory triggerHistory = new TriggerHistory();
        Assertions.assertFalse(certificateRuleEvaluator.evaluateRules(List.of(rule), certificate, triggerHistory));

        condition.setFieldIdentifier("invalid");
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        Assertions.assertThrows(RuleException.class, () -> certificateRuleEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        condition.setFieldIdentifier(SearchableFields.COMMON_NAME.toString());
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        condition.setOperator(FilterConditionOperator.GREATER);
        Assertions.assertThrows(RuleException.class, () -> certificateRuleEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        condition.setValue(123);
        condition.setOperator(FilterConditionOperator.CONTAINS);
        Assertions.assertThrows(RuleException.class, () -> certificateRuleEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        condition.setFieldIdentifier("expiryInDays");
        condition.setOperator(FilterConditionOperator.GREATER);
        condition.setValue(1);
        certificate.setNotAfter(new SimpleDateFormat(("dd.MM.yyyy")).parse("01.01.5000"));
        Assertions.assertThrows(RuleException.class, () -> certificateRuleEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
    }


    @Test
    public void testEvaluatorDate() throws RuleException, ParseException {
        certificate.setNotBefore(new SimpleDateFormat(("yyyy-MM-dd HH:mm:ss")).parse("2019-12-01 22:10:15"));
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        condition.setFieldIdentifier(SearchableFields.NOT_BEFORE.toString());
        condition.setValue("2010-12-12");
        condition.setOperator(FilterConditionOperator.GREATER);
        Assertions.assertTrue(certificateRuleEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        DiscoveryHistory discovery = new DiscoveryHistory();
        discovery.setStartTime(new SimpleDateFormat(("yyyy-MM-dd HH:mm:ss")).parse("2019-12-01 22:10:15"));
        condition.setFieldIdentifier(SearchableFields.START_TIME.toString());
        condition.setValue("2019-12-01T22:10:00.274+00:00");
        Assertions.assertTrue(discoveryHistoryRuleEvaluator.evaluateConditionItem(condition, discovery, Resource.DISCOVERY));

    }


    @Test
    public void testsCryptographicKeyRuleEvaluator() throws RuleException {
        CryptographicKeyItem cryptographicKey = new CryptographicKeyItem();
        cryptographicKey.setName("Key");
        ConditionItem condition = new ConditionItem();
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        condition.setFieldIdentifier(SearchableFields.NAME.toString());
        condition.setOperator(FilterConditionOperator.NOT_EMPTY);
        Assertions.assertTrue(cryptographicKeyRuleEvaluator.evaluateConditionItem(condition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        cryptographicKey.setLength(256);
        condition.setFieldIdentifier(SearchableFields.CKI_LENGTH.toString());
        condition.setOperator(FilterConditionOperator.GREATER);
        condition.setValue(255);
        Assertions.assertTrue(cryptographicKeyRuleEvaluator.evaluateConditionItem(condition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        condition.setValue(255.4);
        Assertions.assertTrue(cryptographicKeyRuleEvaluator.evaluateConditionItem(condition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));


    }

    @Test
    public void testCertificateRuleEvaluatorCustomAttributes() throws AlreadyExistException, NotFoundException, RuleException, AttributeException {
        Certificate certificate = new Certificate();
        certificateRepository.save(certificate);

        CustomAttributeCreateRequestDto customAttributeRequest = new CustomAttributeCreateRequestDto();
        customAttributeRequest.setName("custom");
        customAttributeRequest.setLabel("custom");
        customAttributeRequest.setResources(List.of(Resource.CERTIFICATE));
        customAttributeRequest.setContentType(AttributeContentType.STRING);

        CustomAttributeDefinitionDetailDto customAttribute = attributeService.createCustomAttribute(customAttributeRequest);
        attributeEngine.updateObjectCustomAttributeContent(Resource.CERTIFICATE, certificate.getUuid(), null, customAttribute.getName(), List.of(new StringAttributeContent("ref", "data1"), new StringAttributeContent("ref", "data")));

        ConditionItem condition = new ConditionItem();
        condition.setFieldSource(FilterFieldSource.CUSTOM);
        condition.setFieldIdentifier("custom");
        condition.setOperator(FilterConditionOperator.EQUALS);
        condition.setValue("data");
        Assertions.assertTrue(certificateRuleEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
    }

    @Test
    public void testCertificateRuleEvaluatorMeta() throws RuleException, AttributeException {
        Certificate certificate = new Certificate();
        certificateRepository.save(certificate);
        Connector connector = new Connector();
        connectorRepository.save(connector);
        UUID connectorUuid = connector.getUuid();
        MetadataAttribute metadataAttribute = new MetadataAttribute();
        metadataAttribute.setContentType(AttributeContentType.STRING);
        metadataAttribute.setName("meta");
        metadataAttribute.setUuid(UUID.randomUUID().toString());
        metadataAttribute.setContent(List.of(new StringAttributeContent("ref", "data")));
        metadataAttribute.setType(AttributeType.META);

        MetadataAttributeProperties props = new MetadataAttributeProperties();
        props.setLabel("Test meta");
        metadataAttribute.setProperties(props);

        attributeEngine.updateMetadataAttributes(List.of(metadataAttribute), new ObjectAttributeContentInfo(connectorUuid, Resource.CERTIFICATE, certificate.getUuid()));

        ConditionItem condition = new ConditionItem();
        condition.setFieldSource(FilterFieldSource.META);
        condition.setFieldIdentifier("meta|STRING");
        condition.setOperator(FilterConditionOperator.EQUALS);
        condition.setValue("data");
        Assertions.assertTrue(certificateRuleEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
    }

    @Disabled("Because Hibernate generating duplicates in foreign key constraint name")
    @Test
    public void testSetCertificateGroup() throws RuleException {
        executionItem.setFieldSource(FilterFieldSource.PROPERTY);
        executionItem.setFieldIdentifier(SearchableFields.GROUP_NAME.toString());
        Group group = new Group();
        group.setName("groupName");
        group = groupRepository.save(group);

        Group group2 = new Group();
        group2.setName("groupName2");
        group2 = groupRepository.save(group2);
        executionItem.setData(List.of(group.getUuid().toString(), group2.getUuid().toString()));
        certificateRuleEvaluator.performActions(trigger, certificate, new TriggerHistory());

        List<UUID> groupUuids = associationService.getGroupUuids(Resource.CERTIFICATE, certificate.getUuid());
        Assertions.assertEquals(2, groupUuids.size());
        Assertions.assertTrue(groupUuids.contains(group.getUuid()));
        Assertions.assertTrue(groupUuids.contains(group2.getUuid()));
    }

    @Test
    public void testSetCertificateOwner() throws RuleException {
        executionItem.setFieldSource(FilterFieldSource.PROPERTY);
        executionItem.setFieldIdentifier(SearchableFields.OWNER.toString());
        executionItem.setData(UUID.randomUUID());

        mockServer = new WireMockServer(10001);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/users/[^/]+")).willReturn(
                WireMock.okJson("{ \"username\": \"ownerName\"}")
        ));

        certificateRuleEvaluator.performActions(trigger, certificate, new TriggerHistory());

        NameAndUuidDto owner = associationService.getOwner(Resource.CERTIFICATE, certificate.getUuid());
        Assertions.assertNotNull(owner);
        Assertions.assertEquals("ownerName", owner.getName());
    }

    @Test
    public void testSetRaProfile() throws RuleException {
        mockServer = new WireMockServer(0);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/identify"))
                .willReturn(WireMock.okJson("{\"meta\":[{\"uuid\":\"b42ab690-60fd-11ed-9b6a-0242ac120002\",\"name\":\"ejbcaUsername\",\"description\":\"EJBCA Username\",\"content\":[{\"reference\":\"ShO0lp7qbnE=\",\"data\":\"ShO0lp7qbnE=\"}],\"type\":\"meta\",\"contentType\":\"string\",\"properties\":{\"label\":\"EJBCA Username\",\"visible\":true,\"group\":null,\"global\":false}}]}")));

        Connector connector = new Connector();
        connector.setName("authorityInstanceConnector");
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setStatus(ConnectorStatus.CONNECTED);
        connectorRepository.save(connector);

        AuthorityInstanceReference authorityInstanceReference = new AuthorityInstanceReference();
        authorityInstanceReference.setAuthorityInstanceUuid("1l");
        authorityInstanceReference.setConnector(connector);
        authorityInstanceReferenceRepository.save(authorityInstanceReference);

        RaProfile raProfile = new RaProfile();
        raProfile.setName("Test RA profile");
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        raProfile = raProfileRepository.save(raProfile);

        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent("content");
        certificateContentRepository.save(certificateContent);
        certificate.setCertificateContent(certificateContent);

        executionItem.setFieldSource(FilterFieldSource.PROPERTY);
        executionItem.setFieldIdentifier(SearchableFields.RA_PROFILE_NAME.toString());
        executionItem.setData(raProfile.getUuid());
        certificateRuleEvaluator.performActions(trigger, certificate, new TriggerHistory());
        Assertions.assertEquals(raProfile.getName(), certificate.getRaProfile().getName());
    }

    @Test
    public void testSetCustomAttribute() throws AlreadyExistException, AttributeException, RuleException {
        CustomAttributeCreateRequestDto createRequestDto = new CustomAttributeCreateRequestDto();
        createRequestDto.setName("custom");
        createRequestDto.setContentType(AttributeContentType.STRING);
        createRequestDto.setLabel("custom");
        createRequestDto.setResources(List.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY));
        attributeService.createCustomAttribute(createRequestDto);
        LinkedHashMap<String, String> linkedHashSet = new LinkedHashMap<>();
        linkedHashSet.put("data", "data");
        linkedHashSet.put("reference", "ref");
        executionItem.setFieldSource(FilterFieldSource.CUSTOM);
        executionItem.setFieldIdentifier("custom|STRING");
        executionItem.setData(List.of(linkedHashSet));
        certificateRuleEvaluator.performActions(trigger, certificate, new TriggerHistory());
        List<ResponseAttributeDto> responseAttributeDtos = attributeEngine.getObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid());
        Assertions.assertEquals(1, responseAttributeDtos.get(0).getContent().size());
    }

}
