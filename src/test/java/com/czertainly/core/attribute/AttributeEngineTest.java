package com.czertainly.core.attribute;

import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.client.attribute.ResponseAttributeDto;
import com.czertainly.api.model.client.metadata.MetadataResponseDto;
import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.CustomAttribute;
import com.czertainly.api.model.common.attribute.v2.MetadataAttribute;
import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.DateAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.IntegerAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.common.attribute.v2.properties.CustomAttributeProperties;
import com.czertainly.api.model.common.attribute.v2.properties.MetadataAttributeProperties;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateDetailDto;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class AttributeEngineTest extends BaseSpringBootTest {

    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private CertificateService certificateService;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    private Connector connectorAuthority;
    private Connector connectorDiscovery;
    private Certificate certificate;
    private UUID authorityDiscoveryUuid;
    private UUID networkDiscoveryUuid;

    CustomAttribute departmentCustomAttribute;
    CustomAttribute expirationDateCustomAttribute;
    private MetadataAttribute networkDiscoveryMeta;
    private MetadataAttribute authorityDiscoveryMeta;
    private MetadataAttribute authorityIssueMeta;

    @BeforeEach
    public void setUp() throws GeneralSecurityException, IOException, AttributeException, NotFoundException {
        connectorAuthority = new Connector();
        connectorAuthority.setName("EJBCAAuthorityConnector");
        connectorAuthority.setUrl("http://localhost:8080");
        connectorAuthority.setStatus(ConnectorStatus.CONNECTED);
        connectorAuthority = connectorRepository.save(connectorAuthority);

        connectorDiscovery = new Connector();
        connectorDiscovery.setName("NetworkDiscoveryConnector");
        connectorDiscovery.setUrl("http://localhost:8081");
        connectorDiscovery.setStatus(ConnectorStatus.CONNECTED);
        connectorDiscovery = connectorRepository.save(connectorDiscovery);

        AuthorityInstanceReference authorityInstance = new AuthorityInstanceReference();
        authorityInstance.setName("testAuthorityInstance1");
        authorityInstance.setConnector(connectorAuthority);
        authorityInstance.setConnectorUuid(connectorAuthority.getUuid());
        authorityInstance.setKind("sample");
        authorityInstance.setAuthorityInstanceUuid("1l");
        authorityInstance = authorityInstanceReferenceRepository.save(authorityInstance);

        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent("123456");
        certificateContent = certificateContentRepository.save(certificateContent);

        RaProfile raProfile = new RaProfile();
        raProfile.setName("Test RA profile");
        raProfile.setAuthorityInstanceReference(authorityInstance);
        raProfile = raProfileRepository.save(raProfile);

        certificate = new Certificate();
        certificate.setSubjectDn("testCertificate");
        certificate.setIssuerDn("testCercertificatetificate");
        certificate.setSerialNumber("123456789");
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setCertificateContent(certificateContent);
        certificate.setCertificateContentId(certificateContent.getId());
        certificate.setRaProfile(raProfile);
        certificate = certificateRepository.save(certificate);

        networkDiscoveryUuid = UUID.randomUUID();
        authorityDiscoveryUuid = UUID.randomUUID();

        loadMetadata();
        loadCustomAttributesData();
    }

    @Test
    public void testMetaContents() {
        var mappedMetadata = attributeEngine.getMappedMetadataContent(new ObjectAttributeContentInfo(Resource.CERTIFICATE, certificate.getUuid()));
        Assertions.assertEquals(3, mappedMetadata.size());
    }

    @Test
    public void testMetadataContentReplacement() throws AttributeException {
        networkDiscoveryMeta.setContent(List.of(new StringAttributeContent("localhost:1443"), new StringAttributeContent("localhost:2443"), new StringAttributeContent("localhost:3443")));
        attributeEngine.updateMetadataAttribute(networkDiscoveryMeta, new ObjectAttributeContentInfo(connectorDiscovery.getUuid(), Resource.CERTIFICATE, certificate.getUuid(), Resource.DISCOVERY, networkDiscoveryUuid));
        var mappedMetadata = attributeEngine.getMappedMetadataContent(new ObjectAttributeContentInfo(Resource.CERTIFICATE, certificate.getUuid()));
        Optional<MetadataResponseDto> metadataResponseDto = mappedMetadata.stream().filter(m -> m.getConnectorUuid().equals(connectorDiscovery.getUuid().toString())).findFirst();
        Assertions.assertTrue(metadataResponseDto.isPresent());
        Assertions.assertEquals(4, metadataResponseDto.get().getItems().get(0).getContent().size());

        networkDiscoveryMeta.getProperties().setOverwrite(true);
        networkDiscoveryMeta.setContent(List.of(new StringAttributeContent("TEST", "TEST")));
        attributeEngine.updateMetadataAttribute(networkDiscoveryMeta, new ObjectAttributeContentInfo(connectorDiscovery.getUuid(), Resource.CERTIFICATE, certificate.getUuid(), Resource.DISCOVERY, networkDiscoveryUuid));
        mappedMetadata = attributeEngine.getMappedMetadataContent(new ObjectAttributeContentInfo(Resource.CERTIFICATE, certificate.getUuid()));
        metadataResponseDto = mappedMetadata.stream().filter(m -> m.getConnectorUuid().equals(connectorDiscovery.getUuid().toString())).findFirst();
        Assertions.assertTrue(metadataResponseDto.isPresent());
        Assertions.assertEquals(3, mappedMetadata.size());
        Assertions.assertEquals(1, metadataResponseDto.get().getItems().get(0).getContent().size());
        Assertions.assertEquals("TEST", metadataResponseDto.get().getItems().get(0).getContent().get(0).getReference());
    }

    @Test
    public void testAttributeContentValidation() throws NotFoundException, AttributeException {
        RequestAttributeDto departmentAttributeDto = new RequestAttributeDto();
        departmentAttributeDto.setUuid(departmentCustomAttribute.getUuid());
        departmentAttributeDto.setName(departmentCustomAttribute.getName());
        departmentAttributeDto.setContent(List.of(new StringAttributeContent("Sales")));

        RequestAttributeDto expirationDateAttributeDto = new RequestAttributeDto();
        expirationDateAttributeDto.setUuid(expirationDateCustomAttribute.getUuid());
        expirationDateAttributeDto.setName(expirationDateCustomAttribute.getName());
        expirationDateAttributeDto.setContent(List.of(new DateAttributeContent(LocalDate.now())));

        Assertions.assertThrows(ValidationException.class, () -> attributeEngine.validateCustomAttributesContent(Resource.CONNECTOR, List.of(departmentAttributeDto)), "Custom attribute content should not be updated to resource not assigned");
        Assertions.assertThrows(ValidationException.class, () -> attributeEngine.validateCustomAttributesContent(Resource.CERTIFICATE, List.of(departmentAttributeDto, expirationDateAttributeDto)), "Read-only attribute content should not be able to be changed");

        expirationDateAttributeDto.setContent(List.of(new IntegerAttributeContent(100)));
        Assertions.assertThrows(ValidationException.class, () -> attributeEngine.validateCustomAttributesContent(Resource.CERTIFICATE, List.of(departmentAttributeDto, expirationDateAttributeDto)), "Mismatch between content types");

        expirationDateAttributeDto.setContent(List.of(new DateAttributeContent(LocalDate.EPOCH)));
        Assertions.assertThrows(ValidationException.class, () -> attributeEngine.validateCustomAttributesContent(Resource.CERTIFICATE, List.of(expirationDateAttributeDto)), "Missing content for required custom attribute");

        List<ResponseAttributeDto> responseAttributes = attributeEngine.updateObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid(), List.of(departmentAttributeDto, expirationDateAttributeDto));
        List<ResponseAttributeDto> responseAttributes2 = attributeEngine.getObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid());
        Assertions.assertEquals(2, responseAttributes.size());
    }

    @Test
    public void testDeleteAllObjectAttributeContent() throws NotFoundException, CertificateException, IOException {
        attributeEngine.deleteAllObjectAttributeContent(Resource.CERTIFICATE, certificate.getUuid());
        CertificateDetailDto certificateDetailDto = certificateService.getCertificate(SecuredUUID.fromUUID(certificate.getUuid()));

        Assertions.assertTrue(certificateDetailDto.getMetadata().isEmpty());
        Assertions.assertTrue(certificateDetailDto.getCustomAttributes().isEmpty());
    }

    @Test
    public void testDeleteDefinitionAttributeContent() throws NotFoundException, CertificateException, IOException {
        attributeEngine.deleteAttributeDefinition(AttributeType.CUSTOM, UUID.fromString(departmentCustomAttribute.getUuid()));
        CertificateDetailDto certificateDetailDto = certificateService.getCertificate(SecuredUUID.fromUUID(certificate.getUuid()));

        Assertions.assertEquals(3, certificateDetailDto.getMetadata().size());
        Assertions.assertTrue(certificateDetailDto.getCustomAttributes().isEmpty());

        attributeEngine.deleteAttributeDefinition(AttributeType.META, connectorDiscovery.getUuid(), UUID.fromString(networkDiscoveryMeta.getUuid()), networkDiscoveryMeta.getName());
        
        Assertions.assertFalse(certificateDetailDto.getMetadata().isEmpty());
        Assertions.assertTrue(certificateDetailDto.getCustomAttributes().isEmpty());

        certificateDetailDto = certificateService.getCertificate(SecuredUUID.fromUUID(certificate.getUuid()));
        Assertions.assertEquals(2, certificateDetailDto.getMetadata().size());
        Assertions.assertTrue(certificateDetailDto.getCustomAttributes().isEmpty());
    }

    private void loadCustomAttributesData() throws AttributeException, NotFoundException {
        departmentCustomAttribute = new CustomAttribute();
        departmentCustomAttribute.setUuid(UUID.randomUUID().toString());
        departmentCustomAttribute.setName("department");
        departmentCustomAttribute.setType(AttributeType.CUSTOM);
        departmentCustomAttribute.setContentType(AttributeContentType.STRING);

        CustomAttributeProperties customProps1 = new CustomAttributeProperties();
        customProps1.setLabel("Department");
        customProps1.setRequired(true);
        departmentCustomAttribute.setProperties(customProps1);

        expirationDateCustomAttribute = new CustomAttribute();
        expirationDateCustomAttribute.setUuid(UUID.randomUUID().toString());
        expirationDateCustomAttribute.setName("expiration_date");
        expirationDateCustomAttribute.setType(AttributeType.CUSTOM);
        expirationDateCustomAttribute.setContentType(AttributeContentType.DATE);
        expirationDateCustomAttribute.setContent(List.of(new DateAttributeContent(LocalDate.EPOCH)));

        CustomAttributeProperties customProps2 = new CustomAttributeProperties();
        customProps2.setLabel("Expiration date");
        customProps2.setReadOnly(true);
        expirationDateCustomAttribute.setProperties(customProps2);

        attributeEngine.updateCustomAttributeDefinition(departmentCustomAttribute, List.of(Resource.CERTIFICATE, Resource.AUTHORITY));
        attributeEngine.updateCustomAttributeDefinition(expirationDateCustomAttribute, List.of(Resource.CERTIFICATE));

        RequestAttributeDto departmentAttributeDto = new RequestAttributeDto();
        departmentAttributeDto.setUuid(departmentCustomAttribute.getUuid());
        departmentAttributeDto.setName(departmentCustomAttribute.getName());
        departmentAttributeDto.setContent(List.of(new StringAttributeContent("Sales")));
        attributeEngine.updateObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid(), List.of(departmentAttributeDto));
    }

    private void loadMetadata() throws AttributeException {
        networkDiscoveryMeta = new MetadataAttribute();
        networkDiscoveryMeta.setName("discoverySource");
        networkDiscoveryMeta.setUuid("000043aa-6022-11ed-9b6a-0242ac120002");
        networkDiscoveryMeta.setContentType(AttributeContentType.STRING);
        networkDiscoveryMeta.setType(AttributeType.META);
        networkDiscoveryMeta.setDescription("Source from where the certificate is discovered");
        MetadataAttributeProperties metaProps1 = new MetadataAttributeProperties();
        metaProps1.setLabel("Discovery Source");
        metaProps1.setVisible(true);
        metaProps1.setGlobal(true);
        networkDiscoveryMeta.setProperties(metaProps1);
        networkDiscoveryMeta.setContent(List.of(new StringAttributeContent("localhost:0443")));
        attributeEngine.updateMetadataAttribute(networkDiscoveryMeta, new ObjectAttributeContentInfo(connectorDiscovery.getUuid(), Resource.CERTIFICATE, certificate.getUuid(), Resource.DISCOVERY, networkDiscoveryUuid));

        authorityDiscoveryMeta = new MetadataAttribute();
        authorityDiscoveryMeta.setName("username");
        authorityDiscoveryMeta.setUuid("df2fbaa2-60fd-11ed-9b6a-0242ac120002");
        authorityDiscoveryMeta.setContentType(AttributeContentType.STRING);
        authorityDiscoveryMeta.setType(AttributeType.META);
        authorityDiscoveryMeta.setDescription("Username of certificate");
        MetadataAttributeProperties metaProps2 = new MetadataAttributeProperties();
        metaProps2.setLabel("Username");
        metaProps2.setVisible(true);
        authorityDiscoveryMeta.setProperties(metaProps2);
        authorityDiscoveryMeta.setContent(List.of(new StringAttributeContent("tst-username")));
        attributeEngine.updateMetadataAttribute(authorityDiscoveryMeta, new ObjectAttributeContentInfo(connectorAuthority.getUuid(), Resource.CERTIFICATE, certificate.getUuid(), Resource.DISCOVERY, authorityDiscoveryUuid));

        authorityIssueMeta = new MetadataAttribute();
        authorityIssueMeta.setUuid("b42ab690-60fd-11ed-9b6a-0242ac120002");
        authorityIssueMeta.setName("ejbcaUsername");
        authorityIssueMeta.setDescription("EJBCA Username");
        authorityIssueMeta.setType(AttributeType.META);
        authorityIssueMeta.setContentType(AttributeContentType.STRING);
        authorityIssueMeta.setContent(List.of(new StringAttributeContent("tst-ejbcaUsername==")));
        MetadataAttributeProperties metaProps3 = new MetadataAttributeProperties();
        metaProps3.setVisible(true);
        metaProps3.setLabel("EJBCA Username");
        authorityIssueMeta.setProperties(metaProps3);
        attributeEngine.updateMetadataAttribute(authorityIssueMeta, new ObjectAttributeContentInfo(connectorAuthority.getUuid(), Resource.CERTIFICATE, certificate.getUuid()));
    }
}
