package com.czertainly.core.service.impl;

import com.czertainly.api.clients.v2.CertificateApiClient;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.client.attribute.ResponseAttributeDto;
import com.czertainly.api.model.client.certificate.*;
import com.czertainly.api.model.client.dashboard.StatisticsDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.common.attribute.v2.MetadataAttribute;
import com.czertainly.api.model.connector.v2.CertificateIdentificationRequestDto;
import com.czertainly.api.model.connector.v2.CertificateIdentificationResponseDto;
import com.czertainly.api.model.core.audit.ObjectType;
import com.czertainly.api.model.core.audit.OperationType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.auth.UserDto;
import com.czertainly.api.model.core.certificate.*;
import com.czertainly.api.model.core.compliance.ComplianceRuleStatus;
import com.czertainly.api.model.core.compliance.ComplianceStatus;
import com.czertainly.api.model.core.enums.CertificateRequestFormat;
import com.czertainly.api.model.core.enums.Protocol;
import com.czertainly.api.model.core.location.LocationDto;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.attribute.CsrAttributes;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.AttributeOperation;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.comparator.SearchFieldDataComparator;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.enums.SearchFieldNameEnum;
import com.czertainly.core.messaging.model.NotificationRecipient;
import com.czertainly.core.messaging.producers.EventProducer;
import com.czertainly.core.messaging.producers.NotificationProducer;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.model.request.CertificateRequest;
import com.czertainly.core.security.authn.client.UserManagementApiClient;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.*;
import com.czertainly.core.service.v2.ExtendedAttributeService;
import com.czertainly.core.util.*;
import com.czertainly.core.util.converter.Sql2PredicateConverter;
import com.czertainly.core.validation.certificate.ICertificateValidator;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MarkerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

@Service
@Transactional
public class CertificateServiceImpl implements CertificateService {

    // Default page size for the certificate search API when page size is not provided
    public static final Integer DEFAULT_PAGE_SIZE = 10;
    // Maximum page size for search API operation
    public static final Integer MAX_PAGE_SIZE = 1000;
    // Default batch size to perform bulk delete operation on Certificates
    public static final Integer DELETE_BATCH_SIZE = 1000;

    private static final String UNDEFINED_CERTIFICATE_OBJECT_NAME = "undefined";
    private static final Logger logger = LoggerFactory.getLogger(CertificateServiceImpl.class);

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateRequestRepository certificateRequestRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private RaProfileService raProfileService;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private DiscoveryCertificateRepository discoveryCertificateRepository;

    @Autowired
    private ComplianceService complianceService;

    @Autowired
    private CertificateEventHistoryService certificateEventHistoryService;

    @Autowired
    private SearchService searchService;

    @Lazy
    @Autowired
    private LocationService locationService;

    @Lazy
    @Autowired
    private CryptographicKeyService cryptographicKeyService;

    @Autowired
    private PermissionEvaluator permissionEvaluator;

    @Autowired
    private EventProducer eventProducer;

    @Autowired
    private NotificationProducer notificationProducer;

    @Autowired
    private CertificateApiClient certificateApiClient;

    @Autowired
    private UserManagementApiClient userManagementApiClient;


    private AttributeEngine attributeEngine;

    private ExtendedAttributeService extendedAttributeService;

    private ResourceObjectAssociationService objectAssociationService;

    /**
     * A map that contains ICertificateValidator implementations mapped to their corresponding certificate type code
     */
    private Map<String, ICertificateValidator> certificateValidatorMap;

    private CrlService crlService;

    private CertificateProtocolAssociationRepository certificateProtocolAssociationRepository;

    @Autowired
    public void setCertificateProtocolAssociationRepository(CertificateProtocolAssociationRepository certificateProtocolAssociationRepository) {
        this.certificateProtocolAssociationRepository = certificateProtocolAssociationRepository;
    }

    @Autowired
    public void setCrlService(CrlService crlService) {
        this.crlService = crlService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setExtendedAttributeService(ExtendedAttributeService extendedAttributeService) {
        this.extendedAttributeService = extendedAttributeService;
    }

    @Autowired
    public void setObjectAssociationService(ResourceObjectAssociationService objectAssociationService) {
        this.objectAssociationService = objectAssociationService;
    }

    @Autowired
    public void setCertificateValidatorMap(Map<String, ICertificateValidator> certificateValidatorMap) {
        this.certificateValidatorMap = certificateValidatorMap;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CERTIFICATE, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.LIST, parentResource = Resource.RA_PROFILE, parentAction = ResourceAction.MEMBERS)
    public CertificateResponseDto listCertificates(SecurityFilter filter, SearchRequestDto request) throws ValidationException {
        setupSecurityFilter(filter);
        RequestValidatorHelper.revalidateSearchRequestDto(request);
        final Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());

        // filter certificates based on attribute filters
        final List<UUID> objectUUIDs = attributeEngine.getResourceObjectUuidsByFilters(Resource.CERTIFICATE, filter, request.getFilters());

        final BiFunction<Root<Certificate>, CriteriaBuilder, Predicate> additionalWhereClause = (root, cb) -> Sql2PredicateConverter.mapSearchFilter2Predicates(request.getFilters(), cb, root, objectUUIDs);
        final List<CertificateDto> listedKeyDTOs = certificateRepository.findUsingSecurityFilter(filter, List.of("groups", "owner", "raProfile", "key"), additionalWhereClause, p, (root, cb) -> cb.desc(root.get("created"))).stream().map(Certificate::mapToListDto).toList();
        final Long maxItems = certificateRepository.countUsingSecurityFilter(filter, additionalWhereClause);

        final CertificateResponseDto responseDto = new CertificateResponseDto();
        responseDto.setCertificates(listedKeyDTOs);
        responseDto.setItemsPerPage(request.getItemsPerPage());
        responseDto.setPageNumber(request.getPageNumber());
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / request.getItemsPerPage()));
        return responseDto;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CERTIFICATE, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    public CertificateDetailDto getCertificate(SecuredUUID uuid) throws NotFoundException, CertificateException, IOException {
        Certificate certificate = getCertificateEntityWithAssociations(uuid);
        CertificateDetailDto dto = certificate.mapToDto();
        if (certificate.getComplianceResult() != null) {
            dto.setNonCompliantRules(frameComplianceResult(certificate.getComplianceResult()));
        }
        if (dto.getCertificateRequest() != null) {
            dto.getCertificateRequest().setAttributes(attributeEngine.getObjectDataAttributesContent(null, null, Resource.CERTIFICATE_REQUEST, certificate.getCertificateRequest().getUuid()));
            dto.getCertificateRequest().setSignatureAttributes(attributeEngine.getObjectDataAttributesContent(null, AttributeOperation.CERTIFICATE_REQUEST_SIGN, Resource.CERTIFICATE_REQUEST, certificate.getCertificateRequest().getUuid()));
        }
        if (certificate.getRaProfile() != null) {
            dto.setIssueAttributes(attributeEngine.getObjectDataAttributesContent(certificate.getRaProfile().getAuthorityInstanceReference().getConnectorUuid(), AttributeOperation.CERTIFICATE_ISSUE, Resource.CERTIFICATE, certificate.getUuid()));
            dto.setRevokeAttributes(attributeEngine.getObjectDataAttributesContent(certificate.getRaProfile().getAuthorityInstanceReference().getConnectorUuid(), AttributeOperation.CERTIFICATE_REVOKE, Resource.CERTIFICATE, certificate.getUuid()));
        }
        // TODO: originally showing only metadata from discovery resource, should it be like that?
        dto.setMetadata(attributeEngine.getMappedMetadataContent(new ObjectAttributeContentInfo(Resource.CERTIFICATE, certificate.getUuid())));
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid()));
        dto.setRelatedCertificates(certificateRepository.findBySourceCertificateUuid(certificate.getUuid()).stream().map(Certificate::mapToListDto).toList());
        return dto;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CERTIFICATE, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    public Certificate getCertificateEntity(SecuredUUID uuid) throws NotFoundException {
        Certificate entity = certificateRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(Certificate.class, uuid));
        raProfileService.evaluateCertificateRaProfilePermissions(uuid, SecuredParentUUID.fromUUID(entity.getRaProfileUuid()));

        return entity;
    }

    private Certificate getCertificateEntityWithAssociations(SecuredUUID uuid) throws NotFoundException {
        Certificate entity = certificateRepository.findWithAssociationsByUuid(uuid.getValue()).orElseThrow(() -> new NotFoundException(Certificate.class, uuid));
        raProfileService.evaluateCertificateRaProfilePermissions(uuid, SecuredParentUUID.fromUUID(entity.getRaProfileUuid()));

        return entity;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CERTIFICATE, operation = OperationType.REQUEST)
    // This method does not need security as it is not exposed by the controllers. This method also does not use uuid
    public Certificate getCertificateEntityByContent(String content) {
        CertificateContent certificateContent = certificateContentRepository.findByContent(content);
        return certificateRepository.findByCertificateContent(certificateContent);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CERTIFICATE, operation = OperationType.REQUEST)
    //This method does not need security as it is used only by the internal services for certificate related operations
    public Certificate getCertificateEntityByFingerprint(String fingerprint) throws NotFoundException {
        return certificateRepository.findByFingerprint(fingerprint).orElseThrow(() -> new NotFoundException(Certificate.class, fingerprint));
    }

    @Override
    public Certificate getCertificateEntityByIssuerDnNormalizedAndSerialNumber(String issuerDn, String serialNumber) throws NotFoundException {
        return certificateRepository.findByIssuerDnNormalizedAndSerialNumber(issuerDn, serialNumber).orElseThrow(() -> new NotFoundException(Certificate.class, issuerDn + " " + serialNumber));
    }

    @Override
    public Boolean checkCertificateExistsByFingerprint(String fingerprint) {
        try {
            return certificateRepository.findByFingerprint(fingerprint).isPresent();
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CERTIFICATE, operation = OperationType.DELETE)
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DELETE)
    public void deleteCertificate(SecuredUUID uuid) throws NotFoundException {
        Certificate certificate = getCertificateEntity(uuid);

        if (certificate.getUserUuid() != null) {
            eventProducer.produceCertificateEventMessage(uuid.getValue(), CertificateEvent.DELETE.getCode(), CertificateEventStatus.FAILED.toString(), "Certificate is used by an User", null);
            throw new ValidationException(String.format("Could not delete certificate %s with UUID %s: Certificate is used by some user.", certificate.getCommonName(), certificate.getUuid().toString()));
        }

        // remove certificate from Locations
        try {
            locationService.removeCertificateFromLocations(uuid);
        } catch (ConnectorException e) {
            logger.error("Failed to remove Certificate {} from Locations.", uuid);
        }

        // If there is some CRL for this certificate, set its CA certificate UUID to null
        for (Crl crl : crlService.findCrlsForCaCertificate(uuid.getValue())) crl.setCaCertificateUuid(null);

        CertificateContent content = (certificate.getCertificateContent() != null && discoveryCertificateRepository.findByCertificateContent(certificate.getCertificateContent()).isEmpty()) ? certificateContentRepository.findById(certificate.getCertificateContent().getId()).orElse(null) : null;
        certificateRepository.delete(certificate);
        if (content != null) {
            certificateContentRepository.delete(content);
            certificate.setCertificateContent(null);
        }

        objectAssociationService.removeObjectAssociations(Resource.CERTIFICATE, uuid.getValue());
        attributeEngine.deleteAllObjectAttributeContent(Resource.CERTIFICATE, uuid.getValue());
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CERTIFICATE, operation = OperationType.CHANGE)
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.UPDATE)
    public void updateCertificateObjects(SecuredUUID uuid, CertificateUpdateObjectsDto request) throws NotFoundException, CertificateOperationException, AttributeException {
        logger.debug("Updating certificate objects: RA {} groups {} owner {}", request.getRaProfileUuid(), request.getGroupUuids(), request.getOwnerUuid());
        if (request.getRaProfileUuid() != null) {
            switchRaProfile(uuid, request.getRaProfileUuid().isEmpty() ? null : SecuredUUID.fromString(request.getRaProfileUuid()));
        }
        if (request.getGroupUuids() != null) {
            this.updateCertificateGroups(uuid, request.getGroupUuids().stream().map(UUID::fromString).collect(Collectors.toSet()));
        }
        if (request.getOwnerUuid() != null) {
            updateOwner(uuid, request.getOwnerUuid().isEmpty() ? null : request.getOwnerUuid());
        }
        if (request.getTrustedCa() != null) {
            updateTrustedCaMark(uuid, request.getTrustedCa());
        }
    }

    private void updateTrustedCaMark(SecuredUUID uuid, Boolean trustedCa) throws NotFoundException {
        Certificate certificate = getCertificateEntity(uuid);
        if (certificate.getTrustedCa() == null) {
            throw new ValidationException("Trying to mark certificate as trusted CA when certificate is not CA.");
        }
        certificate.setTrustedCa(trustedCa);
    }

    @Async
    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CERTIFICATE, operation = OperationType.CHANGE)
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.UPDATE, parentResource = Resource.RA_PROFILE, parentAction = ResourceAction.DETAIL)
    public void bulkUpdateCertificateObjects(SecurityFilter filter, MultipleCertificateObjectUpdateDto request) throws NotFoundException {
        logger.info("Bulk updating certificate objects: RA {} groups {} owner {}", request.getRaProfileUuid(), request.getGroupUuids(), request.getOwnerUuid());
        setupSecurityFilter(filter);
        if (request.getRaProfileUuid() != null) {
            bulkUpdateRaProfile(filter, request);
        }
        if (request.getGroupUuids() != null) {
            bulkUpdateCertificateGroup(filter, request);
        }
        if (request.getOwnerUuid() != null) {
            bulkUpdateOwner(filter, request);
        }
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CERTIFICATE, operation = OperationType.DELETE)
    @Async("threadPoolTaskExecutor")
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DELETE, parentResource = Resource.RA_PROFILE, parentAction = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void bulkDeleteCertificate(SecurityFilter filter, RemoveCertificateDto request) throws NotFoundException {
        setupSecurityFilter(filter);

        UUID loggedUserUuid = null;
        if (request.getFilters() == null || request.getFilters().isEmpty() || (request.getUuids() != null && !request.getUuids().isEmpty())) {
            int deletedCount = 0;
            for (String uuid : request.getUuids()) {
                UUID certificateUuid = UUID.fromString(uuid);
                try {
                    deleteCertificate(SecuredUUID.fromUUID(certificateUuid));
                    ++deletedCount;
                } catch (Exception e) {
                    logger.error("Unable to delete the certificate {}: {}", certificateUuid, e.getMessage());
                    if (loggedUserUuid == null) {
                        loggedUserUuid = UUID.fromString(AuthHelper.getUserIdentification().getUuid());
                    }
                    notificationProducer.produceNotificationText(Resource.CERTIFICATE, certificateUuid, NotificationRecipient.buildUserNotificationRecipient(loggedUserUuid), "Unable to delete the certificate " + certificateUuid, e.getMessage());
                }
            }
            logger.debug("Bulk deleted {} of {} certificates.", deletedCount, request.getUuids().size());
        } else {
            String joins = "WHERE c.userUuid IS NULL";
            String data = searchService.createCriteriaBuilderString(filter, true);
            if (!data.isEmpty()) {
                joins = joins + " AND " + data;
            }

            String customQuery = searchService.getQueryDynamicBasedOnFilter(request.getFilters(), "Certificate", getSearchableFieldInformation(), joins, false, false, "");

            List<Certificate> certListDyn = (List<Certificate>) searchService.customQueryExecutor(customQuery);

            for (List<Certificate> certificates : partitionList(certListDyn)) {
                certificateRepository.deleteAll(certificates);
            }
            for (List<CertificateContent> certificateContents : partitionContents(certificateContentRepository.findCertificateContentNotUsed())) {
                certificateContentRepository.deleteAll(certificateContents);
            }
        }
    }

    @Deprecated
    public List<SearchFieldDataDto> getSearchableFieldInformation() {
        return getSearchableFieldsMap();
    }

    @Override
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup() {
        final List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine.getResourceSearchableFields(Resource.CERTIFICATE, false);

        List<SearchFieldDataDto> fields = List.of(
                SearchHelper.prepareSearch(SearchFieldNameEnum.COMMON_NAME),
                SearchHelper.prepareSearch(SearchFieldNameEnum.SERIAL_NUMBER_LABEL),
                SearchHelper.prepareSearch(SearchFieldNameEnum.ISSUER_SERIAL_NUMBER),
                SearchHelper.prepareSearch(SearchFieldNameEnum.RA_PROFILE, raProfileRepository.findAll().stream().map(RaProfile::getName).toList()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.GROUP, groupRepository.findAll().stream().map(Group::getName).toList()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.OWNER, userManagementApiClient.getUsers().getData().stream().map(UserDto::getUsername).toList()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.CERTIFICATE_STATE, Arrays.stream(CertificateState.values()).map(CertificateState::getCode).toList()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.CERTIFICATE_VALIDATION_STATUS, Arrays.stream(CertificateValidationStatus.values()).map(CertificateValidationStatus::getCode).toList()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.COMPLIANCE_STATUS, Arrays.stream(ComplianceStatus.values()).map(ComplianceStatus::getCode).toList()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.ISSUER_COMMON_NAME),
                SearchHelper.prepareSearch(SearchFieldNameEnum.FINGERPRINT),
                SearchHelper.prepareSearch(SearchFieldNameEnum.SIGNATURE_ALGORITHM, new ArrayList<>(certificateRepository.findDistinctSignatureAlgorithm())),
                SearchHelper.prepareSearch(SearchFieldNameEnum.EXPIRES),
                SearchHelper.prepareSearch(SearchFieldNameEnum.NOT_BEFORE),
                SearchHelper.prepareSearch(SearchFieldNameEnum.SUBJECT_DN),
                SearchHelper.prepareSearch(SearchFieldNameEnum.ISSUER_DN),
                SearchHelper.prepareSearch(SearchFieldNameEnum.SUBJECT_ALTERNATIVE),
                SearchHelper.prepareSearch(SearchFieldNameEnum.OCSP_VALIDATION, Arrays.stream((CertificateValidationStatus.values())).map(CertificateValidationStatus::getCode).toList()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.CRL_VALIDATION, Arrays.stream((CertificateValidationStatus.values())).map(CertificateValidationStatus::getCode).toList()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.SIGNATURE_VALIDATION, Arrays.stream((CertificateValidationStatus.values())).map(CertificateValidationStatus::getCode).toList()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.PUBLIC_KEY_ALGORITHM, new ArrayList<>(certificateRepository.findDistinctPublicKeyAlgorithm())),
                SearchHelper.prepareSearch(SearchFieldNameEnum.KEY_SIZE, new ArrayList<>(certificateRepository.findDistinctKeySize())),
                SearchHelper.prepareSearch(SearchFieldNameEnum.KEY_USAGE, serializedListOfStringToListOfObject(certificateRepository.findDistinctKeyUsage())),
                SearchHelper.prepareSearch(SearchFieldNameEnum.PRIVATE_KEY),
                SearchHelper.prepareSearch(SearchFieldNameEnum.TRUSTED_CA)
        );

        fields = new ArrayList<>(fields);
        fields.sort(new SearchFieldDataComparator());

        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));

        logger.debug("Searchable Fields by Groups: {}", searchFieldDataByGroupDtos);
        return searchFieldDataByGroupDtos;
    }

    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CERTIFICATE, operation = OperationType.CHANGE)
    // @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    // Auth is not required for this method. It is used only internally by other services to update the certificate chain
    private void updateCertificateChain(Certificate certificate) throws CertificateException {
        if (certificate.getCertificateContent() == null) {
            return;
        }

        // Check if the certificate is self-signed
        if (isSelfSigned(certificate)) {
            return;
        }
        boolean issuerInInventory = false;
        X509Certificate subCert;
        try {
            subCert = CertificateUtil.parseCertificate(certificate.getCertificateContent().getContent());
        } catch (Exception e) {
            // We do not need to handle exceptions here because if subject certificate cannot be parsed, we cannot update its certificate chain
            return;
        }
        // Try to find issuer certificate in repository
        for (Certificate issuer : certificateRepository.findBySubjectDnNormalized(certificate.getIssuerDnNormalized())) {
            X509Certificate issCert;
            try {
                issCert = CertificateUtil.parseCertificate(issuer.getCertificateContent().getContent());
            } catch (Exception e) {
                // We do not need to handle exceptions here because if certificate cannot be parsed, we ignore it as a
                // candidate for issuer and continue with next candidate
                continue;
            }
            // Verify signature for a certificate with matching Subject DN, if it matches, the issuer is found
            if (verifySignature(subCert, issCert)) {
                certificate.setIssuerSerialNumber(issuer.getSerialNumber());
                certificate.setIssuerCertificateUuid(issuer.getUuid());
                certificateRepository.save(certificate);
                issuerInInventory = true;
                // If the issuer of certificate doesn't have its issuer, try to update issuer for this certificate as well
                if (issuer.getIssuerCertificateUuid() == null) {
                    updateCertificateChain(issuer);
                }
                break;
            }
        }
        // If the issuer isn't in inventory, try to download it from AIA extension of the certificate
        if (!issuerInInventory) {
            int downloadedCertificates = 0;
            List<String> aiaChain = downloadChainFromAia(certificate);
            Certificate previousCertificate = certificate;
            for (String chainCertificate : aiaChain) {
                try {
                    Certificate nextInChain;
                    // If the certificate from isn't in repository, create it, otherwise only update issuer uuid and serial number
                    try {
                        nextInChain = checkCreateCertificate(chainCertificate);
//                        eventProducer.produceCertificateEventMessage(nextInChain.getUuid(), CertificateEvent.UPLOAD.getCode(), CertificateEventStatus.SUCCESS.toString(), "Downloaded from AIA extension.", null);
                    } catch (AlreadyExistException e) {
                        X509Certificate x509Cert = CertificateUtil.parseCertificate(chainCertificate);
                        String fingerprint = CertificateUtil.getThumbprint(x509Cert);
                        nextInChain = certificateRepository.findByFingerprint(fingerprint).orElse(null);
                    }
                    assert nextInChain != null;
                    previousCertificate.setIssuerCertificateUuid(nextInChain.getUuid());
                    previousCertificate.setIssuerSerialNumber(nextInChain.getSerialNumber());
                    previousCertificate = nextInChain;
                    ++downloadedCertificates;
                } catch (NoSuchAlgorithmException | CertificateException e) {
                    // Certificate downloaded from AIA cannot be parsed and inserted into inventory, so ignore the rest of chain
                    break;
                }
            }

            // if downloaded some certificate, try to update chain of last one, if it is really last self-signed
            if (downloadedCertificates > 0) {
                updateCertificateChain(previousCertificate);
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    public CertificateChainResponseDto getCertificateChain(SecuredUUID uuid, boolean withEndCertificate) throws NotFoundException {
        Certificate certificate = getCertificateEntity(uuid);
        return getCertificateChainInternal(certificate, withEndCertificate);
    }

    private CertificateChainResponseDto getCertificateChainInternal(Certificate certificate, boolean withEndCertificate) {
        List<CertificateDetailDto> certificateChain = new ArrayList<>();
        CertificateChainResponseDto certificateChainResponseDto = new CertificateChainResponseDto();
        certificateChainResponseDto.setCertificates(certificateChain);

        if (certificate.getCertificateContent() == null) {
            return certificateChainResponseDto;
        }

        if (withEndCertificate) {
            certificateChain.add(certificate.mapToDto());
        }

        Certificate lastCertificate = constructCertificateChain(certificate, certificateChain);
        try {
            // if last certificate is self-signed, we presume it is root certificate and we are finished
            if (isSelfSigned(lastCertificate)) {
                certificateChainResponseDto.setCompleteChain(true);
            } else {
                // update chain and determine if its issuer was found
                updateCertificateChain(lastCertificate);
                if (lastCertificate.getIssuerCertificateUuid() != null) {
                    // construct newly found certificates from chain and do the self-signed check again
                    lastCertificate = constructCertificateChain(lastCertificate, certificateChain);
                    certificateChainResponseDto.setCompleteChain(isSelfSigned(lastCertificate));
                }
            }
        } catch (CertificateException e) {
            // If it cannot be verified whether certificate is self-signed or updateCertificateChain fails,
            // we end certificate chain building and return partial result
        }

        return certificateChainResponseDto;
    }

    private Certificate constructCertificateChain(Certificate certificate, List<CertificateDetailDto> certificateChain) {
        Certificate lastCertificate = certificate;
        // Go up the certificate chain until certificate without issuer is found
        while (lastCertificate.getIssuerCertificateUuid() != null) {
            Certificate issuerCertificate = certificateRepository.findByUuid(lastCertificate.getIssuerCertificateUuid()).orElse(null);
            if (issuerCertificate != null) {
                certificateChain.add(issuerCertificate.mapToDto());
                lastCertificate = issuerCertificate;
            } else {
                // If issuer certificate does not exist in the inventory, set it and issuer serial number to null
                // and return incomplete chain
                lastCertificate.setIssuerCertificateUuid(null);
                lastCertificate.setIssuerSerialNumber(null);
                certificateRepository.save(lastCertificate);
            }
        }

        return lastCertificate;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    public CertificateChainDownloadResponseDto downloadCertificateChain(SecuredUUID uuid, CertificateFormat certificateFormat, boolean withEndCertificate, CertificateFormatEncoding encoding) throws NotFoundException, CertificateException {
        List<CertificateContentDto> certificateContent = getCertificateContent(List.of(uuid.toString()));
        if (certificateContent.isEmpty()) {
            throw new ValidationException("Cannot download certificate chain, the end certificate is not issued.");
        }
        CertificateChainResponseDto certificateChainResponseDto = getCertificateChain(uuid, withEndCertificate);
        List<CertificateDetailDto> certificateChain = certificateChainResponseDto.getCertificates();
        CertificateChainDownloadResponseDto certificateChainDownloadResponseDto = new CertificateChainDownloadResponseDto();
        certificateChainDownloadResponseDto.setCompleteChain(certificateChainResponseDto.isCompleteChain());
        certificateChainDownloadResponseDto.setFormat(certificateFormat);
        certificateChainDownloadResponseDto.setEncoding(encoding);
        certificateChainDownloadResponseDto.setContent(getDownloadedContent(certificateChain, certificateFormat, encoding, true));
        return certificateChainDownloadResponseDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    public CertificateDownloadResponseDto downloadCertificate(String uuid, CertificateFormat certificateFormat, CertificateFormatEncoding encoding) throws CertificateException, NotFoundException, IOException {
        CertificateDetailDto certificate = getCertificate(SecuredUUID.fromString(uuid));
        if (certificate.getCertificateContent() == null) {
            throw new ValidationException("Cannot download the certificate, certificate is not issued.");
        }
        CertificateDownloadResponseDto certificateDownloadResponseDto = new CertificateDownloadResponseDto();
        certificateDownloadResponseDto.setFormat(certificateFormat);
        certificateDownloadResponseDto.setEncoding(encoding);
        certificateDownloadResponseDto.setContent(getDownloadedContent(List.of(certificate), certificateFormat, encoding, false));
        return certificateDownloadResponseDto;
    }

    private String getDownloadedContent(List<CertificateDetailDto> certificateDetailDtos, CertificateFormat certificateFormat, CertificateFormatEncoding encoding, boolean downloadingChain) throws NotFoundException, CertificateException {
        if (certificateFormat == CertificateFormat.RAW) {
            if (encoding == CertificateFormatEncoding.DER) {
                if (downloadingChain) {
                    throw new ValidationException("DER encoding of raw format is unsupported for certificate chain.");
                }
                return getCertificateEntity(SecuredUUID.fromString(certificateDetailDtos.get(0).getUuid())).getCertificateContent().getContent();
            }
            // Encoding is PEM otherwise
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(new OutputStreamWriter(byteArrayOutputStream));
            for (CertificateDto certificateDto : certificateDetailDtos) {
                Certificate certificateInstance = getCertificateEntity(SecuredUUID.fromString(certificateDto.getUuid()));
                String content = certificateInstance.getCertificateContent().getContent();
                X509Certificate x509Certificate;
                x509Certificate = CertificateUtil.getX509Certificate(content);
                try {
                    jcaPEMWriter.writeObject(x509Certificate);
                    jcaPEMWriter.flush();
                } catch (IOException e) {
                    throw new CertificateException("Could not write downloaded content as PEM format: " + e.getMessage());
                }
            }
            return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
        }
        // Formatting is PKCS7 otherwise
        else {
            List<X509Certificate> x509CertificateChain = new ArrayList<>();
            for (CertificateDto certificateDto : certificateDetailDtos) {
                Certificate certificateInstance = getCertificateEntity(SecuredUUID.fromString(certificateDto.getUuid()));
                X509Certificate x509Certificate;
                x509Certificate = CertificateUtil.getX509Certificate(certificateInstance.getCertificateContent().getContent());
                x509CertificateChain.add(x509Certificate);
            }
            try {
                CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
                generator.addCertificates(new JcaCertStore(x509CertificateChain));
                byte[] encoded = generator.generate(new CMSProcessableByteArray(new byte[0])).getEncoded();
                if (encoding == CertificateFormatEncoding.PEM) {
                    ContentInfo contentInfo = ContentInfo.getInstance(ASN1Primitive.fromByteArray(encoded));
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(new OutputStreamWriter(byteArrayOutputStream));
                    jcaPEMWriter.writeObject(contentInfo);
                    jcaPEMWriter.flush();
                    return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
                }
                // Encoding is DER otherwise
                else {
                    return Base64.getEncoder().encodeToString(encoded);
                }
            } catch (Exception e) {
                throw new CertificateException("Could not write downloaded content as PKCS#7 format: " + e.getMessage());
            }
        }
    }


    @Override
    public void validate(Certificate certificate) {
        CertificateChainResponseDto certificateChainResponse = getCertificateChainInternal(certificate, true);

        CertificateValidationStatus newStatus;
        CertificateValidationStatus oldStatus = certificate.getValidationStatus();
        ICertificateValidator certificateValidator = getCertificateValidator(certificate.getCertificateType());

        try {
            newStatus = certificateValidator.validateCertificate(certificate, certificateChainResponse.isCompleteChain());
        } catch (Exception e) {
            logger.warn("Unable to validate the certificate {}: {}", certificate, e.getMessage());
            newStatus = CertificateValidationStatus.FAILED;
            certificate.setValidationStatus(newStatus);
            certificateRepository.save(certificate);
        }

        if (!oldStatus.equals(CertificateValidationStatus.NOT_CHECKED) && !oldStatus.equals(newStatus)) {
            eventProducer.produceCertificateStatusChangeEventMessage(certificate.getUuid(), CertificateEvent.UPDATE_VALIDATION_STATUS, CertificateEventStatus.SUCCESS, oldStatus, newStatus);
            try {
                notificationProducer.produceNotificationCertificateStatusChanged(oldStatus, newStatus, certificate.mapToListDto());
            } catch (Exception e) {
                logger.error("Sending certificate {} notification for change of status {} failed. Error: {}", certificate.getUuid(), newStatus.getCode(), e.getMessage());
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    public CertificateValidationResultDto getCertificateValidationResult(SecuredUUID uuid) throws NotFoundException, CertificateException {
        Certificate certificate = getCertificateEntity(uuid);
        if (certificate.getCertificateContent() != null) {
            validate(certificate);
        }

        String validationResult = certificate.getCertificateValidationResult();
        CertificateValidationResultDto resultDto = new CertificateValidationResultDto();
        resultDto.setResultStatus(certificate.getValidationStatus());
        try {
            Map<CertificateValidationCheck, CertificateValidationCheckDto> validationChecks = MetaDefinitions.deserializeValidation(validationResult);
            resultDto.setValidationChecks(validationChecks);
        } catch (IllegalStateException e) {
            logger.error(e.getMessage());
        }
        return resultDto;
    }

    /**
     * Check if the X.509 certificate is self-signed
     *
     * @param certificate entity
     * @return true if the certificate is self-signed, false otherwise
     * @throws CertificateException if the certificate cannot be parsed
     */
    private boolean isSelfSigned(Certificate certificate) throws CertificateException {
        // we check the signature with the certificate public key
        X509Certificate x509Certificate = getX509(certificate.getCertificateContent().getContent());
        try {
            x509Certificate.verify(x509Certificate.getPublicKey());
            return true;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            logger.debug("Unable to verify if the certificate {} is self-signed: {}", certificate.getUuid(), e.getMessage());
            throw new CertificateException(e);
        } catch (SignatureException | InvalidKeyException e) {
            // if the certificate is not self-signed, the verification will fail
            return false;
        }
    }

    private boolean verifySignature(X509Certificate subjectCertificate, X509Certificate issuerCertificate) {
        try {
            subjectCertificate.verify(issuerCertificate.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private X509Certificate getX509(String certificate) throws CertificateException {
        return CertificateUtil.getX509Certificate(certificate.replace("-----BEGIN CERTIFICATE-----", "").replace("\r", "").replace("\n", "").replace("-----END CERTIFICATE-----", ""));
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.CREATE)
    public Certificate createCertificate(String certificateData, CertificateType certificateType) throws com.czertainly.api.exception.CertificateException {
        Certificate entity = new Certificate();
        String fingerprint;

        // by default, we are working with the X.509 certificate
        if (certificateType == null) {
            certificateType = CertificateType.X509;
        }
        if (!certificateType.equals(CertificateType.X509)) {
            String message = "Unsupported type of the certificate: " + certificateType;
            logger.debug(message);
            throw new com.czertainly.api.exception.CertificateException(message);
        } else {
            X509Certificate certificate;
            try {
                certificate = getX509(certificateData);
            } catch (CertificateException e) {
                String message = "Failed to get parse the certificate " + certificateData + " > " + e.getMessage();
                logger.error("message");
                throw new com.czertainly.api.exception.CertificateException(message);
            }
            try {
                fingerprint = CertificateUtil.getThumbprint(certificate.getEncoded());
                Optional<Certificate> existingCertificate = certificateRepository.findByFingerprint(fingerprint);

                if (existingCertificate.isPresent()) {
                    logger.debug("Returning existing certificate with fingerprint {}", fingerprint);
                    return existingCertificate.get();
                }
            } catch (NoSuchAlgorithmException | CertificateException e) {
                String message = "Failed to get thumbprint for certificate " + certificate.getSerialNumber() + " > " + e.getMessage();
                logger.error("message");
                throw new com.czertainly.api.exception.CertificateException(message);
            }

            CertificateUtil.prepareIssuedCertificate(entity, certificate);
            entity.setFingerprint(fingerprint);
            entity.setCertificateContent(checkAddCertificateContent(fingerprint, X509ObjectToString.toPem(certificate)));

            certificateRepository.save(entity);
            certificateEventHistoryService.addEventHistory(entity.getUuid(), CertificateEvent.UPLOAD, CertificateEventStatus.SUCCESS, "Certificate uploaded", "");

            certificateComplianceCheck(entity);
            validate(entity);

            return entity;
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.CREATE)
    public Certificate createCertificateEntity(X509Certificate certificate) {
        logger.debug("Making a new entry for a certificate");
        Certificate modal = new Certificate();
        String fingerprint = null;
        try {
            fingerprint = CertificateUtil.getThumbprint(certificate.getEncoded());
            Optional<Certificate> existingCertificate = certificateRepository.findByFingerprint(fingerprint);

            if (existingCertificate.isPresent()) {
                return existingCertificate.get();
            }
        } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
            logger.error("Unable to calculate sha 256 thumbprint");
        }

        CertificateUtil.prepareIssuedCertificate(modal, certificate);
        if (modal.getKey() == null) {
            UUID keyUuid = cryptographicKeyService.findKeyByFingerprint(modal.getPublicKeyFingerprint());
            if (keyUuid != null) modal.setKeyUuid(keyUuid);
        }
        CertificateContent certificateContent = checkAddCertificateContent(fingerprint, X509ObjectToString.toPem(certificate));
        modal.setFingerprint(fingerprint);
        modal.setCertificateContent(certificateContent);
        modal.setCertificateContentId(certificateContent.getId());

        return modal;
    }

    private CertificateContent checkAddCertificateContent(String fingerprint, String content) {
        CertificateContent certificateContent = certificateContentRepository.findByFingerprint(fingerprint);
        if (certificateContent != null) {
            return certificateContent;
        }

        certificateContent = new CertificateContent();
        certificateContent.setContent(CertificateUtil.normalizeCertificateContent(content));
        certificateContent.setFingerprint(fingerprint);

        certificateContentRepository.save(certificateContent);
        return certificateContent;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CERTIFICATE, operation = OperationType.CREATE)
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.CREATE)
    public CertificateDetailDto upload(UploadCertificateRequestDto request) throws CertificateException, NoSuchAlgorithmException, AlreadyExistException, NotFoundException, AttributeException {
        X509Certificate certificate = CertificateUtil.parseUploadedCertificateContent(request.getCertificate());
        String fingerprint = CertificateUtil.getThumbprint(certificate);
        if (certificateRepository.findByFingerprint(fingerprint).isPresent()) {
            throw new AlreadyExistException("Certificate already exists with fingerprint " + fingerprint);
        }

        attributeEngine.validateCustomAttributesContent(Resource.CERTIFICATE, request.getCustomAttributes());

        Certificate entity = createCertificateEntity(certificate);
        certificateRepository.save(entity);

        CertificateDetailDto dto = entity.mapToDto();
        dto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.CERTIFICATE, entity.getUuid(), request.getCustomAttributes()));
        certificateEventHistoryService.addEventHistory(entity.getUuid(), CertificateEvent.UPLOAD, CertificateEventStatus.SUCCESS, "Certificate uploaded", "");

        validate(entity);

        return dto;
    }

    @Override
    public Certificate checkCreateCertificate(String certificate) throws AlreadyExistException, CertificateException, NoSuchAlgorithmException {
        X509Certificate x509Cert = CertificateUtil.parseCertificate(certificate);
        String fingerprint = CertificateUtil.getThumbprint(x509Cert);
        if (certificateRepository.findByFingerprint(fingerprint).isPresent()) {
            throw new AlreadyExistException("Certificate already exists with serial number " + fingerprint);
        }
        Certificate entity = createCertificateEntity(x509Cert);
        entity = certificateRepository.save(entity);

        // set owner of certificate to logged user
        objectAssociationService.setOwnerFromProfile(Resource.CERTIFICATE, entity.getUuid());

        certificateComplianceCheck(entity);
        return entity;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.REVOKE)
    public void revokeCertificate(String serialNumber) {
        Certificate certificate = null;
        CertificateValidationStatus oldStatus = CertificateValidationStatus.NOT_CHECKED;
        try {
            certificate = certificateRepository.findBySerialNumberIgnoreCase(serialNumber).orElseThrow(() -> new NotFoundException(Certificate.class, serialNumber));
            oldStatus = certificate.getValidationStatus();
            certificate.setState(CertificateState.REVOKED);
            certificateRepository.save(certificate);
        } catch (NotFoundException e) {
            logger.warn("Unable to find the certificate with serialNumber {}", serialNumber);
        }
        if (certificate != null) {
            eventProducer.produceCertificateStatusChangeEventMessage(certificate.getUuid(), CertificateEvent.UPDATE_VALIDATION_STATUS, CertificateEventStatus.SUCCESS, oldStatus, CertificateValidationStatus.REVOKED);
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    // TODO - Enhance method to return data from location service using filter
    public List<LocationDto> listLocations(SecuredUUID certificateUuid) throws NotFoundException {
        Certificate certificateEntity = certificateRepository.findByUuid(certificateUuid).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));

        final LocationsResponseDto locationsResponseDto = locationService.listLocations(SecurityFilter.create(), new SearchRequestDto());
        final List<String> locations = locationsResponseDto.getLocations().stream().map(LocationDto::getUuid).toList();

        return certificateEntity.getLocations().stream().map(CertificateLocation::getLocation).sorted(Comparator.comparing(Location::getCreated).reversed()).map(Location::mapToDtoSimple).filter(e -> locations.contains(e.getUuid())).toList();
    }


    @Override
    // Only Internal method
    public List<Certificate> listCertificatesForRaProfile(RaProfile raProfile) {
        return certificateRepository.findByRaProfile(raProfile);
    }

    @Override
    // Only Internal method
    public List<Certificate> listCertificatesForRaProfileAndNonNullComplianceStatus(RaProfile raProfile) {
        return certificateRepository.findByRaProfileAndComplianceStatusIsNotNull(raProfile);
    }

    @Override
    @Async
    public void checkCompliance(CertificateComplianceCheckDto request) {
        for (String uuid : request.getCertificateUuids()) {
            try {
                complianceService.checkComplianceOfCertificate(getCertificateEntity(SecuredUUID.fromString(uuid)));
            } catch (ConnectorException e) {
                logger.error("Compliance check failed.", e);
            }
        }
    }

    @Override
    // Internal Use only
    public void updateCertificateEntity(Certificate certificate) {
        certificateRepository.save(certificate);
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public int updateCertificatesStatusScheduled() {
        List<CertificateValidationStatus> skipStatuses = List.of(CertificateValidationStatus.REVOKED, CertificateValidationStatus.EXPIRED);
        long totalCertificates = certificateRepository.countCertificatesToCheckStatus(skipStatuses);
        int maxCertsToValidate = Math.max(100, Math.round(totalCertificates / (float) 24));

        LocalDateTime before = LocalDateTime.now().minusDays(1);

        // process 1/24 of eligible certificates for status update
        final List<UUID> certificateUuids = certificateRepository.findCertificatesToCheckStatus(before, skipStatuses, PageRequest.of(0, maxCertsToValidate));

        int certificatesUpdated = 0;
        logger.info(MarkerFactory.getMarker("scheduleInfo"), "Scheduled certificate status update. Batch size {}/{} certificates", certificateUuids.size(), totalCertificates);
        for (final UUID certificateUuid : certificateUuids) {
            Certificate certificate = null;
            TransactionStatus status = transactionManager.getTransaction(new DefaultTransactionDefinition());
            try {
                certificate = certificateRepository.findWithAssociationsByUuid(certificateUuid).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
                validate(certificate);
                if (certificate.getRaProfileUuid() != null && certificate.getComplianceStatus() == ComplianceStatus.NOT_CHECKED) {
                    complianceService.checkComplianceOfCertificate(certificate);
                }

                transactionManager.commit(status);
                ++certificatesUpdated;
            } catch (NotFoundException e) {
                logger.warn(MarkerFactory.getMarker("scheduleInfo"), "Scheduled task was unable to update status of the certificate. Error: {}", e.getMessage(), e);
                transactionManager.rollback(status);
            } catch (Exception e) {
                logger.warn(MarkerFactory.getMarker("scheduleInfo"), "Scheduled task was unable to update status of the certificate. Certificate {}. Error: {}", certificate, e.getMessage(), e);
                transactionManager.rollback(status);
            }

        }
        logger.info(MarkerFactory.getMarker("scheduleInfo"), "Certificates status updated for {}/{} certificates", certificatesUpdated, certificateUuids.size());
        return certificatesUpdated;
    }

    @Override
    // Internal Use Only
    public void updateCertificateUser(UUID certificateUuid, String userUuid) throws NotFoundException {
        Certificate certificate = certificateRepository.findByUuid(certificateUuid).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
        if (userUuid == null) {
            certificate.setUserUuid(null);
        } else {
            certificate.setUserUuid(UUID.fromString(userUuid));
        }
        certificateRepository.save(certificate);
    }

    @Override
    // Internal Use Only
    public void removeCertificateUser(UUID userUuid) {
        try {
            Certificate certificate = certificateRepository.findByUserUuid(userUuid).orElseThrow(() -> new NotFoundException(Certificate.class, userUuid));
            certificate.setUserUuid(null);
            certificateRepository.save(certificate);
        } catch (NotFoundException e) {
            logger.warn("No Certificate found for the user with UUID {}", userUuid);
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.LIST, parentResource = Resource.RA_PROFILE, parentAction = ResourceAction.LIST)
    public Long statisticsCertificateCount(SecurityFilter filter) {
        setupSecurityFilter(filter);
        return certificateRepository.countUsingSecurityFilter(filter);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.LIST, parentResource = Resource.RA_PROFILE, parentAction = ResourceAction.LIST)
    public StatisticsDto addCertificateStatistics(SecurityFilter filter, StatisticsDto dto) {
        setupSecurityFilter(filter);
        List<Certificate> certificates = certificateRepository.findUsingSecurityFilter(filter, List.of("groups", "owner", "raProfile"), null);

        Map<String, Long> groupStat = new HashMap<>();
        Map<String, Long> raProfileStat = new HashMap<>();
        Map<String, Long> typeStat = new HashMap<>();
        Map<String, Long> keySizeStat = new HashMap<>();
        Map<String, Long> bcStat = new HashMap<>();
        Map<String, Long> expiryStat = new HashMap<>();
        Map<String, Long> stateStat = new HashMap<>();
        Map<String, Long> validationStatusStat = new HashMap<>();
        Map<String, Long> complianceStat = new HashMap<>();
        Date currentTime = new Date();
        for (Certificate certificate : certificates) {
            typeStat.merge(certificate.getCertificateType().getCode(), 1L, Long::sum);

            if (certificate.getGroups() == null || certificate.getGroups().isEmpty()) {
                groupStat.merge("Unassigned", 1L, Long::sum);
            } else {
                for (Group group : certificate.getGroups()) {
                    groupStat.merge(group.getName(), 1L, Long::sum);
                }
            }

            raProfileStat.merge(certificate.getRaProfile() != null ? certificate.getRaProfile().getName() : "Unassigned", 1L, Long::sum);
            if (certificate.getCertificateContent() != null) {
                expiryStat.merge(getExpiryTime(currentTime, certificate.getNotAfter()), 1L, Long::sum);
                bcStat.merge(certificate.getBasicConstraints(), 1L, Long::sum);
            }
            keySizeStat.merge(certificate.getKeySize().toString(), 1L, Long::sum);
            stateStat.merge(certificate.getState().getCode(), 1L, Long::sum);
            validationStatusStat.merge(certificate.getValidationStatus().getCode(), 1L, Long::sum);
            complianceStat.merge(certificate.getComplianceStatus().getCode(), 1L, Long::sum);
        }
        dto.setGroupStatByCertificateCount(groupStat);
        dto.setRaProfileStatByCertificateCount(raProfileStat);
        dto.setCertificateStatByType(typeStat);
        dto.setCertificateStatByKeySize(keySizeStat);
        dto.setCertificateStatByBasicConstraints(bcStat);
        dto.setCertificateStatByExpiry(expiryStat);
        dto.setCertificateStatByState(stateStat);
        dto.setCertificateStatByValidationStatus(validationStatusStat);
        dto.setCertificateStatByComplianceStatus(complianceStat);
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.CREATE)
    public void checkCreatePermissions() {
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.ISSUE)
    public void checkIssuePermissions() {
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.RENEW)
    public void checkRenewPermissions() {
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.REVOKE)
    public void checkRevokePermissions() {
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.ANY)
    public List<BaseAttribute> getCsrGenerationAttributes() {
        return CsrAttributes.csrAttributes();
    }

    @Override
    public void clearKeyAssociations(UUID keyUuid) {
        List<Certificate> certificates = certificateRepository.findByKeyUuid(keyUuid);
        for (Certificate certificate : certificates) {
            certificate.setKey(null);
            certificate.setKeyUuid(null);
            certificateRepository.save(certificate);
        }
    }

    @Override
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter) {
        return null;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getCertificateEntity(uuid);
    }

    @Override
    public void updateCertificateKeys(UUID keyUuid, String publicKeyFingerprint) {
        for (Certificate certificate : certificateRepository.findByPublicKeyFingerprint(publicKeyFingerprint)) {
            certificate.setKeyUuid(keyUuid);
            certificateRepository.save(certificate);
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.LIST)
    public List<CertificateContentDto> getCertificateContent(List<String> uuids) {
        List<CertificateContentDto> response = new ArrayList<>();
        for (String uuid : uuids) {
            try {
                SecuredUUID securedUUID = SecuredUUID.fromString(uuid);
                permissionEvaluator.certificate(securedUUID);
                Certificate certificate = getCertificateEntity(securedUUID);
                CertificateContentDto dto = new CertificateContentDto();
                dto.setUuid(uuid);
                dto.setCommonName(certificate.getCommonName());
                dto.setSerialNumber(certificate.getSerialNumber());
                dto.setCertificateContent(certificate.getCertificateContent().getContent());
                response.add(dto);
            } catch (Exception e) {
                logger.error("Unable to get the certificate content {}. Exception: {}", uuid, e.getMessage());
            }
        }
        return response;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.CREATE)
    public CertificateDetailDto submitCertificateRequest(
            String certificateRequest,
            CertificateRequestFormat certificateRequestFormat,
            List<RequestAttributeDto> signatureAttributes,
            List<RequestAttributeDto> csrAttributes,
            List<RequestAttributeDto> issueAttributes,
            UUID keyUuid,
            UUID raProfileUuid,
            UUID sourceCertificateUuid,
            UUID protocolProfileUuid,
            UUID additionalProtocolUuid,
            Protocol protocol
    ) throws NoSuchAlgorithmException, ConnectorException, AttributeException, CertificateRequestException {
        RaProfile raProfile = raProfileService.getRaProfileEntity(SecuredUUID.fromUUID(raProfileUuid));
        extendedAttributeService.mergeAndValidateIssueAttributes(raProfile, issueAttributes);

        // create certificate request from CSR and parse the data
        byte[] decodedCsr = Base64.getDecoder().decode(certificateRequest);
        CertificateRequest request = CertificateRequestUtils.createCertificateRequest(decodedCsr, certificateRequestFormat);

        Certificate certificate = new Certificate();
        // prepare certificate request data for certificate
        CertificateUtil.prepareCsrObject(certificate, request);

        certificate.setKeyUuid(keyUuid);
        certificate.setState(CertificateState.REQUESTED);
        certificate.setComplianceStatus(ComplianceStatus.NOT_CHECKED);
        certificate.setValidationStatus(CertificateValidationStatus.NOT_CHECKED);
        certificate.setCertificateType(CertificateType.X509);
        certificate.setRaProfileUuid(raProfileUuid);
        certificate.setSourceCertificateUuid(sourceCertificateUuid);

        // find if exists same certificate request by content
        CertificateRequestEntity certificateRequestEntity;

        final String certificateRequestFingerprint = CertificateUtil.getThumbprint(decodedCsr);
        // get the certificate request by fingerprint, if exists
        Optional<CertificateRequestEntity> certificateRequestOptional =
                certificateRequestRepository.findByFingerprint(certificateRequestFingerprint);

        List<ResponseAttributeDto> requestAttributes;
        List<ResponseAttributeDto> requestSignatureAttributes;
        if (certificateRequestOptional.isPresent()) {
            certificateRequestEntity = certificateRequestOptional.get();
            // if no CSR attributes are assigned to CSR, update them with ones provided
            requestAttributes = attributeEngine.getObjectDataAttributesContent(
                    null, null, Resource.CERTIFICATE_REQUEST, certificateRequestEntity.getUuid()
            );
            requestSignatureAttributes = attributeEngine.getObjectDataAttributesContent(
                    null, AttributeOperation.CERTIFICATE_REQUEST_SIGN, Resource.CERTIFICATE_REQUEST, certificateRequestEntity.getUuid()
            );
            if (requestAttributes.isEmpty() && csrAttributes != null && !csrAttributes.isEmpty()) {
                requestAttributes = attributeEngine.updateObjectDataAttributesContent(
                        null, null, Resource.CERTIFICATE_REQUEST, certificateRequestEntity.getUuid(), csrAttributes
                );
            }
            if (requestSignatureAttributes.isEmpty() && signatureAttributes != null && !signatureAttributes.isEmpty()) {
                requestSignatureAttributes = attributeEngine.updateObjectDataAttributesContent(
                        null, AttributeOperation.CERTIFICATE_REQUEST_SIGN, Resource.CERTIFICATE_REQUEST, certificateRequestEntity.getUuid(), signatureAttributes
                );
            }
        } else {
            certificateRequestEntity = certificate.prepareCertificateRequest(certificateRequestFormat);
            certificateRequestEntity.setFingerprint(certificateRequestFingerprint);
            certificateRequestEntity.setContent(certificateRequest);
            certificateRequestEntity = certificateRequestRepository.save(certificateRequestEntity);

            requestAttributes = attributeEngine.updateObjectDataAttributesContent(
                    null, null, Resource.CERTIFICATE_REQUEST, certificateRequestEntity.getUuid(), csrAttributes
            );
            requestSignatureAttributes = attributeEngine.updateObjectDataAttributesContent(
                    null, AttributeOperation.CERTIFICATE_REQUEST_SIGN, Resource.CERTIFICATE_REQUEST, certificateRequestEntity.getUuid(), signatureAttributes
            );
        }

        certificate.setCertificateRequest(certificateRequestEntity);
        certificate.setCertificateRequestUuid(certificateRequestEntity.getUuid());
        certificate = certificateRepository.save(certificate);

        if (protocol != null) {
            CertificateProtocolAssociation protocolAssociation = new CertificateProtocolAssociation();
            protocolAssociation.setCertificateUuid(certificate.getUuid());
            protocolAssociation.setProtocol(protocol);
            protocolAssociation.setProtocolProfileUuid(protocolProfileUuid);
            protocolAssociation.setAdditionalProtocolUuid(additionalProtocolUuid);
            certificateProtocolAssociationRepository.save(protocolAssociation);
        }


        // set owner of certificate to logged user
        objectAssociationService.setOwnerFromProfile(Resource.CERTIFICATE, certificate.getUuid());

        CertificateDetailDto dto = certificate.mapToDto();
        dto.getCertificateRequest().setAttributes(requestAttributes);
        dto.getCertificateRequest().setSignatureAttributes(requestSignatureAttributes);
        dto.setIssueAttributes(attributeEngine.updateObjectDataAttributesContent(
                raProfile.getAuthorityInstanceReference().getConnectorUuid(),
                AttributeOperation.CERTIFICATE_ISSUE, Resource.CERTIFICATE, certificate.getUuid(), issueAttributes)
        );
        certificateEventHistoryService.addEventHistory(
                certificate.getUuid(), CertificateEvent.REQUEST, CertificateEventStatus.SUCCESS,
                "Certificate request created", ""
        );

        logger.info("Certificate request submitted and certificate created {}", certificate);

        return dto;
    }

    @Override
    public CertificateDetailDto issueRequestedCertificate(UUID uuid, String certificateData, List<MetadataAttribute> meta) throws CertificateException, NoSuchAlgorithmException, AlreadyExistException, NotFoundException, AttributeException {
        X509Certificate x509Cert = CertificateUtil.parseCertificate(certificateData);
        String fingerprint = CertificateUtil.getThumbprint(x509Cert);
        if (certificateRepository.findByFingerprint(fingerprint).isPresent()) {
            throw new AlreadyExistException("Certificate already exists with fingerprint " + fingerprint);
        }
        Certificate certificate = certificateRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(Certificate.class, uuid));
        CertificateUtil.prepareIssuedCertificate(certificate, x509Cert);
        CertificateContent certificateContent = checkAddCertificateContent(fingerprint, X509ObjectToString.toPem(x509Cert));
        certificate.setFingerprint(fingerprint);
        certificate.setCertificateContent(certificateContent);
        certificate.setCertificateContentId(certificateContent.getId());

        // if key association is not sent, search in key inventory by fingerprint
        if (certificate.getKeyUuid() == null && certificate.getPublicKeyFingerprint() != null) {
            UUID keyUuid = cryptographicKeyService.findKeyByFingerprint(certificate.getPublicKeyFingerprint());
            certificate.setKeyUuid(keyUuid);
        }

        certificateRepository.save(certificate);

        // save metadata
        UUID connectorUuid = certificate.getRaProfile().getAuthorityInstanceReference().getConnectorUuid();

        attributeEngine.updateMetadataAttributes(meta, new ObjectAttributeContentInfo(connectorUuid, Resource.CERTIFICATE, certificate.getUuid()));
        certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.ISSUE, CertificateEventStatus.SUCCESS, "Issued using RA Profile " + certificate.getRaProfile().getName(), "");

        // check compliance and validity of certificate
        certificateComplianceCheck(certificate);
        validate(certificate);

        logger.info("Certificate was successfully issued. {}", certificate.getUuid());

        CertificateDetailDto dto = certificate.mapToDto();
        if (dto.getCertificateRequest() != null) {
            dto.getCertificateRequest().setAttributes(attributeEngine.getObjectDataAttributesContent(null, null, Resource.CERTIFICATE_REQUEST, certificate.getCertificateRequest().getUuid()));
            dto.getCertificateRequest().setSignatureAttributes(attributeEngine.getObjectDataAttributesContent(null, AttributeOperation.CERTIFICATE_REQUEST_SIGN, Resource.CERTIFICATE_REQUEST, certificate.getCertificateRequest().getUuid()));
        }
        dto.setMetadata(attributeEngine.getMappedMetadataContent(new ObjectAttributeContentInfo(Resource.CERTIFICATE, certificate.getUuid())));
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid()));
        dto.setRelatedCertificates(certificateRepository.findBySourceCertificateUuid(certificate.getUuid()).stream().map(Certificate::mapToListDto).toList());

        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.LIST, parentResource = Resource.RA_PROFILE, parentAction = ResourceAction.LIST)
    public List<CertificateDto> listScepCaCertificates(SecurityFilter filter, boolean intuneEnabled) {
        setupSecurityFilter(filter);

        List<Certificate> certificates = certificateRepository.findUsingSecurityFilter(filter, List.of("groups", "owner"), (root, cb) -> cb.and(cb.isNotNull(root.get("keyUuid")), cb.equal(root.get("state"), CertificateState.ISSUED), cb.or(cb.equal(root.get("validationStatus"), CertificateValidationStatus.VALID), cb.equal(root.get("validationStatus"), CertificateValidationStatus.EXPIRING))));
        return certificates.stream().filter(c -> CertificateUtil.isCertificateScepCaCertAcceptable(c, intuneEnabled)).map(Certificate::mapToListDto).toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.LIST, parentResource = Resource.RA_PROFILE, parentAction = ResourceAction.LIST)
    public List<CertificateDto> listCmpSigningCertificates(SecurityFilter filter) {
        setupSecurityFilter(filter);

        List<Certificate> certificates = certificateRepository.findUsingSecurityFilter(
                filter,
                List.of("groups", "owner"),
                (root, cb) -> cb.and(
                        cb.isNotNull(root.get("keyUuid")),
                        cb.equal(root.get("state"), CertificateState.ISSUED),
                        cb.or(
                                cb.equal(root.get("validationStatus"), CertificateValidationStatus.VALID),
                                cb.equal(root.get("validationStatus"), CertificateValidationStatus.EXPIRING)
                        )
                )
        );

        return certificates.stream()
                .filter(CertificateUtil::isCertificateCmpAcceptable)
                .map(Certificate::mapToListDto).toList();
    }

    private String getExpiryTime(Date now, Date expiry) {
        long diffInMilliseconds = expiry.getTime() - now.getTime();
        long difference = TimeUnit.DAYS.convert(diffInMilliseconds, TimeUnit.MILLISECONDS);
        if (diffInMilliseconds <= 0) {
            return "expired";
        } else if (difference < 10) {
            return "10";
        } else if (difference < 20) {
            return "20";
        } else if (difference < 30) {
            return "30";
        } else if (difference < 60) {
            return "60";
        } else if (difference < 90) {
            return "90";
        }
        return "More";
    }


    @Deprecated
    private List<SearchFieldDataDto> getSearchableFieldsMap() {

        final List<SearchFieldDataDto> fields = List.of(SearchHelper.prepareSearch(SearchFieldNameEnum.COMMON_NAME), SearchHelper.prepareSearch(SearchFieldNameEnum.SERIAL_NUMBER_LABEL), SearchHelper.prepareSearch(SearchFieldNameEnum.ISSUER_SERIAL_NUMBER), SearchHelper.prepareSearch(SearchFieldNameEnum.RA_PROFILE, raProfileRepository.findAll().stream().map(RaProfile::getName).toList()), SearchHelper.prepareSearch(SearchFieldNameEnum.GROUP, groupRepository.findAll().stream().map(Group::getName).toList()), SearchHelper.prepareSearch(SearchFieldNameEnum.OWNER), SearchHelper.prepareSearch(SearchFieldNameEnum.CERTIFICATE_STATE, Arrays.stream(CertificateState.values()).map(CertificateState::getCode).toList()), SearchHelper.prepareSearch(SearchFieldNameEnum.CERTIFICATE_VALIDATION_STATUS, Arrays.stream(CertificateValidationStatus.values()).map(CertificateValidationStatus::getCode).toList()), SearchHelper.prepareSearch(SearchFieldNameEnum.COMPLIANCE_STATUS, Arrays.stream(ComplianceStatus.values()).map(ComplianceStatus::getCode).toList()), SearchHelper.prepareSearch(SearchFieldNameEnum.ISSUER_COMMON_NAME), SearchHelper.prepareSearch(SearchFieldNameEnum.FINGERPRINT), SearchHelper.prepareSearch(SearchFieldNameEnum.SIGNATURE_ALGORITHM, new ArrayList<>(certificateRepository.findDistinctSignatureAlgorithm())), SearchHelper.prepareSearch(SearchFieldNameEnum.EXPIRES), SearchHelper.prepareSearch(SearchFieldNameEnum.NOT_BEFORE), SearchHelper.prepareSearch(SearchFieldNameEnum.SUBJECT_DN), SearchHelper.prepareSearch(SearchFieldNameEnum.ISSUER_DN), SearchHelper.prepareSearch(SearchFieldNameEnum.SUBJECT_ALTERNATIVE), SearchHelper.prepareSearch(SearchFieldNameEnum.OCSP_VALIDATION, Arrays.stream((CertificateValidationStatus.values())).map(CertificateValidationStatus::getCode).toList()), SearchHelper.prepareSearch(SearchFieldNameEnum.CRL_VALIDATION, Arrays.stream((CertificateValidationStatus.values())).map(CertificateValidationStatus::getCode).toList()), SearchHelper.prepareSearch(SearchFieldNameEnum.SIGNATURE_VALIDATION, Arrays.stream((CertificateValidationStatus.values())).map(CertificateValidationStatus::getCode).toList()), SearchHelper.prepareSearch(SearchFieldNameEnum.PUBLIC_KEY_ALGORITHM, new ArrayList<>(certificateRepository.findDistinctPublicKeyAlgorithm())), SearchHelper.prepareSearch(SearchFieldNameEnum.KEY_SIZE, new ArrayList<>(certificateRepository.findDistinctKeySize())), SearchHelper.prepareSearch(SearchFieldNameEnum.KEY_USAGE, serializedListOfStringToListOfObject(certificateRepository.findDistinctKeyUsage())));

        logger.debug("Searchable Fields: {}", fields);
        return fields;
    }

    private List<Object> serializedListOfStringToListOfObject(List<String> serializedData) {
        Set<String> serSet = new LinkedHashSet<>();
        for (String obj : serializedData) {
            serSet.addAll(MetaDefinitions.deserializeArrayString(obj));
        }
        return new ArrayList<>(serSet);
    }

    private List<CertificateComplianceResultDto> frameComplianceResult(CertificateComplianceStorageDto storageDto) {
        logger.debug("Framing Compliance Result from stored data: {}", storageDto);
        List<CertificateComplianceResultDto> result = new ArrayList<>();
        List<ComplianceProfileRule> rules = complianceService.getComplianceProfileRuleEntityForIds(storageDto.getNok());
        List<ComplianceRule> rulesWithoutAttributes = complianceService.getComplianceRuleEntityForIds(storageDto.getNok());
        for (ComplianceProfileRule complianceRule : rules) {
            result.add(getCertificateComplianceResultDto(complianceRule, ComplianceRuleStatus.NOK));
        }
        for (ComplianceRule complianceRule : rulesWithoutAttributes) {
            result.add(getCertificateComplianceResultDto(complianceRule, ComplianceRuleStatus.NOK));
        }
        logger.debug("Compliance Result: {}", result);
        return result;
    }

    private CertificateComplianceResultDto getCertificateComplianceResultDto(ComplianceProfileRule rule, ComplianceRuleStatus status) {
        CertificateComplianceResultDto dto = new CertificateComplianceResultDto();
        dto.setConnectorName(rule.getComplianceRule().getConnector().getName());
        dto.setRuleName(rule.getComplianceRule().getName());
        dto.setRuleDescription(rule.getComplianceRule().getDescription());
        List<DataAttribute> attributes = AttributeDefinitionUtils.mergeAttributes(rule.getComplianceRule().getAttributes(), rule.getAttributes());
        dto.setAttributes(AttributeDefinitionUtils.getResponseAttributes(attributes));
        dto.setStatus(status);
        return dto;
    }

    private CertificateComplianceResultDto getCertificateComplianceResultDto(ComplianceRule rule, ComplianceRuleStatus status) {
        CertificateComplianceResultDto dto = new CertificateComplianceResultDto();
        dto.setConnectorName(rule.getConnector().getName());
        dto.setRuleName(rule.getName());
        dto.setRuleDescription(rule.getDescription());
        dto.setAttributes(AttributeDefinitionUtils.getResponseAttributes(rule.getAttributes()));
        dto.setStatus(status);
        return dto;
    }

    // TODO - move to search service
    private void bulkUpdateRaProfileComplianceCheck(List<SearchFilterRequestDto> searchFilter) {
        List<Certificate> certificates = (List<Certificate>) searchService.completeSearchQueryExecutor(searchFilter, "Certificate", getSearchableFieldInformation());
        CertificateComplianceCheckDto dto = new CertificateComplianceCheckDto();
        dto.setCertificateUuids(certificates.stream().map(Certificate::getUuid).map(UUID::toString).toList());
        checkCompliance(dto);
    }

    private void certificateComplianceCheck(Certificate certificate) {
        if (certificate.getRaProfile() != null) {
            try {
                complianceService.checkComplianceOfCertificate(certificate);
            } catch (ConnectorException e) {
                logger.debug("Error when checking compliance: {}", e.getMessage());
            }
        }
    }

    private List<String> downloadChainFromAia(Certificate certificate) {
        List<String> chainCertificates = new ArrayList<>();
        String chainUrl;
        try {
            X509Certificate certX509 = getX509(certificate.getCertificateContent().getContent());
            while (true) {
                chainUrl = OcspUtil.getChainFromAia(certX509);
                if (chainUrl == null || chainUrl.isEmpty()) {
                    break;
                }
                String chainContent = downloadChain(chainUrl);
                if (chainContent.isEmpty()) {
                    break;
                }
                logger.info("Certificate {} downloaded from Authority Information Access extension URL {}", certX509.getSubjectX500Principal().getName(), chainUrl);

                chainCertificates.add(chainContent);
                certX509 = getX509(chainContent);

                // if self-signed, do not attempt to download itself
                if (verifySignature(certX509, certX509)) {
                    break;
                }
            }
        } catch (Exception e) {
            logger.debug("Unable to get the chain of certificate {} from Authority Information Access", certificate.getUuid(), e);
        }
        return chainCertificates;
    }

    private String downloadChain(String chainUrl) {
        try {
            CertificateFactory fac = CertificateFactory.getInstance("X509");
            X509Certificate cert;
            // Handle ldap protocol

            if (chainUrl.startsWith("ldap://") || chainUrl.startsWith("ldaps://")) {
                byte[] certificate = LdapUtils.downloadFromLdap(chainUrl);
                if (certificate == null) return "";
                cert = (X509Certificate) fac.generateCertificate(new ByteArrayInputStream(certificate));
            } else {
                URL url = new URL(chainUrl);
                URLConnection urlConnection = url.openConnection();
                urlConnection.setConnectTimeout(1000);
                urlConnection.setReadTimeout(1000);
                String fileName = chainUrl.split("/")[chainUrl.split("/").length - 1];
                try (InputStream in = url.openStream(); ReadableByteChannel rbc = Channels.newChannel(in); FileOutputStream fos = new FileOutputStream(fileName)) {
                    fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
                } catch (Exception e) {
                    logger.error(e.getMessage());
                    return "";
                }
                FileInputStream is = new FileInputStream(fileName);
                cert = (X509Certificate) fac.generateCertificate(is);
                is.close();
                Path path = Paths.get(fileName);
                Files.deleteIfExists(path);
            }
            final StringWriter writer = new StringWriter();
            final JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
            pemWriter.writeObject(cert);
            pemWriter.flush();
            pemWriter.close();
            writer.close();

            return writer.toString();
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return "";
    }

    public void switchRaProfile(SecuredUUID uuid, SecuredUUID raProfileUuid) throws NotFoundException, CertificateOperationException, AttributeException {
        Certificate certificate = getCertificateEntity(uuid);

        // check if there is change in RA profile compared to current state
        if ((raProfileUuid == null && certificate.getRaProfileUuid() == null) || (raProfileUuid != null && certificate.getRaProfileUuid() != null) && certificate.getRaProfileUuid().toString().equals(raProfileUuid.toString())) {
            return;
        }

        // removing RA profile
        RaProfile newRaProfile = null;
        RaProfile currentRaProfile = certificate.getRaProfile();
        String newRaProfileName = UNDEFINED_CERTIFICATE_OBJECT_NAME;
        String currentRaProfileName = currentRaProfile != null ? currentRaProfile.getName() : UNDEFINED_CERTIFICATE_OBJECT_NAME;
        CertificateIdentificationResponseDto response = null;
        if (raProfileUuid != null) {
            newRaProfile = raProfileRepository.findByUuid(raProfileUuid).orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
            newRaProfileName = newRaProfile.getName();

            // identify certificate by new authority
            CertificateIdentificationRequestDto requestDto = new CertificateIdentificationRequestDto();
            requestDto.setCertificate(certificate.getCertificateContent().getContent());
            requestDto.setRaProfileAttributes(attributeEngine.getRequestObjectDataAttributesContent(newRaProfile.getAuthorityInstanceReference().getConnectorUuid(), null, Resource.RA_PROFILE, newRaProfile.getUuid()));
            try {
                response = certificateApiClient.identifyCertificate(newRaProfile.getAuthorityInstanceReference().getConnector().mapToDto(), newRaProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(), requestDto);
            } catch (ConnectorException e) {
                certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.UPDATE_RA_PROFILE, CertificateEventStatus.FAILED, String.format("Certificate not identified by authority of new RA profile %s. Certificate needs to be reissued.", newRaProfile.getName()), "");
                throw new CertificateOperationException(String.format("Cannot switch RA profile for certificate. Certificate not identified by authority of new RA profile %s. Certificate: %s", newRaProfile.getName(), certificate));
            } catch (ValidationException e) {
                certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.UPDATE_RA_PROFILE, CertificateEventStatus.FAILED, String.format("Certificate identified by authority of new RA profile %s but not valid according to RA profile attributes. Certificate needs to be reissued.", newRaProfile.getName()), "");
                throw new CertificateOperationException(String.format("Cannot switch RA profile for certificate. Certificate identified by authority of new RA profile %s but not valid according to RA profile attributes. Certificate: %s", newRaProfile.getName(), certificate));
            }
        }

        certificate.setRaProfile(newRaProfile);
        certificateRepository.save(certificate);

        // delete old metadata
        if (currentRaProfile != null) {
            attributeEngine.deleteObjectAttributesContent(AttributeType.META, new ObjectAttributeContentInfo(currentRaProfile.getAuthorityInstanceReference().getConnectorUuid(), Resource.CERTIFICATE, certificate.getUuid()));
        }

        // save metadata for identified certificate and run compliance
        if (newRaProfile != null) {
            UUID connectorUuid = newRaProfile.getAuthorityInstanceReference().getConnectorUuid();
            attributeEngine.updateMetadataAttributes(response.getMeta(), new ObjectAttributeContentInfo(connectorUuid, Resource.CERTIFICATE, certificate.getUuid()));

            try {
                complianceService.checkComplianceOfCertificate(certificate);
            } catch (ConnectorException e) {
                logger.error("Error when checking compliance:", e);
            }
        }

        certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.UPDATE_RA_PROFILE, CertificateEventStatus.SUCCESS, currentRaProfileName + " -> " + newRaProfileName, "");
    }

    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.UPDATE)
    public void updateCertificateGroups(SecuredUUID uuid, Set<UUID> groupUuids) throws NotFoundException {
        Certificate certificate = getCertificateEntityWithAssociations(uuid);

        if (groupUuids == null) {
            groupUuids = new HashSet<>();
        }

        // check if there is change in group compared to current state
        Set<UUID> currentGroups = certificate.getGroups().stream().map(Group::getUuid).collect(Collectors.toSet());
        if (currentGroups.equals(groupUuids)) {
            return;
        }

        String currentGroupNames = certificate.getGroups().isEmpty() ? UNDEFINED_CERTIFICATE_OBJECT_NAME : String.join(", ", certificate.getGroups().stream().map(Group::getName).toList());
        Set<Group> newGroups = objectAssociationService.setGroups(Resource.CERTIFICATE, certificate.getUuid(), groupUuids);
        String newGroupNames = newGroups.isEmpty() ? UNDEFINED_CERTIFICATE_OBJECT_NAME : String.join(", ", newGroups.stream().map(Group::getName).toList());

        certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.UPDATE_GROUP, CertificateEventStatus.SUCCESS, currentGroupNames + " -> " + newGroupNames, "");
    }

    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.UPDATE)
    public void updateOwner(SecuredUUID uuid, String ownerUuid) throws NotFoundException {
        Certificate certificate = getCertificateEntityWithAssociations(uuid);

        // if there is no change, do not update and save request to Auth service
        if ((ownerUuid == null && certificate.getOwner() == null) || (ownerUuid != null && certificate.getOwner() != null) && certificate.getOwner().getUuid().equals(ownerUuid)) {
            return;
        }

        UUID newOwnerUuid = ownerUuid == null ? null : UUID.fromString(ownerUuid);
        String currentOwnerName = certificate.getOwner() == null ? UNDEFINED_CERTIFICATE_OBJECT_NAME : certificate.getOwner().getOwnerUsername();

        String newOwnerName = UNDEFINED_CERTIFICATE_OBJECT_NAME;
        NameAndUuidDto newOwner = objectAssociationService.setOwner(Resource.CERTIFICATE, uuid.getValue(), newOwnerUuid);
        if (newOwner != null) {
            newOwnerName = newOwner.getName();
        }

        certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.UPDATE_OWNER, CertificateEventStatus.SUCCESS, String.format("%s -> %s", currentOwnerName, newOwnerName == null ? UNDEFINED_CERTIFICATE_OBJECT_NAME : newOwnerName), "");
    }

    private void bulkUpdateRaProfile(SecurityFilter filter, MultipleCertificateObjectUpdateDto request) throws NotFoundException {
        boolean removeRaProfile = request.getRaProfileUuid().isEmpty();
        if (request.getFilters() == null || request.getFilters().isEmpty() || (request.getCertificateUuids() != null && !request.getCertificateUuids().isEmpty())) {
            for (String certificateUuidString : request.getCertificateUuids()) {
                try {
                    SecuredUUID certificateUuid = SecuredUUID.fromString(certificateUuidString);
                    permissionEvaluator.certificate(certificateUuid);
                    switchRaProfile(certificateUuid, removeRaProfile ? null : SecuredUUID.fromString(request.getRaProfileUuid()));
                } catch (CertificateOperationException e) {
                    logger.warn(e.getMessage());
                } catch (AttributeException e) {
                    logger.warn("Certificate {} switched but there was issue with updating attributes: {}", certificateUuidString, e.getMessage());
                }
            }
        } else {
            RaProfile raProfile = removeRaProfile ? null : raProfileRepository.findByUuid(SecuredUUID.fromString(request.getRaProfileUuid())).orElseThrow(() -> new NotFoundException(RaProfile.class, request.getRaProfileUuid()));

            String data = searchService.createCriteriaBuilderString(filter, false);
            if (!data.isEmpty()) {
                data = "WHERE " + data;
            }

            String profileUpdateQuery = "UPDATE Certificate c SET c.raProfile = " + (removeRaProfile ? "NULL" : raProfile.getUuid()) + searchService.getCompleteSearchQuery(request.getFilters(), "certificate", data, getSearchableFieldInformation(), true, false).replace("GROUP BY c.id ORDER BY c.id DESC", "");
            certificateRepository.bulkUpdateQuery(profileUpdateQuery);
            certificateEventHistoryService.addEventHistoryForRequest(request.getFilters(), "Certificate", getSearchableFieldInformation(), CertificateEvent.UPDATE_RA_PROFILE, CertificateEventStatus.SUCCESS, "RA Profile Name: " + (removeRaProfile ? UNDEFINED_CERTIFICATE_OBJECT_NAME : raProfile.getName()));
            bulkUpdateRaProfileComplianceCheck(request.getFilters());
        }
    }

    private void bulkUpdateCertificateGroup(SecurityFilter filter, MultipleCertificateObjectUpdateDto request) throws NotFoundException {
        if (request.getFilters() == null || request.getFilters().isEmpty() || (request.getCertificateUuids() != null && !request.getCertificateUuids().isEmpty())) {
            Set<UUID> groupUuids = request.getGroupUuids().stream().map(UUID::fromString).collect(Collectors.toSet());
            for (String certificateUuidString : request.getCertificateUuids()) {
                SecuredUUID certificateUuid = SecuredUUID.fromString(certificateUuidString);
                permissionEvaluator.certificate(certificateUuid);
                this.updateCertificateGroups(certificateUuid, groupUuids);
            }
        }
        // updating group by filters not supported now
//        else {
//        }
    }

    private void bulkUpdateOwner(SecurityFilter filter, MultipleCertificateObjectUpdateDto request) throws NotFoundException {
        boolean removeOwner = request.getOwnerUuid().isEmpty();
        String ownerUuid = null;
        String ownerName = null;
        if (!removeOwner) {
            ownerUuid = request.getOwnerUuid();
        }
        List<CertificateEventHistory> batchHistoryOperationList = new ArrayList<>();
        if (request.getFilters() == null || request.getFilters().isEmpty() || (request.getCertificateUuids() != null && !request.getCertificateUuids().isEmpty())) {
            List<Certificate> batchOperationList = new ArrayList<>();
            for (String certificateUuidString : request.getCertificateUuids()) {
                SecuredUUID certificateUuid = SecuredUUID.fromString(certificateUuidString);
                permissionEvaluator.certificate(certificateUuid);
                updateOwner(certificateUuid, ownerUuid);
            }
            certificateRepository.saveAll(batchOperationList);
            certificateEventHistoryService.asyncSaveAllInBatch(batchHistoryOperationList);
        } else {
            String data = searchService.createCriteriaBuilderString(filter, false);
            if (!data.isEmpty()) {
                data = "WHERE " + data;
            }
            String ownerUpdateQuery = "UPDATE Certificate c SET c.owner = '" + (removeOwner ? "NULL" : ownerName) + "',c.owner_uuid = '" + (removeOwner ? "NULL" : UUID.fromString(request.getOwnerUuid())) + "' " + searchService.getCompleteSearchQuery(request.getFilters(), "certificate", data, getSearchableFieldInformation(), true, false).replace("GROUP BY c.id ORDER BY c.id DESC", "");
            certificateRepository.bulkUpdateQuery(ownerUpdateQuery);
            certificateEventHistoryService.addEventHistoryForRequest(request.getFilters(), "Certificate", getSearchableFieldInformation(), CertificateEvent.UPDATE_OWNER, CertificateEventStatus.SUCCESS, "Owner: " + (removeOwner ? UNDEFINED_CERTIFICATE_OBJECT_NAME : ownerName));
        }
    }

    private List<List<Certificate>> partitionList(List<Certificate> fullList) {
        List<List<Certificate>> certificates = new ArrayList<>();

        for (int i = 0; i < fullList.size(); i += DELETE_BATCH_SIZE) {
            certificates.add(fullList.subList(i, Math.min(i + DELETE_BATCH_SIZE, fullList.size())));
        }
        return certificates;
    }

    private List<List<CertificateContent>> partitionContents(List<CertificateContent> fullList) {
        List<List<CertificateContent>> certificates = new ArrayList<>();

        for (int i = 0; i < fullList.size(); i += DELETE_BATCH_SIZE) {
            certificates.add(fullList.subList(i, Math.min(i + DELETE_BATCH_SIZE, fullList.size())));
        }
        return certificates;
    }

    private void setupSecurityFilter(SecurityFilter filter) {
        filter.setParentRefProperty("raProfileUuid");
    }

    private ICertificateValidator getCertificateValidator(CertificateType certificateType) {
        ICertificateValidator certificateValidator = certificateValidatorMap.get(certificateType.getCode());
        if (certificateValidator == null) {
            throw new ValidationException("Unsupported certificate type validator for certificate type " + certificateType.getLabel());
        }
        return certificateValidator;
    }
}
