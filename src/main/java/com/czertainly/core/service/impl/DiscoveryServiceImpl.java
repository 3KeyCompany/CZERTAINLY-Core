package com.czertainly.core.service.impl;

import com.czertainly.api.clients.DiscoveryApiClient;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.certificate.DiscoveryResponseDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.discovery.DiscoveryCertificateResponseDto;
import com.czertainly.api.model.client.discovery.DiscoveryDto;
import com.czertainly.api.model.client.discovery.DiscoveryHistoryDetailDto;
import com.czertainly.api.model.client.discovery.DiscoveryHistoryDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.MetadataAttribute;
import com.czertainly.api.model.connector.discovery.DiscoveryDataRequestDto;
import com.czertainly.api.model.connector.discovery.DiscoveryProviderCertificateDataDto;
import com.czertainly.api.model.connector.discovery.DiscoveryProviderDto;
import com.czertainly.api.model.connector.discovery.DiscoveryRequestDto;
import com.czertainly.api.model.core.audit.ObjectType;
import com.czertainly.api.model.core.audit.OperationType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateEvent;
import com.czertainly.api.model.core.certificate.CertificateEventStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.discovery.DiscoveryStatus;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.comparator.SearchFieldDataComparator;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.entity.workflows.Trigger;
import com.czertainly.core.dao.entity.workflows.TriggerAssociation;
import com.czertainly.core.dao.entity.workflows.TriggerHistory;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.dao.repository.workflows.TriggerAssociationRepository;
import com.czertainly.core.enums.SearchFieldNameEnum;
import com.czertainly.core.evaluator.CertificateRuleEvaluator;
import com.czertainly.core.messaging.model.NotificationRecipient;
import com.czertainly.core.messaging.producers.EventProducer;
import com.czertainly.core.messaging.producers.NotificationProducer;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.*;
import com.czertainly.core.tasks.DiscoveryCertificateTask;
import com.czertainly.core.util.*;
import com.czertainly.core.util.converter.Sql2PredicateConverter;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.function.BiFunction;

@Service
@Transactional
public class DiscoveryServiceImpl implements DiscoveryService {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryServiceImpl.class);
    private static final Integer MAXIMUM_CERTIFICATES_PER_PAGE = 100;
    private static final Integer SLEEP_TIME = 5 * 1000; // Seconds * Milliseconds - Retry of discovery for every 5 Seconds
    private static final Long MAXIMUM_WAIT_TIME = (long) (6 * 60 * 60); // Hours * Minutes * Seconds
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private DiscoveryApiClient discoveryApiClient;
    @Autowired
    private ConnectorService connectorService;
    @Autowired
    private CertificateService certificateService;
    @Autowired
    private CertificateEventHistoryService certificateEventHistoryService;
    @Autowired
    private CredentialService credentialService;
    @Autowired
    private DiscoveryCertificateRepository discoveryCertificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private NotificationProducer notificationProducer;
    private EventProducer eventProducer;
    private AttributeEngine attributeEngine;

    private TriggerService triggerService;
    private TriggerAssociationRepository triggerAssociationRepository;
    private CertificateRuleEvaluator certificateRuleEvaluator;

    private DiscoveryCertificateTask discoveryCertificateTask;

    @Autowired
    public void setTriggerService(TriggerService triggerService) {
        this.triggerService = triggerService;
    }

    @Autowired
    public void setTriggerAssociationRepository(TriggerAssociationRepository triggerAssociationRepository) {
        this.triggerAssociationRepository = triggerAssociationRepository;
    }

    @Autowired
    public void setCertificateRuleEvaluator(CertificateRuleEvaluator certificateRuleEvaluator) {
        this.certificateRuleEvaluator = certificateRuleEvaluator;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setEventProducer(EventProducer eventProducer) {
        this.eventProducer = eventProducer;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.DISCOVERY, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.LIST)
    public DiscoveryResponseDto listDiscoveries(final SecurityFilter filter, final SearchRequestDto request) {

        RequestValidatorHelper.revalidateSearchRequestDto(request);
        final Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());

        // filter discoveries based on attribute filters
        final List<UUID> objectUUIDs = attributeEngine.getResourceObjectUuidsByFilters(Resource.DISCOVERY, filter, request.getFilters());

        final BiFunction<Root<DiscoveryHistory>, CriteriaBuilder, Predicate> additionalWhereClause = (root, cb) -> Sql2PredicateConverter.mapSearchFilter2Predicates(request.getFilters(), cb, root, objectUUIDs, attributeEngine.findAllObjectUuids(Resource.DISCOVERY));
        final List<DiscoveryHistoryDto> listedDiscoveriesDTOs = discoveryRepository.findUsingSecurityFilter(filter, List.of(), additionalWhereClause, p, (root, cb) -> cb.desc(root.get("created")))
                .stream()
                .map(DiscoveryHistory::mapToListDto).toList();
        final Long maxItems = discoveryRepository.countUsingSecurityFilter(filter, additionalWhereClause);

        final DiscoveryResponseDto responseDto = new DiscoveryResponseDto();
        responseDto.setDiscoveries(listedDiscoveriesDTOs);
        responseDto.setItemsPerPage(request.getItemsPerPage());
        responseDto.setPageNumber(request.getPageNumber());
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / request.getItemsPerPage()));
        return responseDto;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.DISCOVERY, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.DETAIL)
    public DiscoveryHistoryDetailDto getDiscovery(SecuredUUID uuid) throws NotFoundException {
        DiscoveryHistory discoveryHistory = getDiscoveryEntity(uuid);
        DiscoveryHistoryDetailDto dto = discoveryHistory.mapToDto();
        dto.setMetadata(attributeEngine.getMappedMetadataContent(new ObjectAttributeContentInfo(Resource.DISCOVERY, discoveryHistory.getUuid())));
        dto.setAttributes(attributeEngine.getObjectDataAttributesContent(discoveryHistory.getConnectorUuid(), null, Resource.DISCOVERY, discoveryHistory.getUuid()));
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.DISCOVERY, uuid.getValue()));
        return dto;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.DISCOVERY, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.DETAIL)
    public DiscoveryCertificateResponseDto getDiscoveryCertificates(SecuredUUID uuid,
                                                                    Boolean newlyDiscovered,
                                                                    int itemsPerPage,
                                                                    int pageNumber) throws NotFoundException {
        DiscoveryHistory discoveryHistory = getDiscoveryEntity(uuid);
        // Page number for the user always starts from 1. But for JPA, page number starts from 0
        Pageable p = PageRequest.of(pageNumber > 1 ? pageNumber - 1 : 0, itemsPerPage);
        List<DiscoveryCertificate> certificates;
        long maxItems;
        if (newlyDiscovered == null) {
            certificates = discoveryCertificateRepository.findByDiscovery(discoveryHistory, p);
            maxItems = discoveryCertificateRepository.countByDiscovery(discoveryHistory);
        } else {
            certificates = discoveryCertificateRepository.findByDiscoveryAndNewlyDiscovered(discoveryHistory, newlyDiscovered, p);
            maxItems = discoveryCertificateRepository.countByDiscoveryAndNewlyDiscovered(discoveryHistory, newlyDiscovered);
        }

        final DiscoveryCertificateResponseDto responseDto = new DiscoveryCertificateResponseDto();
        responseDto.setCertificates(certificates.stream().map(DiscoveryCertificate::mapToDto).toList());
        responseDto.setItemsPerPage(itemsPerPage);
        responseDto.setPageNumber(pageNumber);
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / itemsPerPage));
        return responseDto;
    }

    public DiscoveryHistory getDiscoveryEntity(SecuredUUID uuid) throws NotFoundException {
        return discoveryRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(DiscoveryHistory.class, uuid));
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.DISCOVERY, operation = OperationType.DELETE)
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.DELETE)
    public void deleteDiscovery(SecuredUUID uuid) throws NotFoundException {
        DiscoveryHistory discovery = discoveryRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(DiscoveryHistory.class, uuid));
        for (DiscoveryCertificate cert : discoveryCertificateRepository.findByDiscovery(discovery)) {
            try {
                discoveryCertificateRepository.delete(cert);
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
            if (certificateRepository.findByCertificateContent(cert.getCertificateContent()) == null && discoveryCertificateRepository.findByCertificateContent(cert.getCertificateContent()).isEmpty()) {
                CertificateContent content = certificateContentRepository.findById(cert.getCertificateContent().getId())
                        .orElse(null);
                if (content != null) {
                    try {
                        certificateContentRepository.delete(content);
                    } catch (Exception e) {
                        logger.warn("Failed to delete the certificate.");
                        logger.warn(e.getMessage());
                    }
                }
            }
        }

        attributeEngine.deleteAllObjectAttributeContent(Resource.DISCOVERY, discovery.getUuid());
        discoveryRepository.delete(discovery);

        triggerService.deleteTriggerAssociation(Resource.DISCOVERY, discovery.getUuid());

        try {
            String referenceUuid = discovery.getDiscoveryConnectorReference();
            if (referenceUuid != null && !referenceUuid.isEmpty()) {
                Connector connector = connectorService.getConnectorEntity(SecuredUUID.fromUUID(discovery.getConnectorUuid()));
                discoveryApiClient.removeDiscovery(connector.mapToDto(), referenceUuid);
            }
        } catch (ConnectorException e) {
            logger.warn("Failed to delete discovery in the connector. But core history is deleted");
            logger.warn(e.getMessage());
        } catch (Exception e) {
            logger.warn(e.getMessage());
        }
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.DISCOVERY, operation = OperationType.DELETE)
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.DELETE)
    public void bulkRemoveDiscovery(List<SecuredUUID> discoveryUuids) throws NotFoundException {
        for (SecuredUUID uuid : discoveryUuids) {
            deleteDiscovery(uuid);
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.LIST)
    public Long statisticsDiscoveryCount(SecurityFilter filter) {
        return discoveryRepository.countUsingSecurityFilter(filter);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.DISCOVERY, operation = OperationType.CREATE)
    public DiscoveryHistoryDetailDto createDiscovery(final DiscoveryDto request, final boolean saveEntity) throws AlreadyExistException, ConnectorException, AttributeException {
        if (discoveryRepository.findByName(request.getName()).isPresent()) {
            throw new AlreadyExistException(DiscoveryHistory.class, request.getName());
        }
        if (request.getConnectorUuid() == null) {
            throw new ValidationException(ValidationError.create("Connector UUID is empty"));
        }
        Connector connector = connectorService.getConnectorEntity(SecuredUUID.fromString(request.getConnectorUuid()));

        attributeEngine.validateCustomAttributesContent(Resource.DISCOVERY, request.getCustomAttributes());
        connectorService.mergeAndValidateAttributes(SecuredUUID.fromUUID(connector.getUuid()), FunctionGroupCode.DISCOVERY_PROVIDER, request.getAttributes(), request.getKind());


        DiscoveryHistory discovery = new DiscoveryHistory();
        discovery.setName(request.getName());
        discovery.setConnectorName(connector.getName());
        discovery.setStartTime(new Date());
        discovery.setStatus(DiscoveryStatus.IN_PROGRESS);
        discovery.setConnectorUuid(connector.getUuid());
        discovery.setKind(request.getKind());

        if (saveEntity) {
            discovery = discoveryRepository.save(discovery);
            attributeEngine.updateObjectCustomAttributesContent(Resource.DISCOVERY, discovery.getUuid(), request.getCustomAttributes());
            attributeEngine.updateObjectDataAttributesContent(connector.getUuid(), null, Resource.DISCOVERY, discovery.getUuid(), request.getAttributes());
            if (request.getTriggers() != null) {
                int triggerOrder = -1;
                for (UUID triggerUuid : request.getTriggers()) {
                    TriggerAssociation triggerAssociation = new TriggerAssociation();
                    triggerAssociation.setResource(Resource.DISCOVERY);
                    triggerAssociation.setObjectUuid(discovery.getUuid());
                    triggerAssociation.setTriggerUuid(triggerUuid);
                    Trigger trigger = triggerService.getTriggerEntity(triggerUuid.toString());
                    // If it is an ignore trigger, the order is always -1, otherwise increment the order
                    if (trigger.isIgnoreTrigger()) {
                        triggerAssociation.setTriggerOrder(-1);
                    } else {
                        triggerAssociation.setTriggerOrder(++triggerOrder);
                    }
                    triggerAssociationRepository.save(triggerAssociation);
                }
                discovery = discoveryRepository.findWithTriggersByUuid(discovery.getUuid());
            }
            return discovery.mapToDto();
        }

        return null;
    }

    @Override
    @Async("threadPoolTaskExecutor")
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.DISCOVERY, operation = OperationType.CREATE)
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.CREATE)
    public void runDiscoveryAsync(UUID discoveryUuid) {
        runDiscovery(discoveryUuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.CREATE)
    public DiscoveryHistoryDetailDto runDiscovery(UUID discoveryUuid) {
        UUID loggedUserUuid = UUID.fromString(AuthHelper.getUserIdentification().getUuid());

        // reload discovery modal with all association since it could be in separate transaction/session due to async
        DiscoveryHistory discovery = discoveryRepository.findWithTriggersByUuid(discoveryUuid);

        logger.info("Starting discovery: name={}, uuid={}", discovery.getName(), discovery.getUuid());
        try {
            DiscoveryRequestDto dtoRequest = new DiscoveryRequestDto();
            dtoRequest.setName(discovery.getName());
            dtoRequest.setKind(discovery.getKind());

            Connector connector = connectorService.getConnectorEntity(
                    SecuredUUID.fromString(discovery.getConnectorUuid().toString()));

            // TODO: necessary to load full credentials this way?
            // Load complete credential data
            var dataAttributes = attributeEngine.getDefinitionObjectAttributeContent(
                    AttributeType.DATA, connector.getUuid(), null, Resource.DISCOVERY, discovery.getUuid());
            credentialService.loadFullCredentialData(dataAttributes);
            dtoRequest.setAttributes(AttributeDefinitionUtils.getClientAttributes(dataAttributes));

            DiscoveryProviderDto response = discoveryApiClient.discoverCertificates(connector.mapToDto(), dtoRequest);

            logger.debug("Discovery response: name={}, uuid={}, status={}, total={}",
                    discovery.getName(), discovery.getUuid(), response.getStatus(), response.getTotalCertificatesDiscovered());

            discovery.setDiscoveryConnectorReference(response.getUuid());
            discoveryRepository.save(discovery);

            DiscoveryDataRequestDto getRequest = new DiscoveryDataRequestDto();
            getRequest.setName(response.getName());
            getRequest.setKind(discovery.getKind());
            getRequest.setPageNumber(1);
            getRequest.setItemsPerPage(MAXIMUM_CERTIFICATES_PER_PAGE);

            boolean waitForCompletion = checkForCompletion(response);
            boolean isReachedMaxTime = false;
            int oldCertificateCount = 0;
            while (waitForCompletion) {
                if (discovery.getDiscoveryConnectorReference() == null) {
                    discovery.setStatus(DiscoveryStatus.FAILED);
                    discovery.setMessage("Discovery does not have associated connector");
                    discoveryRepository.save(discovery);
                    return discovery.mapToDto();
                }
                logger.debug("Waiting {}ms for discovery to be completed: name={}, uuid={}",
                        SLEEP_TIME, discovery.getName(), discovery.getUuid());
                Thread.sleep(SLEEP_TIME);

                response = discoveryApiClient.getDiscoveryData(connector.mapToDto(), getRequest, response.getUuid());

                logger.debug("Discovery response: name={}, uuid={}, status={}, total={}",
                        discovery.getName(), discovery.getUuid(), response.getStatus(), response.getTotalCertificatesDiscovered());

                if ((discovery.getStartTime().getTime() - new Date().getTime()) / 1000 > MAXIMUM_WAIT_TIME
                        && !isReachedMaxTime && oldCertificateCount == response.getTotalCertificatesDiscovered()) {
                    isReachedMaxTime = true;
                    discovery.setStatus(DiscoveryStatus.WARNING);
                    discovery.setMessage(
                            "Discovery " + discovery.getName() + " exceeded maximum time of "
                                    + MAXIMUM_WAIT_TIME / (60 * 60) + " hours. There are no changes in number " +
                                    "of certificates discovered. Please abort the discovery if the provider " +
                                    "is stuck in state " + DiscoveryStatus.IN_PROGRESS.getLabel());
                    discoveryRepository.save(discovery);
                }

                oldCertificateCount = response.getTotalCertificatesDiscovered();
                waitForCompletion = checkForCompletion(response);
            }

            int currentPage = 1;
            int currentTotal = 0;
            Set<DiscoveryProviderCertificateDataDto> certificatesDiscovered = new HashSet<>();
            while (currentTotal < response.getTotalCertificatesDiscovered()) {
                getRequest.setPageNumber(currentPage);
                getRequest.setItemsPerPage(MAXIMUM_CERTIFICATES_PER_PAGE);
                response = discoveryApiClient.getDiscoveryData(connector.mapToDto(), getRequest, response.getUuid());

                if (response.getCertificateData().isEmpty()) {
                    discovery.setMessage(String.format("Retrieved only %d certificates but provider discovered %d " +
                            "certificates in total.", currentTotal, response.getTotalCertificatesDiscovered()));
                    break;
                }
                if (response.getCertificateData().size() > MAXIMUM_CERTIFICATES_PER_PAGE) {
                    updateDiscovery(discovery, response, DiscoveryStatus.FAILED);
                    logger.error("Too many content in response. Maximum processable is {}.", MAXIMUM_CERTIFICATES_PER_PAGE);
                    throw new InterruptedException(
                            "Too many content in response to process. Maximum processable is " + MAXIMUM_CERTIFICATES_PER_PAGE);
                }
                certificatesDiscovered.addAll(response.getCertificateData());

                ++currentPage;
                currentTotal += response.getCertificateData().size();
            }

            updateDiscovery(discovery, response, DiscoveryStatus.PROCESSING);
            updateCertificates(certificatesDiscovered, discovery);

            eventProducer.produceDiscoveryFinishedEventMessage(discovery.getUuid(), loggedUserUuid, ResourceEvent.DISCOVERY_FINISHED);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            discovery.setStatus(DiscoveryStatus.FAILED);
            discovery.setMessage(e.getMessage());
            discoveryRepository.save(discovery);
            logger.error(e.getMessage());
        } catch (Exception e) {
            discovery.setStatus(DiscoveryStatus.FAILED);
            discovery.setMessage(e.getMessage());
            discoveryRepository.save(discovery);
            logger.error(e.getMessage());
        }

        if (discovery.getStatus() != DiscoveryStatus.PROCESSING) {
            notificationProducer.produceNotificationText(Resource.DISCOVERY, discovery.getUuid(), NotificationRecipient.buildUserNotificationRecipient(loggedUserUuid), String.format("Discovery %s has finished with status %s", discovery.getName(), discovery.getStatus()), discovery.getMessage());
        }

        return discovery.mapToDto();
    }

    private void updateDiscovery(DiscoveryHistory modal, DiscoveryProviderDto response, DiscoveryStatus status) throws AttributeException {
        modal.setStatus(status);
        modal.setEndTime(new Date());
        modal.setTotalCertificatesDiscovered(response.getTotalCertificatesDiscovered());
        attributeEngine.updateMetadataAttributes(response.getMeta(), new ObjectAttributeContentInfo(modal.getConnectorUuid(), Resource.DISCOVERY, modal.getUuid()));
        discoveryRepository.save(modal);
    }

    private boolean checkForCompletion(DiscoveryProviderDto response) {
        return response.getStatus() == DiscoveryStatus.IN_PROGRESS;
    }

    private void updateCertificates(Set<DiscoveryProviderCertificateDataDto> certificatesDiscovered,
                                    DiscoveryHistory modal) {
        if (certificatesDiscovered.isEmpty()) {
            logger.warn("No certificates were given by the provider for the discovery");
            return;
        }

        for (DiscoveryProviderCertificateDataDto certificate : certificatesDiscovered) {
            try {
                X509Certificate x509Cert = CertificateUtil.parseCertificate(certificate.getBase64Content());
                boolean existingCertificate = certificateRepository.existsByFingerprint(CertificateUtil.getThumbprint(x509Cert.getEncoded()));
                Certificate entry = certificateService.createCertificateEntity(x509Cert);
                createDiscoveryCertificate(entry, modal, !existingCertificate, certificate.getMeta());
            } catch (Exception e) {
                logger.error(e.getMessage());
                logger.error("Unable to create certificate for {}", modal);
            }
        }
    }

    private void createDiscoveryCertificate(Certificate entry, DiscoveryHistory modal, boolean newlyDiscovered, List<MetadataAttribute> meta) {
        DiscoveryCertificate discoveryCertificate = new DiscoveryCertificate();
        discoveryCertificate.setCommonName(entry.getCommonName());
        discoveryCertificate.setSerialNumber(entry.getSerialNumber());
        discoveryCertificate.setIssuerCommonName(entry.getIssuerCommonName());
        discoveryCertificate.setNotAfter(entry.getNotAfter());
        discoveryCertificate.setNotBefore(entry.getNotBefore());
        discoveryCertificate.setCertificateContent(entry.getCertificateContent());
        discoveryCertificate.setDiscovery(modal);
        discoveryCertificate.setNewlyDiscovered(newlyDiscovered);
        discoveryCertificate.setMeta(meta);
        discoveryCertificateRepository.save(discoveryCertificate);
    }

    @Override
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter) {
        return Collections.emptyList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getDiscoveryEntity(uuid);
    }

    @Override
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup() {
        final List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine.getResourceSearchableFields(Resource.DISCOVERY, false);

        List<SearchFieldDataDto> fields = List.of(
                SearchHelper.prepareSearch(SearchFieldNameEnum.NAME),
                SearchHelper.prepareSearch(SearchFieldNameEnum.DISCOVERY_STATUS, Arrays.stream(DiscoveryStatus.values()).map(DiscoveryStatus::getCode).toList()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.START_TIME),
                SearchHelper.prepareSearch(SearchFieldNameEnum.END_TIME),
                SearchHelper.prepareSearch(SearchFieldNameEnum.TOTAL_CERT_DISCOVERED),
                SearchHelper.prepareSearch(SearchFieldNameEnum.CONNECTOR_NAME, discoveryRepository.findDistinctConnectorName()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.KIND)
        );

        fields = new ArrayList<>(fields);
        fields.sort(new SearchFieldDataComparator());

        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));

        logger.debug("Searchable Fields by Groups: {}", searchFieldDataByGroupDtos);
        return searchFieldDataByGroupDtos;
    }

    @Override
    public void evaluateDiscoveryTriggers(UUID discoveryUuid, UUID userUuid) throws RuleException {
        // Get newly discovered certificates
        DiscoveryHistory discovery = discoveryRepository.findWithTriggersByUuid(discoveryUuid);
        List<DiscoveryCertificate> discoveredCertificates = discoveryCertificateRepository.findByDiscoveryAndNewlyDiscovered(discovery, true, Pageable.unpaged());
        // Get triggers for the discovery, separately for triggers with ignore action, the rest of triggers are in given order
        List<TriggerAssociation> triggerAssociations = triggerAssociationRepository.findAllByResourceAndObjectUuidOrderByTriggerOrderAsc(Resource.DISCOVERY, discoveryUuid);
        List<Trigger> orderedTriggers = new ArrayList<>();
        List<Trigger> ignoreTriggers = new ArrayList<>();
        for (TriggerAssociation triggerAssociation : triggerAssociations) {
            try {
                Trigger trigger = triggerService.getTriggerEntity(String.valueOf(triggerAssociation.getTriggerUuid()));
                if (triggerAssociation.getTriggerOrder() == -1) {
                    ignoreTriggers.add(trigger);
                } else {
                    orderedTriggers.add(trigger);
                }
            } catch (NotFoundException e) {
                logger.error(e.getMessage());
            }
        }

        // For each discovered certificate and for each found trigger, check if it satisfies rules defined by the trigger and perform actions accordingly
        for (DiscoveryCertificate discoveryCertificate : discoveredCertificates) {
            try {
                processDiscoveredCertificate(discovery, discoveryCertificate, ignoreTriggers, orderedTriggers);
            } catch (Exception e) {
                logger.warn("Couldn't process discovered certificate {}. Error: {}", discoveryCertificate, e.getMessage());
            }
        }

        discovery.setStatus(DiscoveryStatus.COMPLETED);
        discoveryRepository.save(discovery);

        notificationProducer.produceNotificationText(Resource.DISCOVERY, discovery.getUuid(), NotificationRecipient.buildUserNotificationRecipient(userUuid), String.format("Discovery %s has finished with status %s", discovery.getName(), discovery.getStatus()), discovery.getMessage());
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void processDiscoveredCertificate(DiscoveryHistory discovery, DiscoveryCertificate discoveryCertificate, List<Trigger> ignoreTriggers, List<Trigger> orderedTriggers) throws RuleException {
        // Get X509 from discovered certificate and create certificate entity, do not save in database yet
        Certificate entry;
        X509Certificate x509Cert;
        try {
            x509Cert = CertificateUtil.parseCertificate(discoveryCertificate.getCertificateContent().getContent());
            entry = certificateService.createCertificateEntity(x509Cert);
        } catch (java.security.cert.CertificateException e) {
            logger.error("Unable to create certificate from discovery certificate with UUID {}.", discoveryCertificate.getUuid());
            return;
        }

        // First, check the triggers that have action with action type set to ignore
        boolean ignored = false;
        List<TriggerHistory> ignoreTriggerHistories = new ArrayList<>();
        for (Trigger trigger : ignoreTriggers) {
            TriggerHistory triggerHistory = triggerService.createTriggerHistory(OffsetDateTime.now(), trigger.getUuid(), discovery.getUuid(), null, discoveryCertificate.getUuid());
            if (certificateRuleEvaluator.evaluateRules(trigger.getRules(), entry, triggerHistory)) {
                ignored = true;
                triggerHistory.setConditionsMatched(true);
                triggerHistory.setActionsPerformed(true);
                break;
            } else {
                triggerHistory.setConditionsMatched(false);
                triggerHistory.setActionsPerformed(false);
            }
            ignoreTriggerHistories.add(triggerHistory);
        }

        // If some trigger ignored this certificate, certificate is not saved and continue with next one
        if (ignored) {
            return;
        }

        // Save certificate to database
        certificateService.updateCertificateEntity(entry);

        // update objectUuid of not ignored certs
        for (TriggerHistory ignoreTriggerHistory : ignoreTriggerHistories) {
            ignoreTriggerHistory.setObjectUuid(entry.getUuid());
        }

        // Evaluate rest of the triggers in given order
        for (Trigger trigger : orderedTriggers) {
            // Create trigger history entry
            TriggerHistory triggerHistory = triggerService.createTriggerHistory(OffsetDateTime.now(), trigger.getUuid(), discovery.getUuid(), entry.getUuid(), discoveryCertificate.getUuid());
            // If rules are satisfied, perform defined actions
            if (certificateRuleEvaluator.evaluateRules(trigger.getRules(), entry, triggerHistory)) {
                triggerHistory.setConditionsMatched(true);
                certificateRuleEvaluator.performActions(trigger, entry, triggerHistory);
                triggerHistory.setActionsPerformed(triggerHistory.getRecords().isEmpty());
            } else {
                triggerHistory.setConditionsMatched(false);
                triggerHistory.setActionsPerformed(false);
            }
        }

        // Set metadata attributes, create certificate event history entry and validate certificate
        try {
            attributeEngine.updateMetadataAttributes(discoveryCertificate.getMeta(), new ObjectAttributeContentInfo(discovery.getConnectorUuid(), Resource.CERTIFICATE, entry.getUuid(), Resource.DISCOVERY, discovery.getUuid(), discovery.getName()));
        } catch (AttributeException e) {
            logger.error("Could not update metadata for discovery certificate {}.", discoveryCertificate.getUuid());
        }
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put("Discovery Name", discovery.getName());
        additionalInfo.put("Discovery UUID", discovery.getUuid());
        additionalInfo.put("Discovery Connector Name", discovery.getConnectorName());
        additionalInfo.put("Discovery Kind", discovery.getKind());
        certificateEventHistoryService.addEventHistory(
                entry.getUuid(),
                CertificateEvent.DISCOVERY,
                CertificateEventStatus.SUCCESS,
                "Discovered from Connector: " + discovery.getConnectorName() + " via discovery: " + discovery.getName(),
                MetaDefinitions.serialize(additionalInfo)
        );
        certificateService.validate(entry);
    }
}
