package com.czertainly.core.service.impl;

import com.czertainly.api.clients.EntityInstanceApiClient;
import com.czertainly.api.clients.LocationApiClient;
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
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.common.attribute.v2.MetadataAttribute;
import com.czertainly.api.model.connector.entity.*;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateEvent;
import com.czertainly.api.model.core.certificate.CertificateEventStatus;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateType;
import com.czertainly.api.model.core.connector.ConnectorDto;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.enums.CertificateRequestFormat;
import com.czertainly.api.model.core.location.LocationDto;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.v2.ClientCertificateDataResponseDto;
import com.czertainly.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.czertainly.api.model.core.v2.ClientCertificateSignRequestDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.comparator.SearchFieldDataComparator;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.CertificateLocationRepository;
import com.czertainly.core.dao.repository.EntityInstanceReferenceRepository;
import com.czertainly.core.dao.repository.LocationRepository;
import com.czertainly.core.dao.repository.RaProfileRepository;
import com.czertainly.core.enums.SearchFieldNameEnum;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.CertificateEventHistoryService;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.LocationService;
import com.czertainly.core.service.PermissionEvaluator;
import com.czertainly.core.service.v2.ClientOperationService;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.core.util.RequestValidatorHelper;
import com.czertainly.core.util.SearchHelper;
import com.czertainly.core.util.converter.Sql2PredicateConverter;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.transaction.Transactional;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.BiFunction;

@Service
@Transactional
public class LocationServiceImpl implements LocationService {

    private static final Logger logger = LoggerFactory.getLogger(LocationServiceImpl.class);

    private LocationRepository locationRepository;
    private EntityInstanceReferenceRepository entityInstanceReferenceRepository;
    private CertificateLocationRepository certificateLocationRepository;
    private RaProfileRepository raProfileRepository;
    private EntityInstanceApiClient entityInstanceApiClient;
    private LocationApiClient locationApiClient;
    private CertificateService certificateService;
    private ClientOperationService clientOperationService;
    private CertificateEventHistoryService certificateEventHistoryService;
    private AttributeEngine attributeEngine;
    private PermissionEvaluator permissionEvaluator;

    @Autowired
    public void setEntityInstanceReferenceRepository(EntityInstanceReferenceRepository entityInstanceReferenceRepository) {
        this.entityInstanceReferenceRepository = entityInstanceReferenceRepository;
    }

    @Autowired
    public void setLocationRepository(LocationRepository locationRepository) {
        this.locationRepository = locationRepository;
    }

    @Autowired
    public void setCertificateLocationRepository(CertificateLocationRepository certificateLocationRepository) {
        this.certificateLocationRepository = certificateLocationRepository;
    }

    @Autowired
    public void setRaProfileRepository(RaProfileRepository raProfileRepository) {
        this.raProfileRepository = raProfileRepository;
    }

    @Autowired
    public void setEntityInstanceApiClient(EntityInstanceApiClient entityInstanceApiClient) {
        this.entityInstanceApiClient = entityInstanceApiClient;
    }

    @Autowired
    public void setLocationApiClient(LocationApiClient locationApiClient) {
        this.locationApiClient = locationApiClient;
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setClientOperationService(ClientOperationService clientOperationService) {
        this.clientOperationService = clientOperationService;
    }

    @Autowired
    public void setCertificateEventHistoryService(CertificateEventHistoryService certificateEventHistoryService) {
        this.certificateEventHistoryService = certificateEventHistoryService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
        this.permissionEvaluator = permissionEvaluator;
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.RA_PROFILE, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.LOCATION, action = ResourceAction.LIST)
    public LocationsResponseDto listLocations(SecurityFilter filter, SearchRequestDto request) {

        RequestValidatorHelper.revalidateSearchRequestDto(request);
        final Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());

        // filter locations based on attribute filters
        final List<UUID> objectUUIDs = attributeEngine.getResourceObjectUuidsByFilters(Resource.LOCATION, filter, request.getFilters());

        final BiFunction<Root<Location>, CriteriaBuilder, Predicate> additionalWhereClause = (root, cb) -> Sql2PredicateConverter.mapSearchFilter2Predicates(request.getFilters(), cb, root, objectUUIDs);
        final List<LocationDto> listedKeyDTOs = locationRepository.findUsingSecurityFilter(filter, List.of("certificates", "certificates.certificate"), additionalWhereClause, p, (root, cb) -> cb.desc(root.get("created")))
                .stream()
                .map(Location::mapToDto).toList();
        final Long maxItems = locationRepository.countUsingSecurityFilter(filter, additionalWhereClause);

        final LocationsResponseDto responseDto = new LocationsResponseDto();
        responseDto.setLocations(listedKeyDTOs);
        responseDto.setItemsPerPage(request.getItemsPerPage());
        responseDto.setPageNumber(request.getPageNumber());
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / request.getItemsPerPage()));
        return responseDto;
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.RA_PROFILE, operation = OperationType.CREATE)
    @ExternalAuthorization(resource = Resource.LOCATION, action = ResourceAction.CREATE, parentResource = Resource.ENTITY, parentAction = ResourceAction.DETAIL)
    public LocationDto addLocation(SecuredParentUUID entityUuid, AddLocationRequestDto dto) throws AlreadyExistException, LocationException, ConnectorException, AttributeException {
        if (StringUtils.isBlank(dto.getName())) {
            throw new ValidationException(ValidationError.create("Location name must not be empty"));
        }

        Optional<Location> o = locationRepository.findByName(dto.getName());
        if (o.isPresent()) {
            throw new AlreadyExistException(Location.class, dto.getName());
        }

        EntityInstanceReference entityInstanceRef = entityInstanceReferenceRepository.findByUuid(entityUuid).orElseThrow(() -> new NotFoundException(EntityInstanceReference.class, entityUuid));
        validateLocationCreation(entityInstanceRef, dto.getAttributes());
        attributeEngine.validateCustomAttributesContent(Resource.LOCATION, dto.getCustomAttributes());
        mergeAndValidateAttributes(entityInstanceRef, dto.getAttributes());

        LocationDetailResponseDto locationDetailResponseDto = getLocationDetail(entityInstanceRef, dto.getAttributes(), dto.getName());
        Location location;
        try {
            location = createLocation(dto, entityInstanceRef, locationDetailResponseDto);
        } catch (CertificateException e) {
            logger.debug("Failed to create Location {}: {}", dto.getName(), e.getMessage());
            throw new LocationException("Failed to create Location " + dto.getName());
        }

        logger.info("Location with name {} and UUID {} created", location.getName(), location.getUuid());

        LocationDto locationDto = location.mapToDto();
        locationDto.setMetadata(attributeEngine.getMappedMetadataContent(new ObjectAttributeContentInfo(Resource.LOCATION, location.getUuid())));
        locationDto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.LOCATION, location.getUuid(), dto.getCustomAttributes()));
        locationDto.setAttributes(attributeEngine.updateObjectDataAttributesContent(entityInstanceRef.getConnectorUuid(), null, Resource.LOCATION, location.getUuid(), dto.getAttributes()));
        locationDto.getCertificates().forEach(e -> e.setMetadata(attributeEngine.getMappedMetadataContent(new ObjectAttributeContentInfo(entityInstanceRef.getConnectorUuid(), Resource.CERTIFICATE, UUID.fromString(e.getCertificateUuid()), Resource.LOCATION, location.getUuid()))));

        return locationDto;
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.RA_PROFILE, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.LOCATION, action = ResourceAction.DETAIL, parentResource = Resource.ENTITY, parentAction = ResourceAction.DETAIL)
    public LocationDto getLocation(SecuredParentUUID entityUuid, SecuredUUID locationUuid) throws NotFoundException {
        Location location = locationRepository.findByUuid(locationUuid)
                .orElseThrow(() -> new NotFoundException(Location.class, locationUuid));
        LocationDto dto = location.mapToDto();
        dto.setMetadata(attributeEngine.getMappedMetadataContent(new ObjectAttributeContentInfo(Resource.LOCATION, location.getUuid())));
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.LOCATION, location.getUuid()));
        dto.setAttributes(attributeEngine.getObjectDataAttributesContent(location.getEntityInstanceReference().getConnectorUuid(), null, Resource.LOCATION, location.getUuid()));
        dto.getCertificates().forEach(e -> e.setMetadata(attributeEngine.getMappedMetadataContent(new ObjectAttributeContentInfo(Resource.CERTIFICATE, UUID.fromString(e.getCertificateUuid()), Resource.LOCATION, location.getUuid()))));
        return dto;
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.RA_PROFILE, operation = OperationType.CHANGE)
    @ExternalAuthorization(resource = Resource.LOCATION, action = ResourceAction.UPDATE, parentResource = Resource.ENTITY, parentAction = ResourceAction.DETAIL)
    public LocationDto editLocation(SecuredParentUUID entityUuid, SecuredUUID locationUuid, EditLocationRequestDto dto) throws ConnectorException, LocationException, AttributeException {
        Location location = locationRepository.findByUuid(locationUuid)
                .orElseThrow(() -> new NotFoundException(Location.class, locationUuid));

        EntityInstanceReference entityInstanceRef = entityInstanceReferenceRepository.findByUuid(entityUuid).orElseThrow(() -> new NotFoundException(EntityInstanceReference.class, entityUuid));
        attributeEngine.validateCustomAttributesContent(Resource.LOCATION, dto.getCustomAttributes());
        mergeAndValidateAttributes(entityInstanceRef, dto.getAttributes());

        LocationDetailResponseDto locationDetailResponseDto = getLocationDetail(entityInstanceRef, dto.getAttributes(), location.getName());

        try {
            updateLocation(location, entityInstanceRef, dto, locationDetailResponseDto);
        } catch (CertificateException e) {
            logger.debug("Failed to update Location {}, {} content: {}", location.getName(), location.getUuid(), e.getMessage());
            throw new LocationException("Failed to update Location content: " + location.getName() + ", " + location.getUuid());
        }

        logger.info("Location with name {} and UUID {} updated", location.getName(), location.getUuid());

        LocationDto locationDto = location.mapToDto();
        locationDto.setMetadata(attributeEngine.getMappedMetadataContent(new ObjectAttributeContentInfo(Resource.LOCATION, location.getUuid())));
        locationDto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.LOCATION, location.getUuid(), dto.getCustomAttributes()));
        locationDto.setAttributes(attributeEngine.updateObjectDataAttributesContent(entityInstanceRef.getConnectorUuid(), null, Resource.LOCATION, location.getUuid(), dto.getAttributes()));
        locationDto.getCertificates().forEach(e -> e.setMetadata(attributeEngine.getMappedMetadataContent(new ObjectAttributeContentInfo(entityInstanceRef.getConnectorUuid(), Resource.CERTIFICATE, UUID.fromString(e.getCertificateUuid()), Resource.LOCATION, location.getUuid()))));
        return locationDto;
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.RA_PROFILE, operation = OperationType.DELETE)
    @ExternalAuthorization(resource = Resource.LOCATION, action = ResourceAction.DELETE, parentResource = Resource.ENTITY, parentAction = ResourceAction.DETAIL)
    public void deleteLocation(SecuredParentUUID entityUuid, SecuredUUID locationUuid) throws NotFoundException {
        Location location = locationRepository.findByUuid(locationUuid)
                .orElseThrow(() -> new NotFoundException(Location.class, locationUuid));

        certificateLocationRepository.deleteAll(location.getCertificates());
        attributeEngine.deleteAllObjectAttributeContent(Resource.LOCATION, location.getUuid());
        locationRepository.delete(location);

        logger.info("Location {} was deleted", location.getName());
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.RA_PROFILE, operation = OperationType.ENABLE)
    @ExternalAuthorization(resource = Resource.LOCATION, action = ResourceAction.ENABLE, parentResource = Resource.ENTITY, parentAction = ResourceAction.DETAIL)
    public void enableLocation(SecuredParentUUID entityUuid, SecuredUUID locationUuid) throws NotFoundException {
        Location location = locationRepository.findByUuid(locationUuid)
                .orElseThrow(() -> new NotFoundException(Location.class, locationUuid));

        location.setEnabled(true);
        locationRepository.save(location);

        logger.info("Location {} enabled", location.getName());
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.RA_PROFILE, operation = OperationType.DISABLE)
    @ExternalAuthorization(resource = Resource.LOCATION, action = ResourceAction.ENABLE, parentResource = Resource.ENTITY, parentAction = ResourceAction.DETAIL)
    public void disableLocation(SecuredParentUUID entityUuid, SecuredUUID locationUuid) throws NotFoundException {
        Location location = locationRepository.findByUuid(locationUuid)
                .orElseThrow(() -> new NotFoundException(Location.class, locationUuid));

        location.setEnabled(false);
        locationRepository.save(location);

        logger.info("Location {} disabled", location.getName());
    }

    @Override
    @ExternalAuthorization(resource = Resource.LOCATION, action = ResourceAction.ANY, parentResource = Resource.ENTITY, parentAction = ResourceAction.ANY)
    public List<BaseAttribute> listPushAttributes(SecuredParentUUID entityUuid, SecuredUUID locationUuid) throws NotFoundException, LocationException {
        Location location = locationRepository.findByUuidAndEnabledIsTrue(locationUuid.getValue())
                .orElseThrow(() -> new NotFoundException(Location.class, locationUuid));

        try {
            return locationApiClient.listPushCertificateAttributes(
                    location.getEntityInstanceReference().getConnector().mapToDto(),
                    location.getEntityInstanceReference().getEntityInstanceUuid());
        } catch (ConnectorException e) {
            logger.debug("Failed to list push Attributes for Location {}, {}: {}",
                    location.getName(), location.getUuid(), e.getMessage());
            throw new LocationException("Failed to list push Attributes for the Location " + location.getName() + ". Reason: " + e.getMessage());
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.LOCATION, action = ResourceAction.ANY, parentResource = Resource.ENTITY, parentAction = ResourceAction.ANY)
    public List<BaseAttribute> listCsrAttributes(SecuredParentUUID entityUuid, SecuredUUID locationUuid) throws NotFoundException, LocationException {
        Location location = locationRepository.findByUuidAndEnabledIsTrue(locationUuid.getValue())
                .orElseThrow(() -> new NotFoundException(Location.class, locationUuid));

        try {
            return locationApiClient.listGenerateCsrAttributes(
                    location.getEntityInstanceReference().getConnector().mapToDto(),
                    location.getEntityInstanceReference().getEntityInstanceUuid());
        } catch (ConnectorException e) {
            logger.debug("Failed to list CSR Attributes for Location {}, {}: {}",
                    location.getName(), location.getUuid(), e.getMessage());
            throw new LocationException("Failed to list CSR Attributes for the Location " + location.getName() + ". Reason: " + e.getMessage());
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.LOCATION, action = ResourceAction.UPDATE, parentResource = Resource.ENTITY, parentAction = ResourceAction.DETAIL)
    public LocationDto removeCertificateFromLocation(SecuredParentUUID entityUuid, SecuredUUID locationUuid, String certificateUuid) throws NotFoundException, LocationException {
        Location location = locationRepository.findByUuidAndEnabledIsTrue(locationUuid.getValue())
                .orElseThrow(() -> new NotFoundException(Location.class, locationUuid));

        Certificate certificate = certificateService.getCertificateEntity(SecuredUUID.fromString(certificateUuid));

        CertificateLocationId clId = new CertificateLocationId(location.getUuid(), certificate.getUuid());
        CertificateLocation certificateInLocation = certificateLocationRepository.findById(clId)
                .orElseThrow(() -> new NotFoundException(CertificateLocation.class, clId));

        try {
            removeCertificateFromLocation(certificateInLocation);
        } catch (ConnectorException e) {
            // record event in the certificate history
            String message = "Remove from Location " + location.getName();
            HashMap<String, Object> additionalInformation = new HashMap<>();
            additionalInformation.put("locationUuid", location.getUuid());
            additionalInformation.put("cause", message);
            certificateEventHistoryService.addEventHistory(
                    certificate.getUuid(),
                    CertificateEvent.UPDATE_LOCATION,
                    CertificateEventStatus.FAILED,
                    message,
                    additionalInformation
            );
            logger.debug("Failed to remove Certificate {} from Location {},{}: {}", certificate.getUuid(),
                    location.getName(), location.getUuid(), e.getMessage());
            throw new LocationException("Failed to remove Certificate " + certificate.getUuid() +
                    " from Location " + location.getName() + ". Reason: " + e.getMessage());
        }

        // save record into the certificate history
        String message = "Removed from Location " + location.getName();
        HashMap<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put("locationUuid", location.getUuid());
        certificateEventHistoryService.addEventHistory(
                certificate.getUuid(),
                CertificateEvent.UPDATE_LOCATION,
                CertificateEventStatus.SUCCESS,
                message,
                additionalInformation
        );

        logger.info("Certificate {} removed from Location {}", certificateUuid, location.getName());
        LocationDto locationDto = location.mapToDto();
        locationDto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.LOCATION, location.getUuid()));
        locationDto.getCertificates().forEach(e -> e.setMetadata(attributeEngine.getMappedMetadataContent(new ObjectAttributeContentInfo(Resource.CERTIFICATE, UUID.fromString(e.getCertificateUuid()), Resource.LOCATION, location.getUuid()))));
        return locationDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.LOCATION, action = ResourceAction.UPDATE)
    // TODO List locations using LocationService in CertificateService and then call removeCertificateFromLocations(SecuredUUID locationUUIDs, String certificateUUID) on location service
    public void removeCertificateFromLocations(SecuredUUID certificateUuid) throws NotFoundException {
        Certificate certificate = certificateService.getCertificateEntity(certificateUuid);

        Set<CertificateLocation> certificateLocations = certificate.getLocations();
        for (CertificateLocation cl : certificateLocations) {
            try {
                if (!cl.getLocation().getEnabled()) {
                    throw new NotFoundException(Location.class, cl.getLocation().getUuid());
                }

                removeCertificateFromLocation(cl);
                certificateLocations.remove(cl);

                // save record into the certificate history
                String message = "Removed from Location " + cl.getLocation().getName();
                HashMap<String, Object> additionalInformation = new HashMap<>();
                additionalInformation.put("locationUuid", cl.getLocation().getUuid());
                certificateEventHistoryService.addEventHistory(
                        certificate.getUuid(),
                        CertificateEvent.UPDATE_LOCATION,
                        CertificateEventStatus.SUCCESS,
                        message,
                        additionalInformation
                );

                logger.info("Certificate {} removed from Location {}", certificateUuid, cl.getLocation().getName());
            } catch (ConnectorException e) {
                // record event in the certificate history
                String message = "Remove from Location " + cl.getLocation().getName();
                HashMap<String, Object> additionalInformation = new HashMap<>();
                additionalInformation.put("locationUuid", cl.getLocation().getUuid());
                additionalInformation.put("cause", message);
                certificateEventHistoryService.addEventHistory(
                        certificate.getUuid(),
                        CertificateEvent.UPDATE_LOCATION,
                        CertificateEventStatus.FAILED,
                        message,
                        additionalInformation
                );
                logger.debug("Failed to remove Certificate {} from Location {}, {}: {}", certificate.getUuid(),
                        cl.getLocation().getName(), cl.getLocation().getUuid(), e.getMessage());
            }
        }
    }

    @Override
    public void removeRejectedCertificateFromLocationAction(CertificateLocationId certificateLocationId) throws ConnectorException {
        CertificateLocation certificateLocation = certificateLocationRepository.findById(certificateLocationId).orElseThrow(() -> new NotFoundException(CertificateLocation.class, certificateLocationId));
        Certificate certificate = certificateLocation.getCertificate();
        Location location = certificateLocation.getLocation();

        List<MetadataAttribute> metadata = attributeEngine.getMetadataAttributesDefinitionContent(new ObjectAttributeContentInfo(
                certificateLocation.getLocation().getEntityInstanceReference().getConnectorUuid(),
                Resource.CERTIFICATE, certificate.getUuid(),
                Resource.LOCATION, location.getUuid()));

        removeStash(location, metadata);

        certificateLocationRepository.delete(certificateLocation);

        attributeEngine.deleteObjectAttributesContent(AttributeType.META, new ObjectAttributeContentInfo(
                certificateLocation.getLocation().getEntityInstanceReference().getConnectorUuid(),
                Resource.CERTIFICATE, certificate.getUuid(),
                Resource.LOCATION, location.getUuid()));

        location.getCertificates().remove(certificateLocation);

        locationRepository.save(location);
        logger.debug("Removed rejected certificate {} from location {}", certificate, location.getName());
    }

    @Override
    @ExternalAuthorization(resource = Resource.LOCATION, action = ResourceAction.UPDATE, parentResource = Resource.ENTITY, parentAction = ResourceAction.DETAIL)
    public LocationDto pushCertificateToLocation(SecuredParentUUID entityUuid, SecuredUUID locationUuid, String certificateUuid, PushToLocationRequestDto request) throws NotFoundException, LocationException, AttributeException {
        Location location = locationRepository.findByUuidAndEnabledIsTrue(locationUuid.getValue())
                .orElseThrow(() -> new NotFoundException(Location.class, locationUuid));

        Certificate certificate = certificateService.getCertificateEntity(SecuredUUID.fromString(certificateUuid));

        if (certificate.getState().equals(CertificateState.REJECTED)) {
            throw new ValidationException(ValidationError.create("Cannot push rejected certificate %s to location %s".formatted(certificate, location.getName())));
        }

        if (!location.isSupportMultipleEntries() && !location.getCertificates().isEmpty()) {
            // record event in the certificate history
            String message = "Location " + location.getName() + " does not support multiple entries";
            HashMap<String, Object> additionalInformation = new HashMap<>();
            additionalInformation.put("locationUuid", location.getUuid());
            additionalInformation.put("cause", message);
            certificateEventHistoryService.addEventHistory(
                    certificate.getUuid(),
                    CertificateEvent.UPDATE_LOCATION,
                    CertificateEventStatus.FAILED,
                    message,
                    additionalInformation
            );
            logger.debug("Location {}, {} does not support multiple entries", location.getName(), location.getUuid());
            throw new LocationException("Location " + location.getName() + " does not support multiple entries");
        }

        // not yet issued certificate
        if (certificate.getCertificateContent() == null) {
            addCertificateToLocation(location, certificate, request.getAttributes(), List.of(), List.of());
            logger.info("Certificate {} is added to location {} and prepared to be pushed after issue", certificate, location.getName());
        } else {
            pushCertificateToLocation(
                    location, certificate,
                    request.getAttributes(), List.of());
            logger.info("Certificate {} successfully pushed to Location {}", certificate, location.getName());
        }

        final LocationDto dto = location.mapToDto();
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.LOCATION, location.getUuid()));
        dto.getCertificates().forEach(e -> e.setMetadata(attributeEngine.getMappedMetadataContent(new ObjectAttributeContentInfo(Resource.CERTIFICATE, UUID.fromString(e.getCertificateUuid()), Resource.LOCATION, location.getUuid()))));
        return dto;
    }

    public void pushRequestedCertificateToLocationAction(CertificateLocationId certificateLocationId, boolean isRenewal) throws NotFoundException, LocationException, AttributeException {
        CertificateLocation certificateLocation = certificateLocationRepository.findById(certificateLocationId).orElseThrow(() -> new NotFoundException(CertificateLocation.class, certificateLocationId));
        Certificate certificate = certificateLocation.getCertificate();
        Location location = certificateLocation.getLocation();

        PushCertificateRequestDto pushCertificateRequestDto = new PushCertificateRequestDto();
        pushCertificateRequestDto.setCertificate(certificate.getCertificateContent().getContent());
        // TODO: support for different types of certificate
        pushCertificateRequestDto.setCertificateType(CertificateType.X509);
        pushCertificateRequestDto.setLocationAttributes(attributeEngine.getRequestObjectDataAttributesContent(location.getEntityInstanceReference().getConnectorUuid(), null, Resource.LOCATION, location.getUuid()));
        pushCertificateRequestDto.setPushAttributes(AttributeDefinitionUtils.getClientAttributes(certificateLocation.getPushAttributes()));

        PushCertificateResponseDto pushCertificateResponseDto;
        try {
            pushCertificateResponseDto = locationApiClient.pushCertificateToLocation(
                    location.getEntityInstanceReference().getConnector().mapToDto(),
                    location.getEntityInstanceReference().getEntityInstanceUuid(),
                    pushCertificateRequestDto
            );
        } catch (ConnectorException e) {
            // record event in the certificate history
            String message = "Failed to push to Location " + location.getName();
            HashMap<String, Object> additionalInformation = new HashMap<>();
            additionalInformation.put("locationUuid", location.getUuid());
            additionalInformation.put("cause", e.getMessage());
            certificateEventHistoryService.addEventHistory(
                    certificate.getUuid(),
                    CertificateEvent.UPDATE_LOCATION,
                    CertificateEventStatus.FAILED,
                    message,
                    additionalInformation
            );

            throw new LocationException("Failed to push Certificate " + certificate.getUuid() +
                    " to Location " + location.getName() + ". Reason: " + e.getMessage());
        }

        certificateLocation.setWithKey(pushCertificateResponseDto.isWithKey());
        certificateLocationRepository.save(certificateLocation);
        attributeEngine.updateMetadataAttributes(pushCertificateResponseDto.getCertificateMetadata(), new ObjectAttributeContentInfo(location.getEntityInstanceReference().getConnectorUuid(), Resource.CERTIFICATE, certificate.getUuid(), Resource.LOCATION, location.getUuid(), location.getName()));

        // TODO: response with the indication if the key is available for pushed certificate

        // save record into the certificate history
        String message = "Pushed to Location " + location.getName();
        HashMap<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put("locationUuid", location.getUuid());
        certificateEventHistoryService.addEventHistory(
                certificate.getUuid(),
                CertificateEvent.UPDATE_LOCATION,
                CertificateEventStatus.SUCCESS,
                message,
                additionalInformation
        );

        if (isRenewal) {
            //Delete current certificate in location table
            CertificateLocationId clId = new CertificateLocationId(location.getUuid(), certificate.getSourceCertificateUuid());
            CertificateLocation certificateInLocation = certificateLocationRepository.findById(clId)
                    .orElse(null);

            if (certificateInLocation != null) {
                certificateLocationRepository.delete(certificateInLocation);
                location.getCertificates().remove(certificateLocation);
                locationRepository.save(location);
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.LOCATION, action = ResourceAction.UPDATE, parentResource = Resource.ENTITY, parentAction = ResourceAction.DETAIL)
    public LocationDto issueCertificateToLocation(SecuredParentUUID entityUuid, SecuredUUID locationUuid, String raProfileUuid, IssueToLocationRequestDto request) throws ConnectorException, LocationException {
        Location location = locationRepository.findByUuidAndEnabledIsTrue(locationUuid.getValue())
                .orElseThrow(() -> new NotFoundException(Location.class, locationUuid));

        if (!location.isSupportKeyManagement()) {
            logger.debug("Location {}, {} does not support key management", location.getName(), location.getUuid());
            throw new LocationException("Location " + location.getName() + " does not support key management");
        }
        if (!location.isSupportMultipleEntries() && !location.getCertificates().isEmpty()) {
            logger.debug("Location {}, {} does not support multiple entries", location.getName(), location.getUuid());
            throw new LocationException("Location " + location.getName() + " does not support multiple entries");
        }
        RaProfile raProfile = raProfileRepository.findByUuid(UUID.fromString(raProfileUuid)).orElseThrow(() -> new NotFoundException(raProfileUuid, RaProfile.class));
        authorityPreChecks(raProfile);
        // generate new CSR
        GenerateCsrResponseDto generateCsrResponseDto = generateCsrLocation(location, request.getCsrAttributes(), false);
        logger.info("Received certificate signing request from Location {}", location.getName());

        // issue new Certificate
        Certificate certificate = null;
        ClientCertificateDataResponseDto clientCertificateDataResponseDto = null;
        try {
            clientCertificateDataResponseDto = issueCertificateForLocation(
                    location, generateCsrResponseDto.getCsr(), request.getIssueAttributes(), raProfileUuid,
                    request.getCertificateCustomAttributes());
            certificate = certificateService.getCertificateEntity(SecuredUUID.fromString(clientCertificateDataResponseDto.getUuid()));
        } catch (Exception e) {
            logger.error("Failed to issue Certificate: {}", e.getMessage());
            removeStash(location, generateCsrResponseDto.getMetadata());
            throw new LocationException("Failed to issue certificate to the location. Error Issuing certificate from Authority. " + e.getMessage());
        }

        // add new Certificate to Location
        try {
            addCertificateToLocation(location, certificate, generateCsrResponseDto.getPushAttributes(), request.getCsrAttributes(), generateCsrResponseDto.getMetadata());
        } catch (Exception e) {
            logger.error("Failed to add new certificate to location: {}", e.getMessage());
            removeStash(location, generateCsrResponseDto.getMetadata());
            throw new LocationException("Failed to add new certificate to the location. Reason: " + e.getMessage());
        }

        logger.info("Certificate {} successfully requested for issue and prepared to be pushed to Location {}", clientCertificateDataResponseDto.getUuid(), location.getName());

        LocationDto locationDto = location.mapToDto();
        locationDto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.LOCATION, location.getUuid()));
        locationDto.getCertificates().forEach(e -> e.setMetadata(attributeEngine.getMappedMetadataContent(new ObjectAttributeContentInfo(Resource.CERTIFICATE, UUID.fromString(e.getCertificateUuid()), Resource.LOCATION, location.getUuid()))));
        return locationDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.LOCATION, action = ResourceAction.UPDATE, parentResource = Resource.ENTITY, parentAction = ResourceAction.DETAIL)
    public LocationDto updateLocationContent(SecuredParentUUID entityUuid, SecuredUUID locationUuid) throws NotFoundException, LocationException {
        Location location = locationRepository.findByUuidAndEnabledIsTrue(locationUuid.getValue())
                .orElseThrow(() -> new NotFoundException(Location.class, locationUuid));

        EntityInstanceReference entityInstanceRef = location.getEntityInstanceReference();

        LocationDetailRequestDto locationDetailRequestDto = new LocationDetailRequestDto();
        locationDetailRequestDto.setLocationAttributes(attributeEngine.getRequestObjectDataAttributesContent(entityInstanceRef.getConnectorUuid(), null, Resource.LOCATION, location.getUuid()));

        LocationDetailResponseDto locationDetailResponseDto;
        try {
            locationDetailResponseDto = locationApiClient.getLocationDetail(
                    entityInstanceRef.getConnector().mapToDto(), entityInstanceRef.getEntityInstanceUuid(), locationDetailRequestDto);
        } catch (ConnectorException e) {
            logger.debug("Failed to get Location details: {}, {}, reason: {}", location.getName(), location.getUuid(), e.getMessage());
            throw new LocationException("Failed to get details for Location " + location.getName() + ". Reason: " + e.getMessage());
        }

        try {
            updateLocationContent(location, locationDetailResponseDto);
        } catch (CertificateException e) { // TODO: do it like this?
            logger.debug("Failed to update Location {}, {} content: {}", location.getName(), location.getUuid(), e.getMessage());
            throw new LocationException("Failed to update content for Location " + location.getName());
        } catch (AttributeException e) {
            logger.debug("Failed to update Location {}, {} content: {}", location.getName(), location.getUuid(), e.getMessage());
            throw new LocationException(String.format("Failed to update content for Location %s because of updating attributes: %s", location.getName(), e.getMessage()));
        }

        logger.info("Location with name {} and UUID {} synced", location.getName(), location.getUuid());

        LocationDto locationDto = location.mapToDto();
        locationDto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.LOCATION, location.getUuid()));
        locationDto.getCertificates().forEach(e -> e.setMetadata(attributeEngine.getMappedMetadataContent(new ObjectAttributeContentInfo(entityInstanceRef.getConnectorUuid(), Resource.CERTIFICATE, UUID.fromString(e.getCertificateUuid()), Resource.LOCATION, location.getUuid()))));

        return locationDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.LOCATION, action = ResourceAction.UPDATE, parentResource = Resource.ENTITY, parentAction = ResourceAction.DETAIL)
    public LocationDto renewCertificateInLocation(SecuredParentUUID entityUuid, SecuredUUID locationUuid, String certificateUuid) throws ConnectorException, LocationException {
        Location location = locationRepository.findByUuidAndEnabledIsTrue(locationUuid.getValue())
                .orElseThrow(() -> new NotFoundException(Location.class, locationUuid));

        CertificateLocation certificateLocation = getCertificateLocation(locationUuid.toString(), certificateUuid);

        // Check if everything is available to do the renewal
        if (certificateLocation.getPushAttributes() == null || certificateLocation.getPushAttributes().isEmpty()) {
            logger.debug("Renewal of the Certificate {} in the Location {}, {} is not possible because the push Attributes are not available",
                    certificateLocation.getCertificate().getUuid(), certificateLocation.getLocation().getName(), certificateLocation.getLocation().getUuid());
            throw new LocationException("Renewal of the Certificate " + certificateUuid + " in the Location " +
                    certificateLocation.getLocation().getName() + " is not possible because the push Attributes are not available");
        }
        if (certificateLocation.getCsrAttributes() == null || certificateLocation.getCsrAttributes().isEmpty()) {
            logger.debug("Renewal of the Certificate {} in the Location {}, {} is not possible because the CSR Attributes are not available",
                    certificateLocation.getCertificate().getUuid(), certificateLocation.getLocation().getName(), certificateLocation.getLocation().getUuid());
            throw new LocationException("Renewal of the certificate " + certificateUuid + " in the location " +
                    certificateLocation.getLocation().getName() + " is not possible because the CSR Attributes are not available");
        }
        if (!certificateLocation.getLocation().isSupportKeyManagement()) {
            logger.debug("Location {}, {} does not support key management", certificateLocation.getLocation().getName(), certificateLocation.getLocation().getUuid());
            throw new LocationException("Location " + certificateLocation.getLocation().getName() + " does not support key management");
        }

        Certificate certificateInScope = certificateService.getCertificateEntity(SecuredUUID.fromString(certificateUuid));
        if (certificateInScope.getRaProfile() == null) {
            logger.debug("Certificate {} is not associated with any RA Profile. Cannot renew the certificate", certificateInScope.getCommonName());
            throw new LocationException("Certificate is not associated with any RA Profile. Cannot renew the certificate in the location");
        }
        //Prechecks for certificate renewal
        String raProfileUuid = certificateInScope.getRaProfile().getUuid().toString();
        RaProfile raProfile = raProfileRepository.findByUuid(UUID.fromString(raProfileUuid)).orElseThrow(() -> new NotFoundException(raProfileUuid, RaProfile.class));
        authorityPreChecks(raProfile);

        // generate new CSR
        GenerateCsrResponseDto generateCsrResponseDto = generateCsrLocation(certificateLocation.getLocation(), AttributeDefinitionUtils.getClientAttributes(certificateLocation.getCsrAttributes()), true);
        logger.info("Received certificate signing request from Location {}", certificateLocation.getLocation().getName());

        // renew existing Certificate
        ClientCertificateDataResponseDto clientCertificateDataResponseDto = null;
        Certificate certificate = null;

        try {
            clientCertificateDataResponseDto = renewCertificate(certificateLocation, generateCsrResponseDto.getCsr());
            certificate = certificateService.getCertificateEntity(SecuredUUID.fromString(clientCertificateDataResponseDto.getUuid()));
        } catch (Exception e) {
            logger.error("Failed to renew Certificate: {}", e.getMessage());
            throw new LocationException("Failed to renew certificate to the location. Error Issuing certificate from Authority. " + e.getMessage());
        }

        // add renewed Certificate to Location
        try {
            addCertificateToLocation(certificateLocation.getLocation(), certificate, generateCsrResponseDto.getPushAttributes(), AttributeDefinitionUtils.getClientAttributes(certificateLocation.getCsrAttributes()), generateCsrResponseDto.getMetadata());

        } catch (Exception e) {
            logger.error("Failed to add new Certificate: {}", e.getMessage());
            throw new LocationException("Failed to add the new certificate to the location. Reason: " + e.getMessage());
        }

        logger.info("Certificate {} successfully requested for renew and prepared to be pushed to Location {}", clientCertificateDataResponseDto.getUuid(), certificateLocation.getLocation().getName());

        LocationDto locationDto = location.mapToDto();
        locationDto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.LOCATION, location.getUuid()));
        locationDto.getCertificates().forEach(e -> e.setMetadata(attributeEngine.getMappedMetadataContent(new ObjectAttributeContentInfo(Resource.CERTIFICATE, UUID.fromString(e.getCertificateUuid()), Resource.LOCATION, location.getUuid()))));

        return locationDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.LOCATION, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter) {
        return locationRepository.findUsingSecurityFilter(filter)
                .stream()
                .map(Location::mapToAccessControlObjects).toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.LOCATION, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        Location location = locationRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(Location.class, uuid));
        if (location.getEntityInstanceReference() == null) {
            return;
        }
        // Parent Permission evaluation - Entity Instance
        permissionEvaluator.authorityInstance(location.getEntityInstanceReference().getSecuredUuid());

    }

    // PRIVATE METHODS

    private GenerateCsrResponseDto generateCsrLocation(Location location, List<RequestAttributeDto> csrAttributes, Boolean isRenewalRequest) throws LocationException {
        GenerateCsrRequestDto generateCsrRequestDto = new GenerateCsrRequestDto();
        generateCsrRequestDto.setLocationAttributes(attributeEngine.getRequestObjectDataAttributesContent(location.getEntityInstanceReference().getConnectorUuid(), null, Resource.LOCATION, location.getUuid()));
        generateCsrRequestDto.setCsrAttributes(csrAttributes);
        generateCsrRequestDto.setRenewal(isRenewalRequest);

        GenerateCsrResponseDto generateCsrResponseDto;
        try {
            generateCsrResponseDto = locationApiClient.generateCsrLocation(
                    location.getEntityInstanceReference().getConnector().mapToDto(),
                    location.getEntityInstanceReference().getEntityInstanceUuid(),
                    generateCsrRequestDto
            );
        } catch (ConnectorException e) {
            logger.debug("Failed to generate CSR for the Location {}, {}, with Attributes {}. Error: {}", location.getName(), location.getUuid(), csrAttributes, e.getMessage());
            throw new LocationException("Failed to generate CSR for Location " + location.getName() + ". Reason: " + e.getMessage());
        }
        return generateCsrResponseDto;
    }

    private ClientCertificateDataResponseDto issueCertificateForLocation(Location location, String csr, List<RequestAttributeDto> issueAttributes, String raProfileUuid, List<RequestAttributeDto> certificateCustomAttributes) throws LocationException {
        ClientCertificateSignRequestDto clientCertificateSignRequestDto = new ClientCertificateSignRequestDto();
        clientCertificateSignRequestDto.setAttributes(issueAttributes);
        // TODO: support for different types of certificate
        clientCertificateSignRequestDto.setRequest(csr);
        clientCertificateSignRequestDto.setFormat(CertificateRequestFormat.PKCS10);
        clientCertificateSignRequestDto.setCustomAttributes(certificateCustomAttributes);
        ClientCertificateDataResponseDto clientCertificateDataResponseDto;
        try {
            // TODO : introduces raProfileRepository, services probably need to be reorganized
            Optional<RaProfile> raProfile = raProfileRepository.findByUuid(UUID.fromString(raProfileUuid));
            if (raProfile.isEmpty() || raProfile.get().getAuthorityInstanceReferenceUuid() == null) {
                logger.debug("Failed to issue Certificate for Location {}, {}. RA profile is not existing or does not have set authority", location.getName(), location.getUuid());
                throw new LocationException("Failed to issue Certificate for Location " + location.getName() + ". RA profile is not existing or does not have set authority");
            }
            clientCertificateDataResponseDto = clientOperationService.issueCertificate(SecuredParentUUID.fromUUID(raProfile.get().getAuthorityInstanceReferenceUuid()), raProfile.get().getSecuredUuid(), clientCertificateSignRequestDto);
        } catch (NotFoundException | java.security.cert.CertificateException | CertificateOperationException |
                 InvalidKeyException | IOException | NoSuchAlgorithmException | CertificateRequestException e) {
            logger.debug("Failed to issue Certificate for Location {}, {}: {}", location.getName(), location.getUuid(), e.getMessage());
            throw new LocationException("Failed to issue Certificate for Location " + location.getName() + ". Reason: " + e.getMessage());
        }
        return clientCertificateDataResponseDto;
    }

    private ClientCertificateDataResponseDto renewCertificate(CertificateLocation certificateLocation, String csr) throws LocationException {
        ClientCertificateRenewRequestDto clientCertificateRenewRequestDto = ClientCertificateRenewRequestDto.builder().build();
        clientCertificateRenewRequestDto.setRequest(csr);
        clientCertificateRenewRequestDto.setReplaceInLocations(false);

        ClientCertificateDataResponseDto clientCertificateDataResponseDto;
        try {
            clientCertificateDataResponseDto = clientOperationService.renewCertificate(
                    SecuredParentUUID.fromUUID(certificateLocation.getCertificate().getRaProfile().getAuthorityInstanceReferenceUuid()),
                    certificateLocation.getCertificate().getRaProfile().getSecuredUuid(),
                    certificateLocation.getCertificate().getSecuredUuid().toString(),
                    clientCertificateRenewRequestDto
            );
        } catch (NotFoundException | IOException | java.security.cert.CertificateException |
                 CertificateOperationException | CertificateRequestException
                 | NoSuchAlgorithmException | InvalidKeyException e) {
            logger.debug("Failed to renew Certificate for Location {}, {}: {}", certificateLocation.getLocation().getName(), certificateLocation.getLocation().getUuid(), e.getMessage());
            throw new LocationException("Failed to renew Certificate for Location " + certificateLocation.getLocation().getName() + ". Reason: " + e.getMessage());
        }
        return clientCertificateDataResponseDto;
    }

    private void addCertificateToLocation(Location location, Certificate certificate, List<RequestAttributeDto> pushAttributes, List<RequestAttributeDto> csrAttributes, List<MetadataAttribute> certificateMetadata) throws LocationException, AttributeException {
        //Get the list of Push and CSR Attributes from the connector. This will then be merged with the user request and
        //stored in the database
        List<BaseAttribute> fullPushAttributes;
        List<BaseAttribute> fullCsrAttributes;
        try {
            fullPushAttributes = listPushAttributes(SecuredParentUUID.fromUUID(location.getEntityInstanceReferenceUuid()), SecuredUUID.fromString(location.getUuid().toString()));
            fullCsrAttributes = listCsrAttributes(SecuredParentUUID.fromUUID(location.getEntityInstanceReferenceUuid()), SecuredUUID.fromString(location.getUuid().toString()));
        } catch (NotFoundException e) {
            logger.error("Unable to find the location with uuid: {}", location.getUuid());
            throw new LocationException("Failed to get Attributes for Location: " + location.getName() + ". Location not found");
        }

        List<DataAttribute> mergedPushAttributes = AttributeDefinitionUtils.mergeAttributes(fullPushAttributes, pushAttributes);
        List<DataAttribute> mergedCsrAttributes = AttributeDefinitionUtils.mergeAttributes(fullCsrAttributes, csrAttributes);

        CertificateLocation certificateLocation = new CertificateLocation();
        certificateLocation.setLocation(location);
        certificateLocation.setCertificate(certificate);
        certificateLocation.setPushAttributes(mergedPushAttributes);
        certificateLocation.setCsrAttributes(mergedCsrAttributes);

        certificateLocationRepository.save(certificateLocation);
        location.getCertificates().add(certificateLocation);
        locationRepository.save(location);

        attributeEngine.updateMetadataAttributes(certificateMetadata, new ObjectAttributeContentInfo(location.getEntityInstanceReference().getConnectorUuid(), Resource.CERTIFICATE, certificate.getUuid(), Resource.LOCATION, location.getUuid(), location.getName()));
    }

    private void pushCertificateToLocation(Location location, Certificate certificate, List<RequestAttributeDto> pushAttributes, List<RequestAttributeDto> csrAttributes) throws LocationException, AttributeException {
        PushCertificateRequestDto pushCertificateRequestDto = new PushCertificateRequestDto();
        pushCertificateRequestDto.setCertificate(certificate.getCertificateContent().getContent());
        // TODO: support for different types of certificate
        pushCertificateRequestDto.setCertificateType(CertificateType.X509);
        pushCertificateRequestDto.setLocationAttributes(attributeEngine.getRequestObjectDataAttributesContent(location.getEntityInstanceReference().getConnectorUuid(), null, Resource.LOCATION, location.getUuid()));
        pushCertificateRequestDto.setPushAttributes(pushAttributes);

        PushCertificateResponseDto pushCertificateResponseDto;
        try {
            pushCertificateResponseDto = locationApiClient.pushCertificateToLocation(
                    location.getEntityInstanceReference().getConnector().mapToDto(),
                    location.getEntityInstanceReference().getEntityInstanceUuid(),
                    pushCertificateRequestDto
            );
        } catch (ConnectorException e) {
            // record event in the certificate history
            String message = "Failed to push to Location " + location.getName();
            HashMap<String, Object> additionalInformation = new HashMap<>();
            additionalInformation.put("locationUuid", location.getUuid());
            additionalInformation.put("cause", e.getMessage());
            certificateEventHistoryService.addEventHistory(
                    certificate.getUuid(),
                    CertificateEvent.UPDATE_LOCATION,
                    CertificateEventStatus.FAILED,
                    message,
                    additionalInformation
            );
            logger.debug("Failed to push Certificate {} to Location {}, {}: {}",
                    certificate.getUuid(), location.getName(), location.getUuid(), e.getMessage());
            throw new LocationException("Failed to push Certificate " + certificate.getUuid() +
                    " to Location " + location.getName() + ". Reason: " + e.getMessage());
        }

        //Get the list of Push and CSR Attributes from the connector. This will then be merged with the user request and
        //stored in the database
        List<BaseAttribute> fullPushAttributes;
        List<BaseAttribute> fullCsrAttributes;
        try {
            fullPushAttributes = listPushAttributes(SecuredParentUUID.fromUUID(location.getEntityInstanceReferenceUuid()), SecuredUUID.fromString(location.getUuid().toString()));
            fullCsrAttributes = listCsrAttributes(SecuredParentUUID.fromUUID(location.getEntityInstanceReferenceUuid()), SecuredUUID.fromString(location.getUuid().toString()));
        } catch (NotFoundException e) {
            logger.error("Unable to find the location with uuid: {}", location.getUuid());
            throw new LocationException("Failed to get Attributes for Location: " + location.getName() + ". Location not found");
        }

        List<DataAttribute> mergedPushAttributes = AttributeDefinitionUtils.mergeAttributes(fullPushAttributes, pushAttributes);
        List<DataAttribute> mergedCsrAttributes = AttributeDefinitionUtils.mergeAttributes(fullCsrAttributes, csrAttributes);

        CertificateLocation certificateLocation = new CertificateLocation();
        certificateLocation.setLocation(location);
        certificateLocation.setCertificate(certificate);
        certificateLocation.setWithKey(pushCertificateResponseDto.isWithKey());
        certificateLocation.setPushAttributes(mergedPushAttributes);
        certificateLocation.setCsrAttributes(mergedCsrAttributes);

        // TODO: response with the indication if the key is available for pushed certificate

        certificateLocationRepository.save(certificateLocation);
        location.getCertificates().add(certificateLocation);

        locationRepository.save(location);

        attributeEngine.updateMetadataAttributes(pushCertificateResponseDto.getCertificateMetadata(), new ObjectAttributeContentInfo(location.getEntityInstanceReference().getConnectorUuid(), Resource.CERTIFICATE, certificate.getUuid(), Resource.LOCATION, location.getUuid(), location.getName()));

        // save record into the certificate history
        String message = "Pushed to Location " + location.getName();
        HashMap<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put("locationUuid", location.getUuid());
        certificateEventHistoryService.addEventHistory(
                certificate.getUuid(),
                CertificateEvent.UPDATE_LOCATION,
                CertificateEventStatus.SUCCESS,
                message,
                additionalInformation
        );
    }

    private LocationDetailResponseDto getLocationDetail(EntityInstanceReference entityInstanceReference, List<RequestAttributeDto> requestAttributes, String locationName) throws LocationException {
        LocationDetailRequestDto locationDetailRequestDto = new LocationDetailRequestDto();
        locationDetailRequestDto.setLocationAttributes(requestAttributes);
        LocationDetailResponseDto locationDetailResponseDto;
        try {
            locationDetailResponseDto = locationApiClient.getLocationDetail(
                    entityInstanceReference.getConnector().mapToDto(), entityInstanceReference.getEntityInstanceUuid(), locationDetailRequestDto);
        } catch (ConnectorException e) {
            logger.debug("Failed to get Location {} details: {}", locationName, e.getMessage());
            throw new LocationException("Failed to get details for Location " + locationName + ". Reason: " + e.getMessage());
        }
        return locationDetailResponseDto;
    }

    private CertificateLocation getCertificateLocation(String locationUuid, String certificateUuid) throws NotFoundException {
        Location location = locationRepository.findByUuid(UUID.fromString(locationUuid))
                .orElseThrow(() -> new NotFoundException(Location.class, locationUuid));

        Certificate certificate = certificateService.getCertificateEntity(SecuredUUID.fromString(certificateUuid));

        CertificateLocationId clId = new CertificateLocationId(location.getUuid(), certificate.getUuid());
        return certificateLocationRepository.findById(clId)
                .orElseThrow(() -> new NotFoundException(CertificateLocation.class, clId));
    }

    private void removeCertificateFromLocation(CertificateLocation certificateLocation) throws ConnectorException {
        Location location = certificateLocation.getLocation();
        Certificate certificate = certificateLocation.getCertificate();

        List<MetadataAttribute> metadata = attributeEngine.getMetadataAttributesDefinitionContent(new ObjectAttributeContentInfo(
                location.getEntityInstanceReference().getConnectorUuid(),
                Resource.CERTIFICATE, certificate.getUuid(),
                Resource.LOCATION, location.getUuid()));

        logger.info("Removing certificate {} from location {} in entity provider", certificate, location.getName());

        removeStash(location, metadata);

        certificateLocationRepository.delete(certificateLocation);

        attributeEngine.deleteObjectAttributesContent(AttributeType.META, new ObjectAttributeContentInfo(
                location.getEntityInstanceReference().getConnectorUuid(),
                Resource.CERTIFICATE, certificate.getUuid(),
                Resource.LOCATION, location.getUuid()));

        location.getCertificates().remove(certificateLocation);

        locationRepository.save(location);
    }

    private void mergeAndValidateAttributes(EntityInstanceReference entityInstanceRef, List<RequestAttributeDto> attributes) throws ConnectorException, AttributeException {
        logger.debug("Merging and validating attributes on entity instance {}. Request Attributes are: {}", entityInstanceRef, attributes);
        if (entityInstanceRef.getConnector() == null) {
            throw new ValidationException(ValidationError.create("Connector of the Entity is not available / deleted"));
        }

        ConnectorDto connectorDto = entityInstanceRef.getConnector().mapToDto();

        // validate first by connector
        entityInstanceApiClient.validateLocationAttributes(connectorDto, entityInstanceRef.getEntityInstanceUuid(), attributes);

        // list definitions
        List<BaseAttribute> definitions = entityInstanceApiClient.listLocationAttributes(connectorDto, entityInstanceRef.getEntityInstanceUuid());

        // validate and update definitions with attribute engine
        attributeEngine.validateUpdateDataAttributes(entityInstanceRef.getConnectorUuid(), null, definitions, attributes);
    }

    private Location createLocation(AddLocationRequestDto dto, EntityInstanceReference entityInstanceRef, LocationDetailResponseDto locationDetailResponseDto) throws CertificateException, AttributeException {
        Location entity = new Location();
        entity.setName(dto.getName());
        entity.setDescription(dto.getDescription());
        entity.setEntityInstanceReference(entityInstanceRef);
        entity.setEnabled(dto.isEnabled() != null && dto.isEnabled());
        entity.setEntityInstanceName(entityInstanceRef.getName());
        locationRepository.save(entity);
        updateContent(entity,
                locationDetailResponseDto.isMultipleEntries(),
                locationDetailResponseDto.isSupportKeyManagement(),
                locationDetailResponseDto.getMetadata(),
                locationDetailResponseDto.getCertificates());

        return entity;
    }

    private void updateLocation(Location entity, EntityInstanceReference entityInstanceRef, EditLocationRequestDto dto, LocationDetailResponseDto locationDetailResponseDto) throws CertificateException, AttributeException {
        entity.setDescription(dto.getDescription());
        entity.setEntityInstanceReference(entityInstanceRef);
        if (dto.isEnabled() != null) {
            entity.setEnabled(dto.isEnabled() != null && dto.isEnabled());
        }
        entity.setEntityInstanceName(entityInstanceRef.getName());

        updateContent(entity,
                locationDetailResponseDto.isMultipleEntries(),
                locationDetailResponseDto.isSupportKeyManagement(),
                locationDetailResponseDto.getMetadata(),
                locationDetailResponseDto.getCertificates());
    }

    private void updateLocationContent(Location entity, LocationDetailResponseDto locationDetailResponseDto) throws CertificateException, AttributeException {
        updateContent(entity,
                locationDetailResponseDto.isMultipleEntries(),
                locationDetailResponseDto.isSupportKeyManagement(),
                locationDetailResponseDto.getMetadata(),
                locationDetailResponseDto.getCertificates());
    }

    private void updateContent(Location entity, boolean supportMultipleEntries, boolean supportKeyManagement,
                               List<MetadataAttribute> metadata, List<CertificateLocationDto> certificates) throws CertificateException, AttributeException {
        entity.setSupportMultipleEntries(supportMultipleEntries);
        entity.setSupportKeyManagement(supportKeyManagement);

        attributeEngine.deleteObjectAttributesContent(AttributeType.META, new ObjectAttributeContentInfo(entity.getEntityInstanceReference().getConnectorUuid(), Resource.LOCATION, entity.getUuid()));
        attributeEngine.updateMetadataAttributes(metadata, new ObjectAttributeContentInfo(entity.getEntityInstanceReference().getConnectorUuid(), Resource.LOCATION, entity.getUuid()));
        Set<CertificateLocation> cls = new HashSet<>();
        for (CertificateLocationDto certificateLocationDto : certificates) {
            CertificateLocation cl = new CertificateLocation();
            cl.setWithKey(certificateLocationDto.isWithKey());
            cl.setCertificate(certificateService.createCertificate(certificateLocationDto.getCertificateData(), certificateLocationDto.getCertificateType()));
            cl.setLocation(entity);
            cl.setPushAttributes(certificateLocationDto.getPushAttributes());
            cl.setCsrAttributes(certificateLocationDto.getCsrAttributes());
            cls.add(cl);

            attributeEngine.deleteObjectAttributesContent(AttributeType.META, new ObjectAttributeContentInfo(entity.getEntityInstanceReference().getConnectorUuid(), Resource.CERTIFICATE, cl.getCertificate().getUuid(), Resource.LOCATION, entity.getUuid()));
            attributeEngine.updateMetadataAttributes(certificateLocationDto.getMetadata(), new ObjectAttributeContentInfo(entity.getEntityInstanceReference().getConnectorUuid(), Resource.CERTIFICATE, cl.getCertificate().getUuid(), Resource.LOCATION, entity.getUuid(), entity.getName()));
        }

        Iterator<CertificateLocation> iterator = entity.getCertificates().iterator();
        while (iterator.hasNext()) {
            CertificateLocation cl = iterator.next();

            if (!cls.contains(cl)) {
                certificateLocationRepository.delete(cl);
                iterator.remove();
            } else {
                CertificateLocation lc = cls.stream().filter(e -> e.getCertificate().getUuid().equals(cl.getCertificate().getUuid())).findFirst().orElse(null);
                if (lc != null) {
                    cl.setCsrAttributes(lc.getCsrAttributes());
                    cl.setPushAttributes(lc.getPushAttributes());
                    cl.setWithKey(lc.isWithKey());
                    certificateLocationRepository.save(cl);
                }
            }
        }

        entity.getCertificates().addAll(cls);
        locationRepository.save(entity);
    }

    private void authorityPreChecks(RaProfile raProfile) throws ValidationException {
        //Check if RA Profile is enabled
        if (!raProfile.getEnabled()) {
            throw new ValidationException(ValidationError.create("RA Profile is disabled"));
        }

        //Check if RA Profile has Authority
        if (raProfile.getAuthorityInstanceReference() == null) {
            throw new ValidationException(ValidationError.create("RA Profile does not have proper authority associated"));
        }
        //Check if Authority is Enabled
        if (!raProfile.getAuthorityInstanceReference().getStatus().equals("connected")) {
            throw new ValidationException(ValidationError.create("Associated Authority is not connected"));
        }

        //Check if Authority has Connector
        if (raProfile.getAuthorityInstanceReference().getConnector() == null) {
            throw new ValidationException(ValidationError.create("Associated authority does not have Connector associated"));
        }

        if (!raProfile.getAuthorityInstanceReference().getConnector().getStatus().equals(ConnectorStatus.CONNECTED)) {
            throw new ValidationException(ValidationError.create("Authority Provider has Invalid State"));
        }

    }

    private void removeStash(Location location, List<MetadataAttribute> metadata) throws ConnectorException {
        RemoveCertificateRequestDto removeCertificateRequestDto = new RemoveCertificateRequestDto();
        removeCertificateRequestDto.setLocationAttributes(attributeEngine.getRequestObjectDataAttributesContent(location.getEntityInstanceReference().getConnectorUuid(), null, Resource.LOCATION, location.getUuid()));
        removeCertificateRequestDto.setCertificateMetadata(metadata);
        locationApiClient.removeCertificateFromLocation(location.getEntityInstanceReference().getConnector().mapToDto(),
                location.getEntityInstanceReference().getEntityInstanceUuid(),
                removeCertificateRequestDto);
    }

    private void validateLocationCreation(EntityInstanceReference entityInstance, List<RequestAttributeDto> requestDto) throws ValidationException {

        for (Location location : locationRepository.findByEntityInstanceReference(entityInstance)) {
            List<DataAttribute> locationAttributes = attributeEngine.getDefinitionObjectAttributeContent(AttributeType.DATA, entityInstance.getConnectorUuid(), null, Resource.LOCATION, location.getUuid());
            if (AttributeDefinitionUtils.checkAttributeEquality(requestDto, locationAttributes)) {
                throw new ValidationException(ValidationError.create("Location with same attributes already exists"));
            }
        }
    }

    @Override
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup() {
        final List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine.getResourceSearchableFields(Resource.LOCATION, false);

        List<SearchFieldDataDto> fields = List.of(
                SearchHelper.prepareSearch(SearchFieldNameEnum.LOCATION_NAME),
                SearchHelper.prepareSearch(SearchFieldNameEnum.LOCATION_INSTANCE_NAME, locationRepository.findDistinctEntityInstanceName()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.LOCATION_ENABLED),
                SearchHelper.prepareSearch(SearchFieldNameEnum.LOCATION_SUPPORT_MULTIPLE_ENTRIES),
                SearchHelper.prepareSearch(SearchFieldNameEnum.LOCATION_SUPPORT_KEY_MANAGEMENT)
        );

        fields = new ArrayList<>(fields);
        fields.sort(new SearchFieldDataComparator());

        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));

        logger.debug("Searchable Fields by Groups: {}", searchFieldDataByGroupDtos);
        return searchFieldDataByGroupDtos;
    }
}
