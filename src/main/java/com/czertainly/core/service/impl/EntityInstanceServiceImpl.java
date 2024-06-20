package com.czertainly.core.service.impl;

import com.czertainly.api.clients.EntityInstanceApiClient;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.client.attribute.ResponseAttributeDto;
import com.czertainly.api.model.client.certificate.EntityInstanceResponseDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.entity.EntityInstanceUpdateRequestDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.connector.entity.EntityInstanceRequestDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.entity.EntityInstanceDto;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.comparator.SearchFieldDataComparator;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.EntityInstanceReference;
import com.czertainly.core.dao.repository.EntityInstanceReferenceRepository;
import com.czertainly.core.enums.SearchFieldNameEnum;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.ConnectorService;
import com.czertainly.core.service.CredentialService;
import com.czertainly.core.service.EntityInstanceService;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.core.util.RequestValidatorHelper;
import com.czertainly.core.util.SearchHelper;
import com.czertainly.core.util.converter.Sql2PredicateConverter;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.BiFunction;

@Service
@Transactional
public class EntityInstanceServiceImpl implements EntityInstanceService {

    private static final Logger logger = LoggerFactory.getLogger(EntityInstanceServiceImpl.class);
    private EntityInstanceReferenceRepository entityInstanceReferenceRepository;
    private ConnectorService connectorService;
    private CredentialService credentialService;
    private EntityInstanceApiClient entityInstanceApiClient;
    private AttributeEngine attributeEngine;

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setEntityInstanceReferenceRepository(EntityInstanceReferenceRepository entityInstanceReferenceRepository) {
        this.entityInstanceReferenceRepository = entityInstanceReferenceRepository;
    }

    @Autowired
    public void setConnectorService(ConnectorService connectorService) {
        this.connectorService = connectorService;
    }

    @Autowired
    public void setCredentialService(CredentialService credentialService) {
        this.credentialService = credentialService;
    }

    @Autowired
    public void setEntityInstanceApiClient(EntityInstanceApiClient entityInstanceApiClient) {
        this.entityInstanceApiClient = entityInstanceApiClient;
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.CA_INSTANCE, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.LIST)
    public EntityInstanceResponseDto listEntityInstances(final SecurityFilter filter, final SearchRequestDto request) {
        RequestValidatorHelper.revalidateSearchRequestDto(request);
        final Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());

        // filter entities based on attribute filters
        final List<UUID> objectUUIDs = attributeEngine.getResourceObjectUuidsByFilters(Resource.ENTITY, filter, request.getFilters());

        final BiFunction<Root<EntityInstanceReference>, CriteriaBuilder, Predicate> additionalWhereClause = (root, cb) -> Sql2PredicateConverter.mapSearchFilter2Predicates(request.getFilters(), cb, root, objectUUIDs, attributeEngine.findAllObjectUuids(Resource.ENTITY));
        final List<EntityInstanceDto> listedKeyDTOs = entityInstanceReferenceRepository.findUsingSecurityFilter(filter, List.of(), additionalWhereClause, p, (root, cb) -> cb.desc(root.get("created")))
                .stream()
                .map(EntityInstanceReference::mapToDto).toList();
        final Long maxItems = entityInstanceReferenceRepository.countUsingSecurityFilter(filter, additionalWhereClause);

        final EntityInstanceResponseDto responseDto = new EntityInstanceResponseDto();
        responseDto.setEntities(listedKeyDTOs);
        responseDto.setItemsPerPage(request.getItemsPerPage());
        responseDto.setPageNumber(request.getPageNumber());
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / request.getItemsPerPage()));
        return responseDto;
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.CA_INSTANCE, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.DETAIL)
    public EntityInstanceDto getEntityInstance(SecuredUUID entityUuid) throws ConnectorException {
        EntityInstanceReference entityInstanceReference = getEntityInstanceReferenceEntity(entityUuid);

        List<ResponseAttributeDto> attributes = attributeEngine.getObjectDataAttributesContent(entityInstanceReference.getConnectorUuid(), null, Resource.ENTITY, entityInstanceReference.getUuid());

        EntityInstanceDto entityInstanceDto = entityInstanceReference.mapToDto();
        entityInstanceDto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.ENTITY, entityUuid.getValue()));
        if (entityInstanceReference.getConnector() == null) {
            entityInstanceDto.setConnectorName(entityInstanceReference.getConnectorName() + " (Deleted)");
            entityInstanceDto.setConnectorUuid("");
            entityInstanceDto.setAttributes(attributes);
            logger.warn("Connector associated with the Entity: {} is not found. Unable to show details", entityInstanceReference.getName());
            return entityInstanceDto;
        }

        com.czertainly.api.model.connector.entity.EntityInstanceDto entityProviderInstanceDto = entityInstanceApiClient.getEntityInstance(entityInstanceReference.getConnector().mapToDto(),
                entityInstanceReference.getEntityInstanceUuid());

        if (attributes.isEmpty() && entityProviderInstanceDto.getAttributes() != null && !entityProviderInstanceDto.getAttributes().isEmpty()) {
            try {
                List<RequestAttributeDto> requestAttributes = AttributeDefinitionUtils.getClientAttributes(entityProviderInstanceDto.getAttributes());
                attributeEngine.updateDataAttributeDefinitions(entityInstanceReference.getConnectorUuid(), null, entityProviderInstanceDto.getAttributes());
                attributes = attributeEngine.updateObjectDataAttributesContent(entityInstanceReference.getConnectorUuid(), null, Resource.ENTITY, entityInstanceReference.getUuid(), requestAttributes);
            } catch (AttributeException e) {
                logger.warn("Could not update data attributes for entity {} retrieved from connector", entityInstanceReference.getName());
            }
        }

        entityInstanceDto.setAttributes(attributes);
        return entityInstanceDto;
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.CA_INSTANCE, operation = OperationType.CREATE)
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.CREATE)
    public EntityInstanceDto createEntityInstance(com.czertainly.api.model.client.entity.EntityInstanceRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException {
        if (entityInstanceReferenceRepository.findByName(request.getName()).isPresent()) {
            throw new AlreadyExistException(EntityInstanceReference.class, request.getName());
        }

        if (request.getConnectorUuid() == null) {
            throw new ValidationException(ValidationError.create("Connector UUID is empty"));
        }

        Connector connector = connectorService.getConnectorEntity(SecuredUUID.fromString(request.getConnectorUuid()));

        FunctionGroupCode codeToSearch = FunctionGroupCode.ENTITY_PROVIDER;
        attributeEngine.validateCustomAttributesContent(Resource.ENTITY, request.getCustomAttributes());
        connectorService.mergeAndValidateAttributes(SecuredUUID.fromUUID(connector.getUuid()), codeToSearch, request.getAttributes(), request.getKind());

        // Load complete credential data
        var dataAttributes = attributeEngine.getDataAttributesByContent(connector.getUuid(), request.getAttributes());
        credentialService.loadFullCredentialData(dataAttributes);

        EntityInstanceRequestDto entityInstanceDto = new EntityInstanceRequestDto();
        entityInstanceDto.setAttributes(AttributeDefinitionUtils.getClientAttributes(dataAttributes));
        entityInstanceDto.setKind(request.getKind());
        entityInstanceDto.setName(request.getName());

        com.czertainly.api.model.connector.entity.EntityInstanceDto response = entityInstanceApiClient.createEntityInstance(connector.mapToDto(), entityInstanceDto);

        EntityInstanceReference entityInstanceRef = new EntityInstanceReference();
        entityInstanceRef.setEntityInstanceUuid((response.getUuid()));
        entityInstanceRef.setName(request.getName());
        //entityInstanceRef.setStatus("connected"); // TODO: status of the Entity
        entityInstanceRef.setConnector(connector);
        entityInstanceRef.setKind(request.getKind());
        entityInstanceRef.setConnectorName(connector.getName());
        entityInstanceReferenceRepository.save(entityInstanceRef);

        logger.info("Entity {} created with Kind {}", entityInstanceRef.getUuid(), entityInstanceRef.getKind());

        EntityInstanceDto dto = entityInstanceRef.mapToDto();
        dto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.ENTITY, entityInstanceRef.getUuid(), request.getCustomAttributes()));
        dto.setAttributes(attributeEngine.updateObjectDataAttributesContent(entityInstanceRef.getConnectorUuid(), null, Resource.ENTITY, entityInstanceRef.getUuid(), request.getAttributes()));
        return dto;
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.CA_INSTANCE, operation = OperationType.CHANGE)
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.UPDATE)
    public EntityInstanceDto editEntityInstance(SecuredUUID entityUuid, EntityInstanceUpdateRequestDto request) throws ConnectorException, AttributeException {
        EntityInstanceReference entityInstanceRef = getEntityInstanceReferenceEntity(entityUuid);

        EntityInstanceDto ref = getEntityInstance(entityUuid);
        Connector connector = connectorService.getConnectorEntity(SecuredUUID.fromString(ref.getConnectorUuid()));

        FunctionGroupCode codeToSearch = FunctionGroupCode.ENTITY_PROVIDER;
        attributeEngine.validateCustomAttributesContent(Resource.ENTITY, request.getCustomAttributes());
        connectorService.mergeAndValidateAttributes(connector.getSecuredUuid(), codeToSearch, request.getAttributes(), ref.getKind());

        // Load complete credential data
        var dataAttributes = attributeEngine.getDataAttributesByContent(connector.getUuid(), request.getAttributes());
        credentialService.loadFullCredentialData(dataAttributes);

        EntityInstanceRequestDto entityInstanceDto = new EntityInstanceRequestDto();
        entityInstanceDto.setAttributes(AttributeDefinitionUtils.getClientAttributes(dataAttributes));
        entityInstanceDto.setKind(entityInstanceRef.getKind());
        entityInstanceDto.setName(entityInstanceRef.getName());
        entityInstanceApiClient.updateEntityInstance(connector.mapToDto(), entityInstanceRef.getEntityInstanceUuid(), entityInstanceDto);
        entityInstanceReferenceRepository.save(entityInstanceRef);

        EntityInstanceDto dto = entityInstanceRef.mapToDto();
        dto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.ENTITY, entityInstanceRef.getUuid(), request.getCustomAttributes()));
        dto.setAttributes(attributeEngine.updateObjectDataAttributesContent(entityInstanceRef.getConnectorUuid(), null, Resource.ENTITY, entityInstanceRef.getUuid(), request.getAttributes()));
        return dto;
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.CA_INSTANCE, operation = OperationType.DELETE)
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.DELETE)
    public void deleteEntityInstance(SecuredUUID entityUuid) throws ConnectorException {
        EntityInstanceReference entityInstanceRef = getEntityInstanceReferenceEntity(entityUuid);

        List<ValidationError> errors = new ArrayList<>();
        if (!entityInstanceRef.getLocations().isEmpty()) {
            errors.add(ValidationError.create("Entity instance {} has {} dependent Locations", entityInstanceRef.getName(),
                    entityInstanceRef.getLocations().size()));
            entityInstanceRef.getLocations().forEach(c -> errors.add(ValidationError.create(c.getName())));
        }

        if (!errors.isEmpty()) {
            throw new ValidationException("Could not delete Entity instance", errors);
        }

        entityInstanceApiClient.removeEntityInstance(entityInstanceRef.getConnector().mapToDto(), entityInstanceRef.getEntityInstanceUuid());
        attributeEngine.deleteAllObjectAttributeContent(Resource.ENTITY, entityInstanceRef.getUuid());
        entityInstanceReferenceRepository.delete(entityInstanceRef);

        logger.info("Entity instance {} was deleted", entityInstanceRef.getName());
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.ATTRIBUTES, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.ANY)
    public List<BaseAttribute> listLocationAttributes(SecuredUUID entityUuid) throws ConnectorException {
        final EntityInstanceReference entityInstance = getEntityInstanceReferenceEntity(entityUuid);
        final Connector connector = entityInstance.getConnector();
        return entityInstanceApiClient.listLocationAttributes(connector.mapToDto(), entityInstance.getEntityInstanceUuid());
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.ATTRIBUTES, operation = OperationType.VALIDATE)
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.ANY)
    public void validateLocationAttributes(SecuredUUID entityUuid, List<RequestAttributeDto> attributes) throws ConnectorException {
        EntityInstanceReference entityInstance = getEntityInstanceReferenceEntity(entityUuid);

        Connector connector = entityInstance.getConnector();

        entityInstanceApiClient.validateLocationAttributes(connector.mapToDto(), entityInstance.getEntityInstanceUuid(),
                attributes);
    }

    @Override
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter) {
        return entityInstanceReferenceRepository.findUsingSecurityFilter(filter)
                .stream()
                .map(EntityInstanceReference::mapToAccessControlObjects).toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getEntityInstanceReferenceEntity(uuid);
        // Since there are is no parent to the Entity, exclusive parent permission evaluation need not be done
    }

    private EntityInstanceReference getEntityInstanceReferenceEntity(SecuredUUID uuid) throws NotFoundException {
        return entityInstanceReferenceRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(EntityInstanceReference.class, uuid));
    }

    @Override
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup() {
        final List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine.getResourceSearchableFields(Resource.ENTITY, false);

        List<SearchFieldDataDto> fields = List.of(
                SearchHelper.prepareSearch(SearchFieldNameEnum.ENTITY_NAME),
                SearchHelper.prepareSearch(SearchFieldNameEnum.ENTITY_CONNECTOR_NAME, entityInstanceReferenceRepository.findDistinctConnectorName()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.ENTITY_KIND, entityInstanceReferenceRepository.findDistinctKind())
        );

        fields = new ArrayList<>(fields);
        fields.sort(new SearchFieldDataComparator());

        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));

        logger.debug("Searchable Fields by Groups: {}", searchFieldDataByGroupDtos);
        return searchFieldDataByGroupDtos;
    }
}
