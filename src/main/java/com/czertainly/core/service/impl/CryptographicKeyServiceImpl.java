package com.czertainly.core.service.impl;

import com.czertainly.api.clients.cryptography.KeyManagementApiClient;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.cryptography.CryptographicKeyResponseDto;
import com.czertainly.api.model.client.cryptography.key.*;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyFormat;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.czertainly.api.model.connector.cryptography.key.KeyData;
import com.czertainly.api.model.connector.cryptography.key.KeyDataResponseDto;
import com.czertainly.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.czertainly.api.model.core.audit.ObjectType;
import com.czertainly.api.model.core.audit.OperationType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.auth.UserDto;
import com.czertainly.api.model.core.connector.ConnectorDto;
import com.czertainly.api.model.core.cryptography.key.*;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.comparator.SearchFieldDataComparator;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.enums.SearchFieldNameEnum;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authn.client.UserManagementApiClient;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.*;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.RequestValidatorHelper;
import com.czertainly.core.util.SearchHelper;
import com.czertainly.core.util.converter.Sql2PredicateConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.function.Predicate.not;

@Service
@Transactional(noRollbackFor = ValidationException.class)
public class CryptographicKeyServiceImpl implements CryptographicKeyService {

    private static final Logger logger = LoggerFactory.getLogger(CryptographicKeyServiceImpl.class);

    // forbidden usages for the keys -- by key type and by key algorithm
    private static final Map<KeyType, List<KeyUsage>> FORBIDDEN_TYPE_USAGES = Map.of(
            KeyType.PRIVATE_KEY, List.of(KeyUsage.VERIFY, KeyUsage.ENCRYPT, KeyUsage.WRAP),
            KeyType.PUBLIC_KEY, List.of(KeyUsage.SIGN, KeyUsage.DECRYPT, KeyUsage.UNWRAP)
    );
    private static final Map<KeyAlgorithm, List<KeyUsage>> FORBIDDEN_ALGORITHM_USAGES = Map.of(
            KeyAlgorithm.ECDSA, List.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
    );

    private static List<KeyUsage> getForbiddenUsages(KeyType keyType, KeyAlgorithm keyAlgorithm) {
        Set<KeyUsage> result = new HashSet<>(Objects.requireNonNullElse(FORBIDDEN_TYPE_USAGES.get(keyType), Collections.emptyList()));
        result.addAll(Objects.requireNonNullElse(FORBIDDEN_ALGORITHM_USAGES.get(keyAlgorithm), Collections.emptyList()));
        return result.stream().toList();
    }

    // --------------------------------------------------------------------------------
    // Services & API Clients
    // --------------------------------------------------------------------------------
    private AttributeEngine attributeEngine;
    private KeyManagementApiClient keyManagementApiClient;
    private TokenInstanceService tokenInstanceService;
    private CryptographicKeyEventHistoryService keyEventHistoryService;
    private PermissionEvaluator permissionEvaluator;
    private CertificateService certificateService;
    private ResourceObjectAssociationService objectAssociationService;

    @Autowired
    private UserManagementApiClient userManagementApiClient;
    // --------------------------------------------------------------------------------
    // Repositories
    // --------------------------------------------------------------------------------
    private CryptographicKeyRepository cryptographicKeyRepository;
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    private TokenProfileRepository tokenProfileRepository;
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    private GroupRepository groupRepository;

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setObjectAssociationService(ResourceObjectAssociationService objectAssociationService) {
        this.objectAssociationService = objectAssociationService;
    }

    @Autowired
    public void setKeyManagementApiClient(KeyManagementApiClient keyManagementApiClient) {
        this.keyManagementApiClient = keyManagementApiClient;
    }

    @Autowired
    public void setTokenInstanceService(TokenInstanceService tokenInstanceService) {
        this.tokenInstanceService = tokenInstanceService;
    }

    @Autowired
    public void setKeyEventHistoryService(CryptographicKeyEventHistoryService keyEventHistoryService) {
        this.keyEventHistoryService = keyEventHistoryService;
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
        this.permissionEvaluator = permissionEvaluator;
    }

    @Autowired
    public void setCryptographicKeyItemRepository(CryptographicKeyItemRepository cryptographicKeyItemRepository) {
        this.cryptographicKeyItemRepository = cryptographicKeyItemRepository;
    }

    @Autowired
    public void setCryptographicKeyRepository(CryptographicKeyRepository cryptographicKeyRepository) {
        this.cryptographicKeyRepository = cryptographicKeyRepository;
    }

    @Autowired
    public void setCryptographicKeyContentRepository(CryptographicKeyItemRepository cryptographicKeyItemRepository) {
        this.cryptographicKeyItemRepository = cryptographicKeyItemRepository;
    }

    @Autowired
    public void setTokenProfileRepository(TokenProfileRepository tokenProfileRepository) {
        this.tokenProfileRepository = tokenProfileRepository;
    }

    @Autowired
    public void setGroupRepository(GroupRepository groupRepository) {
        this.groupRepository = groupRepository;
    }

    @Autowired
    public void setTokenInstanceReferenceRepository(TokenInstanceReferenceRepository tokenInstanceReferenceRepository) {
        this.tokenInstanceReferenceRepository = tokenInstanceReferenceRepository;
    }

    // ----------------------------------------------------------------------------------------------
    // Service Implementations
    // ----------------------------------------------------------------------------------------------

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.LIST, parentResource = Resource.TOKEN, parentAction = ResourceAction.MEMBERS)
    public CryptographicKeyResponseDto listCryptographicKeys(SecurityFilter filter, SearchRequestDto request) {
        filter.setParentRefProperty("tokenInstanceReferenceUuid");
        RequestValidatorHelper.revalidateSearchRequestDto(request);

        // filter keys based on attribute filters
        final List<UUID> objectUUIDs = attributeEngine.getResourceObjectUuidsByFilters(Resource.CRYPTOGRAPHIC_KEY, filter, request.getFilters());

        final Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());
        final List<KeyItemDto> listedKeyDtos = cryptographicKeyItemRepository.findUsingSecurityFilter(filter,
                        List.of("cryptographicKey", "cryptographicKey.certificates", "cryptographicKey.groups", "cryptographicKey.owner", "cryptographicKey.tokenInstanceReference", "cryptographicKey.tokenProfile"),
                        (root, cb) -> Sql2PredicateConverter.mapSearchFilter2Predicates(request.getFilters(), cb, root, objectUUIDs, attributeEngine.findAllObjectUuids(Resource.CRYPTOGRAPHIC_KEY)), p, (root, cb) -> cb.desc(root.get("createdAt")))
                .stream()
                .map(CryptographicKeyItem::mapToSummaryDto)
                .toList();

        final Long maxItems = cryptographicKeyItemRepository.countUsingSecurityFilter(filter, (root, cb) -> Sql2PredicateConverter.mapSearchFilter2Predicates(request.getFilters(), cb, root));
        final CryptographicKeyResponseDto responseDto = new CryptographicKeyResponseDto();
        responseDto.setCryptographicKeys(listedKeyDtos);
        responseDto.setItemsPerPage(request.getItemsPerPage());
        responseDto.setPageNumber(request.getPageNumber());
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / request.getItemsPerPage()));
        return responseDto;
    }

    @Override
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        return getSearchableFieldsMap();
    }


    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.LIST, parentResource = Resource.TOKEN, parentAction = ResourceAction.MEMBERS)
    public List<KeyDto> listKeyPairs(Optional<String> tokenProfileUuid, SecurityFilter filter) {
        logger.info("Requesting key list for Token profile with UUID {}", tokenProfileUuid);
        filter.setParentRefProperty("tokenInstanceReferenceUuid");
        List<KeyDto> response = cryptographicKeyRepository.findUsingSecurityFilter(filter, List.of("groups", "owner"), null, null, (root, cb) -> cb.desc(root.get("created")))
                .stream()
                .map(CryptographicKey::mapToDto)
                .collect(Collectors.toList()
                );
        if (tokenProfileUuid.isPresent() && !tokenProfileUuid.get().isEmpty()) {
            response = response.stream().filter(e -> e.getTokenProfileUuid() != null && e.getTokenProfileUuid().equals(tokenProfileUuid.get())).collect(Collectors.toList());
        }
        response = response
                .stream()
                .filter(
                        e -> e.getItems().size() == 2
                ).filter(
                        e -> e.getItems().stream().filter(i -> i.getState().equals(KeyState.ACTIVE)).count() == 2
                )
                .filter(
                        e -> {
                            List<KeyType> keyTypes = e.getItems().stream().map(KeyItemDto::getType).collect(Collectors.toList());
                            keyTypes.removeAll(List.of(KeyType.PUBLIC_KEY, KeyType.PRIVATE_KEY));
                            return keyTypes.isEmpty();
                        }
                ).collect(Collectors.toList());
        return response;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DETAIL, parentResource = Resource.TOKEN, parentAction = ResourceAction.MEMBERS)
    public KeyDetailDto getKey(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid) throws NotFoundException {
        logger.info("Requesting details of the Key with UUID {} for Token profile {}", uuid, tokenInstanceUuid);
        CryptographicKey key = getCryptographicKeyEntityWithAssociations(uuid.getValue());
        KeyDetailDto dto = key.mapToDetailDto();
        logger.debug("Key details: {}", dto);

        dto.setAttributes(attributeEngine.getObjectDataAttributesContent(key.getTokenInstanceReference().getConnectorUuid(), null, Resource.CRYPTOGRAPHIC_KEY, key.getUuid()));
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, key.getUuid()));
        dto.getItems().forEach(k -> k.setMetadata(attributeEngine.getMappedMetadataContent(new ObjectAttributeContentInfo(Resource.CRYPTOGRAPHIC_KEY, UUID.fromString(k.getUuid())))));
        logger.debug("Key details with attributes {}", dto);
        return dto;
    }


    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DETAIL, parentResource = Resource.TOKEN, parentAction = ResourceAction.MEMBERS)
    public KeyItemDetailDto getKeyItem(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid, String keyItemUuid) throws NotFoundException {
        logger.info("Requesting details of the Key Item {} with UUID {} for Token profile {}", keyItemUuid, uuid, tokenInstanceUuid);
        CryptographicKey key = getCryptographicKeyEntity(uuid.getValue());
        CryptographicKeyItem item = cryptographicKeyItemRepository.findByUuidAndCryptographicKey(
                UUID.fromString(keyItemUuid),
                key
        ).orElseThrow(
                () -> new NotFoundException(CryptographicKeyItem.class, keyItemUuid)
        );
        KeyItemDetailDto dto = item.mapToDto();
        logger.debug("Key details: {}", dto);
        dto.setMetadata(attributeEngine.getMappedMetadataContent(new ObjectAttributeContentInfo(Resource.CRYPTOGRAPHIC_KEY, item.getUuid())));
        logger.debug("Key details with attributes {}", dto);
        return dto;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.CREATE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public KeyDetailDto createKey(UUID tokenInstanceUuid, SecuredParentUUID tokenProfileUuid, KeyRequestType type, KeyRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException, AttributeException {
        logger.error("Creating a new key for Token profile {}. Input: {}", tokenProfileUuid, request);
        if (cryptographicKeyRepository.findByName(request.getName()).isPresent()) {
            logger.error("Key with same name already exists");
            throw new AlreadyExistException("Existing Key with same already exists");
        }
        if (request.getName() == null) {
            logger.error("Name is empty. Cannot create key without name");
            throw new ValidationException(ValidationError.create("Name is required for creating a new Key"));
        }
        TokenInstanceReference tokenInstanceReference = tokenInstanceService.getTokenInstanceEntity(SecuredUUID.fromUUID(tokenInstanceUuid));
        TokenProfile tokenProfile = tokenProfileRepository.findByUuid(
                        tokenProfileUuid)
                .orElseThrow(
                        () -> new NotFoundException(
                                TokenInstanceReference.class,
                                tokenProfileUuid
                        )
                );

        attributeEngine.validateCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, request.getCustomAttributes());
        mergeAndValidateAttributes(type, tokenInstanceReference, request.getAttributes());

        logger.debug("Token instance detail: {}", tokenInstanceReference);
        Connector connector = tokenInstanceReference.getConnector();
        logger.debug("Connector details: {}", connector);
        CreateKeyRequestDto createKeyRequestDto = new CreateKeyRequestDto();
        createKeyRequestDto.setCreateKeyAttributes(request.getAttributes());
        createKeyRequestDto.setTokenProfileAttributes(attributeEngine.getRequestObjectDataAttributesContent(tokenProfile.getTokenInstanceReference().getConnectorUuid(), null, Resource.TOKEN_PROFILE, tokenProfile.getUuid()));

        CryptographicKey key;
        if (type.equals(KeyRequestType.KEY_PAIR)) {
            key = createKeyTypeOfKeyPair(
                    connector,
                    tokenProfile,
                    request,
                    createKeyRequestDto
            );
        } else {
            key = createKeyTypeOfSecret(
                    connector,
                    tokenProfile,
                    request,
                    createKeyRequestDto
            );
        }

        // set owner of certificate to logged user
        objectAssociationService.setOwnerFromProfile(Resource.CRYPTOGRAPHIC_KEY, key.getUuid());
        if(request.getGroupUuids() != null) {
            objectAssociationService.setGroups(Resource.CRYPTOGRAPHIC_KEY, key.getUuid(), request.getGroupUuids().stream().map(UUID::fromString).collect(Collectors.toSet()));
        }

        logger.debug("Key creation is successful. UUID is {}", key.getUuid());
        KeyDetailDto keyDetailDto = key.mapToDetailDto();
        keyDetailDto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, key.getUuid(), request.getCustomAttributes()));
        keyDetailDto.setAttributes(attributeEngine.updateObjectDataAttributesContent(tokenInstanceReference.getConnectorUuid(), null, Resource.CRYPTOGRAPHIC_KEY, key.getUuid(), request.getAttributes()));

        logger.debug("Key details: {}", keyDetailDto);
        return keyDetailDto;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.CHANGE)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE, parentResource = Resource.TOKEN, parentAction = ResourceAction.MEMBERS)
    public KeyDetailDto editKey(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid, EditKeyRequestDto request) throws NotFoundException, AttributeException {
        logger.info("Updating the key with uuid {}. Request: {}", uuid, request);
        CryptographicKey key = getCryptographicKeyEntity(uuid.getValue());

        attributeEngine.validateCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, request.getCustomAttributes());

        if (request.getName() != null && !request.getName().isEmpty()) key.setName(request.getName());
        if (request.getDescription() != null) key.setDescription(request.getDescription());
        if (request.getTokenProfileUuid() != null) {
            TokenProfile tokenProfile = tokenProfileRepository.findByUuid(
                            SecuredUUID.fromString(request.getTokenProfileUuid()))
                    .orElseThrow(
                            () -> new NotFoundException(
                                    TokenInstanceReference.class,
                                    request.getTokenProfileUuid()
                            )
                    );
            if (!tokenProfile.getTokenInstanceReferenceUuid().equals(key.getTokenInstanceReferenceUuid())) {
                throw new ValidationException(
                        ValidationError.create(
                                "Cannot assign Token Profile from different provider"
                        )
                );
            }
            key.setTokenProfile(tokenProfile);
        }
        key = cryptographicKeyRepository.save(key);

        if(request.getGroupUuids() != null) {
            objectAssociationService.setGroups(Resource.CRYPTOGRAPHIC_KEY, key.getUuid(), request.getGroupUuids().stream().map(UUID::fromString).collect(Collectors.toSet()));
        }
        if (request.getOwnerUuid() != null) {
            objectAssociationService.setOwner(Resource.CRYPTOGRAPHIC_KEY, key.getUuid(), UUID.fromString(request.getOwnerUuid()));
        }
        attributeEngine.updateObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, key.getUuid(), request.getCustomAttributes());

        logger.debug("Key details updated. Key: {}", key);
        return getKey(tokenInstanceUuid, uuid);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.DISABLE)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ENABLE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void disableKey(SecuredParentUUID tokenInstanceUuid, UUID uuid, List<String> keyUuids) throws NotFoundException, ValidationException {
        logger.info("Request to disable the key with UUID {} on token instance {}", uuid, tokenInstanceUuid);
        if (keyUuids != null && !keyUuids.isEmpty()) {
            setKeyItemsEnabled(keyUuids, false, false);
        } else {
            disableKey(List.of(uuid.toString()));
        }
        logger.info("Key disabled: {}", uuid);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.ENABLE)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ENABLE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void enableKey(SecuredParentUUID tokenInstanceUuid, UUID uuid, List<String> keyUuids) throws NotFoundException, ValidationException {
        logger.info("Request to enable the key with UUID {} on token instance {}", uuid, tokenInstanceUuid);

        if (keyUuids != null && !keyUuids.isEmpty()) {
            setKeyItemsEnabled(keyUuids, false, true);
        } else {
            enableKey(List.of(uuid.toString()));
        }
        logger.info("Key enabled: {}", uuid);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.DISABLE)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ENABLE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void disableKey(List<String> uuids) {
        logger.info("Request to disable the key with UUID {} ", uuids);
        for (String keyUuid : new LinkedHashSet<>(uuids)) {
            try {
                CryptographicKey key = getCryptographicKeyEntity(UUID.fromString(keyUuid));
                List<String> keyItemUuids = key.getItems().stream().map(keyItem -> keyItem.getUuid().toString()).collect(Collectors.toList());
                setKeyItemsEnabled(keyItemUuids, true, false);
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
        logger.info("Key disabled: {}", uuids);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.ENABLE)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ENABLE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void enableKey(List<String> uuids) {
        logger.info("Request to enable the key with UUID {} ", uuids);
        for (String keyUuid : new LinkedHashSet<>(uuids)) {
            try {
                CryptographicKey key = getCryptographicKeyEntity(UUID.fromString(keyUuid));
                List<String> keyItemUuids = key.getItems().stream().map(keyItem -> keyItem.getUuid().toString()).collect(Collectors.toList());
                setKeyItemsEnabled(keyItemUuids, true, true);
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
        logger.info("Key enabled: {}", uuids);
    }

    @Override
    public void enableKeyItems(List<String> uuids) {
        setKeyItemsEnabled(uuids, true, true);
    }

    @Override
    public void disableKeyItems(List<String> uuids) {
        setKeyItemsEnabled(uuids, true, false);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.DELETE)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DELETE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void deleteKey(SecuredParentUUID tokenInstanceUuid, UUID uuid, List<String> keyItemUuids) throws NotFoundException, ConnectorException {
        logger.info("Request to deleted the key with UUID {} on token instance {}", uuid, tokenInstanceUuid);
        CryptographicKey key = getCryptographicKeyEntity(uuid);
        if (key.getTokenProfile() != null) {
            permissionEvaluator.tokenProfile(key.getTokenProfile().getSecuredUuid());
        }
        if (keyItemUuids != null && !keyItemUuids.isEmpty()) {
            for (String keyUuid : new LinkedHashSet<>(keyItemUuids)) {
                CryptographicKeyItem keyItem = cryptographicKeyItemRepository
                        .findByUuid(UUID.fromString(keyUuid))
                        .orElseThrow(
                                () -> new NotFoundException(
                                        "Sub key with the UUID " + keyUuid + " is not found",
                                        CryptographicKeyItem.class
                                )
                        );

                try {
                    keyManagementApiClient.destroyKey(
                            key.getTokenInstanceReference().getConnector().mapToDto(),
                            key.getTokenInstanceReference().getTokenInstanceUuid(),
                            keyItem.getKeyReferenceUuid().toString()
                    );
                    logger.info("Key item destroyed in the connector. Removing from the core now.");
                } catch (NotFoundException e) {
                    logger.info("Key item already destroyed in the connector.");
                }
                key.getItems().remove(keyItem);
                attributeEngine.deleteAllObjectAttributeContent(Resource.CRYPTOGRAPHIC_KEY, keyItem.getUuid());
                cryptographicKeyItemRepository.delete(keyItem);
                cryptographicKeyRepository.save(key);
            }
            if (key.getItems().isEmpty()) {
                deleteKeyWithAssociations(key);
            }
        } else {
            deleteKey(List.of(uuid.toString()));
        }
        logger.info("Key deleted: {}", uuid);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.DELETE)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DELETE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void deleteKey(List<String> uuids) throws ConnectorException {
        logger.info("Request to deleted the keys with UUIDs {}", uuids);
        for (String uuid : uuids) {
            try {
                CryptographicKey key = getCryptographicKeyEntity(UUID.fromString(uuid));
                if (key.getTokenProfile() != null) {
                    permissionEvaluator.tokenProfile(key.getTokenProfile().getSecuredUuid());
                }
                for (CryptographicKeyItem keyItem : key.getItems()) {
                    try {
                        keyManagementApiClient.destroyKey(
                                key.getTokenInstanceReference().getConnector().mapToDto(),
                                key.getTokenInstanceReference().getTokenInstanceUuid(),
                                keyItem.getKeyReferenceUuid().toString()
                        );
                        logger.info("Key item destroyed in the connector. Removing from the core now.");
                    } catch (NotFoundException e) {
                        logger.info("Key item already destroyed in the connector.");
                    }
                    attributeEngine.deleteAllObjectAttributeContent(Resource.CRYPTOGRAPHIC_KEY, keyItem.getUuid());
                    cryptographicKeyItemRepository.delete(keyItem);
                }
                deleteKeyWithAssociations(key);
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
        logger.info("Keys deleted: {}", uuids);
    }

    @Override
    public void deleteKeyItems(List<String> keyItemUuids) throws ConnectorException {
        logger.info("Request to deleted the key items with UUIDs {}", keyItemUuids);
        for (String uuid : keyItemUuids) {
            try {
                CryptographicKeyItem keyItem = getCryptographicKeyItem(UUID.fromString(uuid));
                CryptographicKey key = keyItem.getCryptographicKey();
                permissionEvaluator.tokenInstance(keyItem.getCryptographicKey().getTokenInstanceReference().getSecuredUuid());
                if (keyItem.getCryptographicKey().getTokenProfile() != null) {
                    permissionEvaluator.tokenProfile(keyItem.getCryptographicKey().getTokenProfile().getSecuredUuid());
                }
                try {
                    keyManagementApiClient.destroyKey(
                            key.getTokenInstanceReference().getConnector().mapToDto(),
                            key.getTokenInstanceReference().getTokenInstanceUuid(),
                            keyItem.getKeyReferenceUuid().toString()
                    );
                    logger.info("Key item destroyed in the connector. Removing from the core now.");
                } catch (NotFoundException e) {
                    logger.info("Key item already destroyed in the connector.");
                }
                attributeEngine.deleteAllObjectAttributeContent(Resource.CRYPTOGRAPHIC_KEY, keyItem.getUuid());
                cryptographicKeyItemRepository.delete(keyItem);
                key.getItems().remove(keyItem);
                if (key.getItems().isEmpty()) {
                    deleteKeyWithAssociations(key);
                }
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
        logger.info("Key Items deleted: {}", keyItemUuids);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DELETE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void destroyKey(SecuredParentUUID tokenInstanceUuid, String uuid, List<String> keyUuids) throws ConnectorException {
        logger.info("Request to destroy the key with UUID {} on token profile {}", uuid, tokenInstanceUuid);
        if (keyUuids != null && !keyUuids.isEmpty()) {
            destroyKeyItems(keyUuids, false);
        } else {
            destroyKey(List.of(uuid));
        }
        logger.info("Key destroyed: {}", uuid);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.DELETE)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DELETE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void destroyKey(List<String> uuids) throws ConnectorException {
        logger.info("Request to destroy the key with UUIDs {}", uuids);
        for (String uuid : uuids) {
            CryptographicKey key = getCryptographicKeyEntity(UUID.fromString(uuid));
            List<String> keyItemUuids = key.getItems().stream().map(keyItem -> keyItem.getUuid().toString()).collect(Collectors.toList());
            destroyKeyItems(keyItemUuids, true);
        }
        logger.info("Key destroyed: {}", uuids);
    }

    @Override
    public void destroyKeyItems(List<String> keyItemUuids) throws ConnectorException {
        destroyKeyItems(keyItemUuids, true);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ANY, parentResource = Resource.TOKEN_PROFILE, parentAction = ResourceAction.DETAIL)
    public List<BaseAttribute> listCreateKeyAttributes(UUID tokenInstanceUuid, SecuredParentUUID tokenProfileUuid, KeyRequestType type) throws ConnectorException {
        logger.info("Request to list the attributes for creating a new key on Token profile: {}", tokenProfileUuid);
        TokenProfile tokenProfile = tokenProfileRepository.findByUuid(
                        tokenProfileUuid.getValue())
                .orElseThrow(
                        () -> new NotFoundException(
                                TokenInstanceReference.class,
                                tokenProfileUuid
                        )
                );
        logger.debug("Token profile details: {}", tokenProfile);
        List<BaseAttribute> attributes;
        if (type.equals(KeyRequestType.KEY_PAIR)) {
            attributes = keyManagementApiClient.listCreateKeyPairAttributes(
                    tokenProfile.getTokenInstanceReference().getConnector().mapToDto(),
                    tokenProfile.getTokenInstanceReference().getTokenInstanceUuid()
            );
        } else {
            attributes = keyManagementApiClient.listCreateSecretKeyAttributes(
                    tokenProfile.getTokenInstanceReference().getConnector().mapToDto(),
                    tokenProfile.getTokenInstanceReference().getTokenInstanceUuid()
            );
        }
        logger.debug("Attributes for the new creation: {}", attributes);
        return attributes;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void syncKeys(SecuredParentUUID tokenInstanceUuid) throws ConnectorException, AttributeException {
        TokenInstanceReference tokenInstanceReference = tokenInstanceService.getTokenInstanceEntity(
                tokenInstanceUuid
        );
        //Create a map to hold the key and its objects. The association key will be used as the name for the parent key object
        Map<String, List<KeyDataResponseDto>> associations = new HashMap<>();
        // Get the list of keys from the connector
        List<KeyDataResponseDto> keys = keyManagementApiClient.listKeys(
                tokenInstanceReference.getConnector().mapToDto(),
                tokenInstanceReference.getTokenInstanceUuid()
        );

        // Iterate and add the keys with the same associations to the map
        for (KeyDataResponseDto key : keys) {
            associations.computeIfAbsent(
                    (key.getAssociation() == null || key.getAssociation().isEmpty()) ? "" : key.getAssociation(),
                    k -> new ArrayList<>()
            ).add(key);
        }
        logger.debug("Total number of keys from the connector: {}", keys.size());

        // Iterate through the created map and store the items in the database
        for (Map.Entry<String, List<KeyDataResponseDto>> entry : associations.entrySet()) {
            // If the key is empty then it is individual entity. Probably only private or public key or Secret Key
            if (entry.getKey().isEmpty()) {
                for (KeyDataResponseDto soleEntity : entry.getValue()) {
                    createKeyAndItems(
                            tokenInstanceReference.getConnectorUuid(),
                            tokenInstanceReference,
                            soleEntity.getName(),
                            List.of(soleEntity)
                    );
                }
            } else {
                createKeyAndItems(
                        tokenInstanceReference.getConnectorUuid(),
                        tokenInstanceReference,
                        entry.getKey(),
                        entry.getValue()
                );
            }
        }
        logger.info("Sync Key Completed");
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.CHANGE)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void compromiseKey(SecuredParentUUID tokenInstanceUuid, UUID uuid, CompromiseKeyRequestDto request) throws NotFoundException {
        logger.info("Request to compromise the key with UUID {} on token instance {}", uuid, tokenInstanceUuid);
        List<UUID> keyUuids = request.getUuids();
        if (keyUuids != null && !keyUuids.isEmpty()) {
            compromiseKeyItems(keyUuids, false, request.getReason());
        } else {
            compromiseKey(new BulkCompromiseKeyRequestDto(request.getReason(), List.of(uuid)));
        }
        logger.info("Key marked as compromised: {}", uuid);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.CHANGE)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void compromiseKey(BulkCompromiseKeyRequestDto request) {
        List<UUID> uuids = request.getUuids();
        logger.info("Request to mark the key as compromised with UUIDs {}", uuids);
        for (UUID uuid : uuids) {
            try {
                CryptographicKey key = getCryptographicKeyEntity(uuid);
                List<UUID> keyItemUuids = key.getItems().stream().map(UniquelyIdentified::getUuid).toList();
                compromiseKeyItems(keyItemUuids, true, request.getReason());
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
        logger.info("Key marked as compromised: {}", uuids);
    }

    @Override
    public void compromiseKeyItems(BulkCompromiseKeyItemRequestDto request) {
        compromiseKeyItems(request.getUuids(), true, request.getReason());
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.CHANGE)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void updateKeyUsages(BulkKeyUsageRequestDto request) {
        logger.info("Request to update the key usages with UUIDs {}", request.getUuids());
        for (UUID uuid : request.getUuids()) {
            try {
                CryptographicKey key = getCryptographicKeyEntity(uuid);
                List<UUID> keyItemsUuids = key.getItems().stream().map(UniquelyIdentified::getUuid).toList();
                setKeyItemsUsages(keyItemsUuids, request.getUsage(), false);
            } catch (Exception e) {
                logger.warn(e.getMessage());
            }
        }
        logger.info("Key usages updated: {}", request.getUuids());
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CRYPTOGRAPHIC_KEY, operation = OperationType.CHANGE)
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void updateKeyUsages(SecuredParentUUID tokenInstanceUuid, UUID uuid, UpdateKeyUsageRequestDto request) throws NotFoundException {
        logger.info("Request to update the key usages with UUID {} on token instance {}", uuid, tokenInstanceUuid);
        if (request.getUuids() != null && !request.getUuids().isEmpty()) {
            setKeyItemsUsages(request.getUuids(), request.getUsage(), true);
        } else {
            BulkKeyUsageRequestDto requestDto = new BulkKeyUsageRequestDto();
            requestDto.setUsage(request.getUsage());
            requestDto.setUuids(List.of(uuid));
            updateKeyUsages(requestDto);
        }
        logger.info("Key usages updated: {}", uuid);
    }

    @Override
    public void updateKeyItemUsages(BulkKeyItemUsageRequestDto request) {
        setKeyItemsUsages(request.getUuids(), request.getUsage(), false);
    }

    @Override
    public List<KeyEventHistoryDto> getEventHistory(SecuredParentUUID tokenInstanceUuid, UUID uuid, UUID keyItemUuid) throws NotFoundException {
        logger.info("Request to get the list of events for the key item");
        return keyEventHistoryService.getKeyEventHistory(keyItemUuid);
    }

    @Override
    public UUID findKeyByFingerprint(String fingerprint) {
        CryptographicKeyItem item = cryptographicKeyItemRepository.findByFingerprint(fingerprint).orElse(null);
        if (item != null) {
            return item.getCryptographicKey().getUuid();
        }
        return null;
    }

    @Override
    public CryptographicKeyItem getKeyItemFromKey(CryptographicKey key, KeyType keyType) {
        for (CryptographicKeyItem item : key.getItems()) {
            if (item.getType().equals(keyType)) {
                return item;
            }
        }
        return null;
    }

    @Override
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter) {
        return null;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getCryptographicKeyEntity(uuid.getValue());
    }

    private void createKeyAndItems(UUID connectorUuid, TokenInstanceReference tokenInstanceReference, String key, List<KeyDataResponseDto> items) throws AttributeException {
        //Iterate through the items for a specific key
        if (checkKeyAlreadyExists(tokenInstanceReference.getUuid(), items)) {
            return;
        }
        // Create the cryptographic Key
        KeyRequestDto dto = new KeyRequestDto();
        dto.setName(key);
        dto.setDescription("Discovered from " + tokenInstanceReference.getName());
        CryptographicKey cryptographicKey = createKeyEntity(dto, null, tokenInstanceReference);
        // Create the items for each key
        Set<CryptographicKeyItem> children = new HashSet<>();
        for (KeyDataResponseDto item : items) {
            children.add(
                    createKeyContent(
                            item.getUuid(),
                            item.getName(),
                            item.getKeyData(),
                            cryptographicKey,
                            connectorUuid,
                            true,
                            false
                    )
            );
        }
        cryptographicKey.setItems(children);
        cryptographicKeyRepository.save(cryptographicKey);
    }

    private boolean checkKeyAlreadyExists(UUID tokenInstanceUuid, List<KeyDataResponseDto> items) {
        //Iterate through the items for a specific key
        for (KeyDataResponseDto item : items) {
            //check if the item with the reference uuid already exists in the database
            // Assumption - Content of the key from earlier does not change
            for (CryptographicKeyItem keyItem : cryptographicKeyItemRepository.findByKeyReferenceUuid(UUID.fromString(item.getUuid()))) {
                if (keyItem.getCryptographicKey().getTokenInstanceReferenceUuid().equals(tokenInstanceUuid)) {
                    return true;
                }
            }
        }
        return false;
    }

    private CryptographicKey createKeyEntity(KeyRequestDto request, TokenProfile tokenProfile, TokenInstanceReference tokenInstanceReference) {
        CryptographicKey key = new CryptographicKey();
        key.setName(request.getName());
        key.setDescription(request.getDescription());
        key.setTokenProfile(tokenProfile);
        key.setTokenInstanceReference(tokenInstanceReference);

        logger.debug("Cryptographic Key: {}", key);
        return cryptographicKeyRepository.save(key);
    }

    private CryptographicKeyItem createKeyContent(String referenceUuid, String referenceName, KeyData keyData, CryptographicKey cryptographicKey, UUID connectorUuid, boolean isDiscovered, boolean enabled) throws AttributeException {
        logger.info("Creating the Key Content for {}", cryptographicKey);
        CryptographicKeyItem keyItem = new CryptographicKeyItem();
        keyItem.setName(referenceName);
        keyItem.setCryptographicKey(cryptographicKey);
        keyItem.setType(keyData.getType());
        keyItem.setKeyAlgorithm(keyData.getAlgorithm());
        keyItem.setKeyData(keyData.getFormat(), keyData.getValue());
        keyItem.setFormat(keyData.getFormat());
        keyItem.setLength(keyData.getLength());
        keyItem.setKeyReferenceUuid(UUID.fromString(referenceUuid));
        keyItem.setState(KeyState.ACTIVE);
        keyItem.setEnabled(enabled);
        if (cryptographicKey.getTokenProfile() != null) {
            keyItem.setUsage(
                    cryptographicKey
                            .getTokenProfile()
                            .getUsage()
                            .stream()
                            .filter(
                                    not(getForbiddenUsages(keyData.getType(), keyData.getAlgorithm())::contains)
                            )
                            .collect(
                                    Collectors.toList()
                            )
            );
        }
        try {
            keyItem.setFingerprint(CertificateUtil.getThumbprint(keyItem.getKeyData().getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException | NullPointerException e) {
            logger.error("Failed to calculate the fingerprint {}", e.getMessage());
        }
        cryptographicKeyItemRepository.save(keyItem);
        String message;
        if (isDiscovered) {
            message = "Key Discovered from Token Instance "
                    + cryptographicKey.getTokenInstanceReference().getName();
        } else {
            message = "Key Created from Token Profile "
                    + cryptographicKey.getTokenProfile().getName()
                    + " on Token Instance "
                    + cryptographicKey.getTokenInstanceReference().getName();
        }
        keyEventHistoryService.addEventHistory(
                KeyEvent.CREATE,
                KeyEventStatus.SUCCESS,
                message,
                null,
                keyItem.getUuid()
        );

        attributeEngine.updateMetadataAttributes(keyData.getMetadata(), new ObjectAttributeContentInfo(connectorUuid, Resource.CRYPTOGRAPHIC_KEY, UUID.fromString(keyItem.getUuid().toString()), Resource.CRYPTOGRAPHIC_KEY, cryptographicKey.getUuid(), cryptographicKey.getName()));
        if (keyData.getType().equals(KeyType.PUBLIC_KEY)) {
            certificateService.updateCertificateKeys(cryptographicKey.getUuid(), keyItem.getFingerprint());
        }

        return keyItem;
    }

    private CryptographicKey getCryptographicKeyEntity(UUID uuid) throws NotFoundException {
        return cryptographicKeyRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(CryptographicKey.class, uuid));
    }

    private CryptographicKey getCryptographicKeyEntityWithAssociations(UUID uuid) throws NotFoundException {
        return cryptographicKeyRepository.findWithAssociationsByUuid(uuid).orElseThrow(() -> new NotFoundException(CryptographicKey.class, uuid));
    }

    private void mergeAndValidateAttributes(KeyRequestType type, TokenInstanceReference tokenInstanceRef, List<RequestAttributeDto> attributes) throws ConnectorException, AttributeException {
        logger.debug("Merging and validating attributes on token instance {}. Request Attributes are: {}", tokenInstanceRef, attributes);
        if (tokenInstanceRef.getConnector() == null) {
            throw new ValidationException(ValidationError.create("Connector of the Token is not available / deleted"));
        }

        ConnectorDto connectorDto = tokenInstanceRef.getConnector().mapToDto();

        // validate first by connector and list attributes definitions
        List<BaseAttribute> definitions;
        if (type.equals(KeyRequestType.KEY_PAIR)) {
            keyManagementApiClient.validateCreateKeyPairAttributes(connectorDto, tokenInstanceRef.getTokenInstanceUuid(), attributes);
            definitions = keyManagementApiClient.listCreateKeyPairAttributes(connectorDto, tokenInstanceRef.getTokenInstanceUuid());
        } else {
            keyManagementApiClient.validateCreateSecretKeyAttributes(connectorDto, tokenInstanceRef.getTokenInstanceUuid(), attributes);
            definitions = keyManagementApiClient.listCreateSecretKeyAttributes(connectorDto, tokenInstanceRef.getTokenInstanceUuid());
        }

        // validate and update definitions with attribute engine
        attributeEngine.validateUpdateDataAttributes(tokenInstanceRef.getConnectorUuid(), null, definitions, attributes);
    }

    private CryptographicKey createKeyTypeOfKeyPair(Connector connector, TokenProfile tokenProfile, KeyRequestDto request, CreateKeyRequestDto createKeyRequestDto) throws ConnectorException, AttributeException {
        boolean enabled = Boolean.TRUE.equals(request.getEnabled());
        KeyPairDataResponseDto response = keyManagementApiClient.createKeyPair(
                connector.mapToDto(),
                tokenProfile.getTokenInstanceReference().getTokenInstanceUuid(),
                createKeyRequestDto
        );
        logger.debug("Response from the connector for the new Key creation: {}", response);
        Set<CryptographicKeyItem> children = new HashSet<>();
        CryptographicKey key = createKeyEntity(request, tokenProfile, tokenProfile.getTokenInstanceReference());
        children.add(createKeyContent(
                response.getPrivateKeyData().getUuid(),
                response.getPrivateKeyData().getName(),
                response.getPrivateKeyData().getKeyData(),
                key,
                connector.getUuid(),
                false,
                enabled
        ));
        children.add(createKeyContent(
                response.getPublicKeyData().getUuid(),
                response.getPrivateKeyData().getName(),
                response.getPublicKeyData().getKeyData(),
                key,
                connector.getUuid(),
                false,
                enabled
        ));
        key.setItems(children);
        return cryptographicKeyRepository.save(key);
    }

    private CryptographicKey createKeyTypeOfSecret(Connector connector, TokenProfile tokenProfile, KeyRequestDto request, CreateKeyRequestDto createKeyRequestDto) throws ConnectorException, AttributeException {
        KeyDataResponseDto response = keyManagementApiClient.createSecretKey(
                connector.mapToDto(),
                tokenProfile.getTokenInstanceReference().getTokenInstanceUuid(),
                createKeyRequestDto
        );
        logger.debug("Response from the connector for the new Key creation: {}", response);
        CryptographicKey key = createKeyEntity(request, tokenProfile, tokenProfile.getTokenInstanceReference());
        key.setItems(
                Set.of(
                        createKeyContent(
                                response.getUuid(),
                                response.getName(),
                                response.getKeyData(),
                                key,
                                connector.getUuid(),
                                false,
                                Boolean.TRUE.equals(request.getEnabled()
                                )
                        )
                )
        );

        return cryptographicKeyRepository.save(key);
    }

    /**
     * Function to enable/disable the key
     *
     * @param keyItemsUuids UUIDs of the Key Items
     */
    private void setKeyItemsEnabled(List<String> keyItemsUuids, boolean evaluateTokenPermission, boolean enabled) {
        logger.info("Request to set the key items with UUIDs {} {}", keyItemsUuids, enabled ? "enabled" : "disabled");
        List<String> errors = new ArrayList<>();
        if (keyItemsUuids != null && !keyItemsUuids.isEmpty()) {
            for (String keyItemUuid : new LinkedHashSet<>(keyItemsUuids)) {
                try {
                    if (!setKeyItemEnabled(UUID.fromString(keyItemUuid), evaluateTokenPermission, enabled)) {
                        errors.add(keyItemUuid);
                    }
                } catch (NotFoundException e) {
                    logger.warn(e.getMessage());
                }
            }
        }
        if (!errors.isEmpty()) {
            throw new ValidationException(errors.stream().map(ValidationError::create).toList());
        }
        logger.info("Key items {}: {}", enabled ? "enabled" : "disabled", keyItemsUuids);
    }

    /**
     * Function to enable/disable the key
     *
     * @param uuid UUID of the Key Item
     */
    private boolean setKeyItemEnabled(UUID uuid, boolean evaluateTokenPermission, boolean enabled) throws NotFoundException {
        CryptographicKeyItem keyItem = getKeyItem(uuid, evaluateTokenPermission);
        if (keyItem.isEnabled() == enabled) {
            String message = "Key " + uuid + " is already " + (enabled ? "enabled." : "disabled.");
            keyEventHistoryService.addEventHistory(KeyEvent.ENABLE, KeyEventStatus.FAILED, message, null, keyItem);
            return false;
        }
        keyItem.setEnabled(enabled);
        cryptographicKeyItemRepository.save(keyItem);
        keyEventHistoryService.addEventHistory(enabled ? KeyEvent.ENABLE : KeyEvent.DISABLE, KeyEventStatus.SUCCESS, "Key " + (enabled ? "enabled." : "disabled."), null, keyItem);
        return true;
    }

    /**
     * Function to mark keys as compromised
     *
     * @param keyItemsUuids UUIDs of the Key Items
     */
    private void compromiseKeyItems(List<UUID> keyItemsUuids, boolean evaluateTokenPermission, KeyCompromiseReason reason) {
        logger.info("Request to mark the key items as compromised with UUIDs {}", keyItemsUuids);
        List<String> errors = new ArrayList<>();
        if (keyItemsUuids != null && !keyItemsUuids.isEmpty()) {
            for (UUID keyItemUuid : new LinkedHashSet<>(keyItemsUuids)) {
                try {
                    if (!compromiseKeyItem(keyItemUuid, reason, evaluateTokenPermission)) {
                        errors.add(keyItemUuid.toString());
                    }
                } catch (NotFoundException e) {
                    logger.warn(e.getMessage());
                }
            }
        }
        if (!errors.isEmpty()) {
            throw new ValidationException(errors.stream().map(ValidationError::create).toList());
        }
        logger.info("Key Items marked as compromised: {}", keyItemsUuids);
    }

    /**
     * Function to mark a key as compromised
     *
     * @param uuid UUID of the Key Item
     */
    private boolean compromiseKeyItem(UUID uuid, KeyCompromiseReason reason, boolean evaluateTokenPermission) throws NotFoundException {
        CryptographicKeyItem keyItem = getKeyItem(uuid, evaluateTokenPermission);
        if (!keyItem.getState().equals(KeyState.PRE_ACTIVE) && !keyItem.getState().equals(KeyState.ACTIVE) && !keyItem.getState().equals(KeyState.DEACTIVATED)) {
            String message = "Invalid state of key " + uuid + ". Key is " + keyItem.getState().getLabel() + ", hence can't be set to " + KeyState.COMPROMISED.getLabel() + ".";
            keyEventHistoryService.addEventHistory(KeyEvent.COMPROMISED, KeyEventStatus.FAILED,
                    message, null, keyItem);
            return false;
        }
        keyItem.setState(KeyState.COMPROMISED);
        keyItem.setReason(reason);
        cryptographicKeyItemRepository.save(keyItem);
        keyEventHistoryService.addEventHistory(KeyEvent.COMPROMISED, KeyEventStatus.SUCCESS, "Key compromised. Reason: " + reason + ".", null, keyItem);
        return true;
    }

    private void setKeyItemsUsages(List<UUID> keyItemsUuids, List<KeyUsage> usages, boolean evaluateTokenPermission) {
        logger.info("Request to update usages of key items with UUIDs {}", keyItemsUuids);
        List<String> errors = new ArrayList<>();
        if (keyItemsUuids != null && !keyItemsUuids.isEmpty()) {
            for (UUID keyItemUuid : new LinkedHashSet<>(keyItemsUuids)) {
                try {
                    if (!setKeyItemUsages(keyItemUuid, usages, evaluateTokenPermission)) {
                        errors.add(keyItemUuid.toString());
                    }
                } catch (Exception e) {
                    logger.warn(e.getMessage());
                }
            }
        }
        if (!errors.isEmpty()) {
            throw new ValidationException(errors.stream().map(ValidationError::create).toList());
        }
        logger.info("Key items usages updated: {}", keyItemsUuids);
    }

    /**
     * Function to update the usage of the key
     *
     * @param uuid UUID of the Key Item
     */
    private boolean setKeyItemUsages(UUID uuid, List<KeyUsage> usages, boolean evaluateTokenPermission) throws NotFoundException {
        CryptographicKeyItem content = getKeyItem(uuid, evaluateTokenPermission);

        List<KeyUsage> forbiddenUsages = getForbiddenUsages(content.getType(), content.getKeyAlgorithm()).stream().filter(usages::contains).toList();
        if (!forbiddenUsages.isEmpty()) {
            String nonAllowedUsages = forbiddenUsages.stream().map(KeyUsage::getCode).collect(Collectors.joining(", "));
            String message = "Unsupported usages of key " + uuid + ": " + nonAllowedUsages + ".";
            keyEventHistoryService.addEventHistory(KeyEvent.UPDATE_USAGE, KeyEventStatus.FAILED, message, null, content);
            return false;
        }
        String oldUsage = content.getUsage().stream().map(KeyUsage::getCode).collect(Collectors.joining(", "));
        content.setUsage(usages);
        cryptographicKeyItemRepository.save(content);
        String newUsage = usages.stream().map(KeyUsage::getCode).collect(Collectors.joining(", "));
        keyEventHistoryService.addEventHistory(KeyEvent.UPDATE_USAGE, KeyEventStatus.SUCCESS,
                "Key usages updated from " + oldUsage + " to " + newUsage + ".", null, content);
        return true;
    }

    /**
     * Function to destroy the key items
     *
     * @param keyItemUuids UUIDs of the Key Items
     */
    private void destroyKeyItems(List<String> keyItemUuids, boolean evaluateTokenPermission) throws ConnectorException {
        logger.info("Request to destroy the key items with UUIDs {}", keyItemUuids);
        List<String> errors = new ArrayList<>();
        if (keyItemUuids != null && !keyItemUuids.isEmpty()) {
            for (String uuid : new LinkedHashSet<>(keyItemUuids)) {
                try {
                    if (!destroyKeyItem(UUID.fromString(uuid), evaluateTokenPermission)) {
                        errors.add(uuid);
                    }
                } catch (Exception e) {
                    logger.warn(e.getLocalizedMessage());
                }
            }
        }
        if (!errors.isEmpty()) {
            throw new ValidationException(errors.stream().map(ValidationError::create).toList());
        }
        logger.info("Key Items destroyed: {}", keyItemUuids);
    }

    /**
     * Function to destroy the key
     *
     * @param uuid UUID of the Key Item
     */
    private boolean destroyKeyItem(UUID uuid, boolean evaluateTokenPermission) throws ConnectorException {
        CryptographicKeyItem keyItem = getKeyItem(uuid, evaluateTokenPermission);
        KeyState finalState = keyItem.getState().equals(KeyState.COMPROMISED) ? KeyState.DESTROYED_COMPROMISED : KeyState.DESTROYED;
        if (!keyItem.getState().equals(KeyState.DEACTIVATED) && !keyItem.getState().equals(KeyState.PRE_ACTIVE) && !keyItem.getState().equals(KeyState.COMPROMISED)) {
            String message = "Invalid state of key " + uuid + ". Key is " + keyItem.getState().getLabel() + ", hence can't be set to " + finalState.getLabel() + ".";
            keyEventHistoryService.addEventHistory(KeyEvent.DESTROY, KeyEventStatus.FAILED,
                    message, null, keyItem);
            return false;
        }
        keyManagementApiClient.destroyKey(
                keyItem.getCryptographicKey().getTokenInstanceReference().getConnector().mapToDto(),
                keyItem.getCryptographicKey().getTokenInstanceReference().getTokenInstanceUuid(),
                keyItem.getKeyReferenceUuid().toString()
        );
        logger.info("Key destroyed in the connector. Removing from the core now");
        keyItem.setKeyData(null);
        keyItem.setState(finalState);
        cryptographicKeyItemRepository.save(keyItem);
        keyEventHistoryService.addEventHistory(KeyEvent.DESTROY, KeyEventStatus.SUCCESS, "Key destroyed.", null, keyItem);
        return true;
    }

    private CryptographicKeyItem getKeyItem(UUID uuid, boolean evaluateTokenPermission) throws NotFoundException {
        CryptographicKeyItem keyItem = getCryptographicKeyItem(uuid);
        if (keyItem.getCryptographicKey().getTokenProfile() != null) {
            permissionEvaluator.tokenProfile(keyItem.getCryptographicKey().getTokenProfile().getSecuredUuid());
        }
        if (evaluateTokenPermission) {
            permissionEvaluator.tokenInstance(keyItem.getCryptographicKey().getTokenInstanceReference().getSecuredUuid());
        }
        return keyItem;
    }

    private CryptographicKeyItem getCryptographicKeyItem(UUID uuid) throws NotFoundException {
        return cryptographicKeyItemRepository
                .findByUuid(uuid)
                .orElseThrow(
                        () -> new NotFoundException(
                                CryptographicKeyItem.class,
                                uuid
                        )
                );
    }

    private void deleteKeyWithAssociations(CryptographicKey key) {
        certificateService.clearKeyAssociations(key.getUuid());
        attributeEngine.deleteAllObjectAttributeContent(Resource.CRYPTOGRAPHIC_KEY, key.getUuid());
        objectAssociationService.removeObjectAssociations(Resource.CRYPTOGRAPHIC_KEY, key.getUuid());
        cryptographicKeyRepository.delete(key);
    }

    private List<SearchFieldDataByGroupDto> getSearchableFieldsMap() {
        final List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine.getResourceSearchableFields(Resource.CRYPTOGRAPHIC_KEY, false);

        List<SearchFieldDataDto> fields = List.of(
                SearchHelper.prepareSearch(SearchFieldNameEnum.NAME),
                SearchHelper.prepareSearch(SearchFieldNameEnum.CK_GROUP, groupRepository.findAll().stream().map(Group::getName).toList()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.CK_OWNER, userManagementApiClient.getUsers().getData().stream().map(UserDto::getUsername).toList()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.CK_KEY_USAGE, Arrays.stream((KeyUsage.values())).map(KeyUsage::getCode).toList()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.KEY_LENGTH),
                SearchHelper.prepareSearch(SearchFieldNameEnum.KEY_STATE, Arrays.stream((KeyState.values())).map(KeyState::getCode).toList()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.KEY_FORMAT, Arrays.stream((KeyFormat.values())).map(KeyFormat::getCode).toList()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.KEY_TYPE, Arrays.stream((KeyType.values())).map(KeyType::getCode).toList()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.KEY_CRYPTOGRAPHIC_ALGORITHM, Arrays.stream((KeyAlgorithm.values())).map(KeyAlgorithm::getCode).toList()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.KEY_TOKEN_PROFILE, tokenProfileRepository.findAll().stream().map(TokenProfile::getName).toList()),
                SearchHelper.prepareSearch(SearchFieldNameEnum.KEY_TOKEN_INSTANCE_LABEL, tokenInstanceReferenceRepository.findAll().stream().map(TokenInstanceReference::getName).toList())
        );
        fields = new ArrayList<>(fields);
        fields.sort(new SearchFieldDataComparator());
        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));

        logger.debug("Searchable CryptographicKey Fields groups: {}", searchFieldDataByGroupDtos);
        return searchFieldDataByGroupDtos;
    }

}
