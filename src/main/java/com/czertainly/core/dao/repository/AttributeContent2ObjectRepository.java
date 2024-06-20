package com.czertainly.core.dao.repository;

import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContent;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentDetail;
import com.czertainly.core.attribute.engine.records.ObjectAttributeDefinitionContent;
import com.czertainly.core.dao.entity.AttributeContent2Object;
import com.czertainly.core.model.SearchFieldObject;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface AttributeContent2ObjectRepository extends SecurityFilterRepository<AttributeContent2Object, String> {

    List<AttributeContent2Object> getByConnectorUuidAndAttributeContentItemUuidAndObjectTypeAndObjectUuidAndSourceObjectTypeAndSourceObjectUuid(UUID connectorUuid, UUID attributeContentItemUuid, Resource objectType, UUID objectUuid, Resource sourceObjectType, UUID sourceObjectUuid);

    @Query("""
            SELECT new com.czertainly.core.attribute.engine.records.ObjectAttributeContent(
                ad.attributeUuid, ad.name, ad.label, ad.type, ad.contentType, aci.json)
                FROM AttributeContent2Object aco
                JOIN AttributeContentItem aci ON aci.uuid = aco.attributeContentItemUuid
                JOIN AttributeDefinition ad ON ad.uuid = aci.attributeDefinitionUuid
                WHERE ad.type = ?1 AND ad.enabled = true AND aco.objectType = ?2 AND aco.objectUuid = ?3
                    AND (COALESCE(?4) IS NULL OR aci.attributeDefinitionUuid IN (?4))
                    AND (COALESCE(?5) IS NULL OR aci.attributeDefinitionUuid NOT IN (?5))
                ORDER BY aci.attributeDefinitionUuid, aco.order
            """)
    List<ObjectAttributeContent> getObjectCustomAttributesContent(AttributeType attributeType, Resource objectType, UUID objectUuid, List<UUID> allowedDefinitionUuids, List<UUID> forbiddenDefinitionUuids);

    @Query("""
            SELECT new com.czertainly.core.attribute.engine.records.ObjectAttributeContent(
                ad.attributeUuid, ad.name, ad.label, ad.type, ad.contentType, aci.json)
                FROM AttributeContent2Object aco
                JOIN AttributeContentItem aci ON aci.uuid = aco.attributeContentItemUuid
                JOIN AttributeDefinition ad ON ad.uuid = aci.attributeDefinitionUuid
                WHERE ad.type = ?1 AND ad.operation = ?3
                    AND aco.connectorUuid = ?2 AND aco.objectType = ?4 AND aco.objectUuid = ?5
                ORDER BY aci.attributeDefinitionUuid, aco.order
            """)
    List<ObjectAttributeContent> getObjectDataAttributesContent(AttributeType attributeType, UUID connectorUuid, String operation, Resource objectType, UUID objectUuid);

    @Query("""
            SELECT new com.czertainly.core.attribute.engine.records.ObjectAttributeContent(
                ad.attributeUuid, ad.name, ad.label, ad.type, ad.contentType, aci.json)
                FROM AttributeContent2Object aco
                JOIN AttributeContentItem aci ON aci.uuid = aco.attributeContentItemUuid
                JOIN AttributeDefinition ad ON ad.uuid = aci.attributeDefinitionUuid
                WHERE ad.type = ?1 AND ad.operation IS NULL
                    AND aco.connectorUuid = ?2 AND aco.objectType = ?3 AND aco.objectUuid = ?4
                ORDER BY aci.attributeDefinitionUuid, aco.order
            """)
    List<ObjectAttributeContent> getObjectDataAttributesContentNoOperation(AttributeType attributeType, UUID connectorUuid, Resource objectType, UUID objectUuid);

    @Query("""
            SELECT new com.czertainly.core.attribute.engine.records.ObjectAttributeContent(
                ad.attributeUuid, ad.name, ad.label, ad.type, ad.contentType, aci.json)
                FROM AttributeContent2Object aco
                JOIN AttributeContentItem aci ON aci.uuid = aco.attributeContentItemUuid
                JOIN AttributeDefinition ad ON ad.uuid = aci.attributeDefinitionUuid
                WHERE ad.type = ?1 AND ad.operation = ?2
                    AND aco.connectorUuid IS NULL AND aco.objectType = ?3 AND aco.objectUuid = ?4
                ORDER BY aci.attributeDefinitionUuid, aco.order
            """)
    List<ObjectAttributeContent> getObjectDataAttributesContentNoConnector(AttributeType attributeType, String operation, Resource objectType, UUID objectUuid);

    @Query("""
            SELECT new com.czertainly.core.attribute.engine.records.ObjectAttributeContent(
                ad.attributeUuid, ad.name, ad.label, ad.type, ad.contentType, aci.json)
                FROM AttributeContent2Object aco
                JOIN AttributeContentItem aci ON aci.uuid = aco.attributeContentItemUuid
                JOIN AttributeDefinition ad ON ad.uuid = aci.attributeDefinitionUuid
                WHERE ad.type = ?1 AND ad.operation IS NULL
                    AND aco.connectorUuid IS NULL AND aco.objectType = ?2 AND aco.objectUuid = ?3
                ORDER BY aci.attributeDefinitionUuid, aco.order
            """)
    List<ObjectAttributeContent> getObjectDataAttributesContentNoConnectorNoOperation(AttributeType attributeType, Resource objectType, UUID objectUuid);

    @Query("""
            SELECT new com.czertainly.core.attribute.engine.records.ObjectAttributeContentDetail(
                ad.attributeUuid, ad.name, ad.label, ad.type, ad.contentType, aci.json, aco.connectorUuid, c.name, aco.sourceObjectType, aco.sourceObjectUuid, aco.sourceObjectName)
                FROM AttributeContent2Object aco
                LEFT JOIN Connector c ON c.uuid = aco.connectorUuid
                JOIN AttributeContentItem aci ON aci.uuid = aco.attributeContentItemUuid
                JOIN AttributeDefinition ad ON ad.uuid = aci.attributeDefinitionUuid
                WHERE ad.type = ?1 AND (CAST(?2 AS java.util.UUID) IS NULL OR aco.connectorUuid = ?2) AND (?3 IS NULL OR ad.operation = ?3)
                    AND aco.objectType = ?4 AND aco.objectUuid = ?5
                    AND (?6 IS NULL OR aco.sourceObjectType = ?6) AND (CAST(?7 AS java.util.UUID) IS NULL OR aco.sourceObjectUuid = ?7)
                ORDER BY aci.attributeDefinitionUuid, aco.order
            """)
    List<ObjectAttributeContentDetail> getObjectAttributeContentDetail(AttributeType attributeType, UUID connectorUuid, String operation, Resource objectType, UUID objectUuid, Resource sourceObjectType, UUID sourceObjectUuid);

    @Query("""
            SELECT new com.czertainly.core.attribute.engine.records.ObjectAttributeDefinitionContent(
                ad.attributeUuid, ad.definition, aci.json)
                FROM AttributeContent2Object aco
                JOIN AttributeContentItem aci ON aci.uuid = aco.attributeContentItemUuid
                JOIN AttributeDefinition ad ON ad.uuid = aci.attributeDefinitionUuid
                WHERE ad.type = ?1 AND (CAST(?2 AS java.util.UUID) IS NULL OR aco.connectorUuid = ?2) AND (?3 IS NULL OR ad.operation = ?3)
                    AND aco.objectType = ?4 AND aco.objectUuid = ?5
                    AND (?6 IS NULL OR aco.sourceObjectType = ?6) AND (CAST(?7 AS java.util.UUID) IS NULL OR aco.sourceObjectUuid = ?7)
                ORDER BY aci.attributeDefinitionUuid, aco.order
            """)
    List<ObjectAttributeDefinitionContent> getObjectAttributeDefinitionContent(AttributeType attributeType, UUID connectorUuid, String operation, Resource objectType, UUID objectUuid, Resource sourceObjectType, UUID sourceObjectUuid);

    @Modifying
    @Query("UPDATE AttributeContent2Object aco SET aco.connectorUuid = NULL WHERE aco.connectorUuid = ?1")
    void removeConnectorByConnectorUuid(UUID connectorUuid);

    long deleteByObjectTypeAndObjectUuid(Resource objectType, UUID objectUuid);
    long deleteByAttributeContentItemAttributeDefinitionTypeAndConnectorUuid(AttributeType attributeType, UUID connectorUuid);
    long deleteByAttributeContentItemAttributeDefinitionTypeAndObjectTypeAndObjectUuid(AttributeType attributeType, Resource objectType, UUID objectUuid);
    long deleteByAttributeContentItemAttributeDefinitionUuid(UUID definitionUuid);
    long deleteByObjectTypeAndObjectUuidAndAttributeContentItemAttributeDefinitionUuid(Resource objectType, UUID objectUuid, UUID definitionUuid);
    long deleteByAttributeContentItemAttributeDefinitionTypeAndConnectorUuidAndObjectTypeAndObjectUuidAndSourceObjectTypeAndSourceObjectUuid(AttributeType attributeType, UUID connectorUuid, Resource objectType, UUID objectUuid, Resource sourceObjectType, UUID sourceObjectUuid);
    long deleteByAttributeContentItemAttributeDefinitionTypeAndAttributeContentItemAttributeDefinitionOperationAndConnectorUuidAndObjectTypeAndObjectUuidAndSourceObjectTypeAndSourceObjectUuid(AttributeType attributeType, String operation, UUID connectorUuid, Resource objectType, UUID objectUuid, Resource sourceObjectType, UUID sourceObjectUuid);

    @Query("SELECT DISTINCT objectUuid FROM AttributeContent2Object WHERE objectType = ?1")
    List<UUID> findDistinctObjectUuidsByObjectType(Resource objectType);

}
