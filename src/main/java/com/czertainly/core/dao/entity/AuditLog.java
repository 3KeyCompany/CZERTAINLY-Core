package com.czertainly.core.dao.entity;

import com.czertainly.api.model.core.audit.AuditLogDto;
import com.czertainly.api.model.core.audit.ObjectType;
import com.czertainly.api.model.core.audit.OperationStatusEnum;
import com.czertainly.api.model.core.audit.OperationType;
import com.czertainly.core.util.DtoMapper;
import jakarta.persistence.*;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.io.Serializable;
import java.util.UUID;

@Entity
@Table(name = "audit_log")
public class AuditLog extends Audited implements Serializable, DtoMapper<AuditLogDto> {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "audit_log_seq")
    @SequenceGenerator(name = "audit_log_seq", sequenceName = "audit_log_id_seq", allocationSize = 1)
    private Long id;

    @Column(name = "uuid", nullable = false)
    protected String uuid = UUID.randomUUID().toString();

    @Column(name = "origination")
    @Enumerated(EnumType.STRING)
    private ObjectType origination;

    @Column(name = "affected")
    @Enumerated(EnumType.STRING)
    private ObjectType affected;

    @Column(name = "object_identifier")
    private String objectIdentifier;

    @Column(name = "operation")
    @Enumerated(EnumType.STRING)
    private OperationType operation;

    @Column(name = "operation_status")
    @Enumerated(EnumType.STRING)
    private OperationStatusEnum operationStatus;

    @Column(name = "additional_data")
    @Lob
    private String additionalData;

    @Override
    public AuditLogDto mapToDto() {
        AuditLogDto dto = new AuditLogDto();
        dto.setId(id);
        dto.setUuid(uuid);
        dto.setAuthor(author);
        dto.setCreated(created);
        dto.setOperationStatus(operationStatus);
        dto.setOrigination(origination);
        dto.setAffected(affected);
        dto.setObjectIdentifier(objectIdentifier);
        dto.setOperation(operation);
        dto.setAdditionalData(additionalData);
        return dto;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public ObjectType getOrigination() {
        return origination;
    }

    public void setOrigination(ObjectType origination) {
        this.origination = origination;
    }

    public ObjectType getAffected() {
        return affected;
    }

    public void setAffected(ObjectType affected) {
        this.affected = affected;
    }

    public String getObjectIdentifier() {
        return objectIdentifier;
    }

    public void setObjectIdentifier(String objectIdentifier) {
        this.objectIdentifier = objectIdentifier;
    }

    public OperationType getOperation() {
        return operation;
    }

    public void setOperation(OperationType operation) {
        this.operation = operation;
    }

    public OperationStatusEnum getOperationStatus() {
        return operationStatus;
    }

    public void setOperationStatus(OperationStatusEnum operationStatus) {
        this.operationStatus = operationStatus;
    }

    public String getAdditionalData() {
        return additionalData;
    }

    public void setAdditionalData(String additionalData) {
        this.additionalData = additionalData;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("id", id)
                .append("origination", origination)
                .append("affected", affected)
                .append("objectIdentifier", objectIdentifier)
                .append("operation", operation)
                .append("operationStatus", operationStatus)
                .append("additionalData", additionalData)
                .append("author", author)
                .append("created", created)
                .append("updated", updated)
                .append("uuid", uuid)
                .toString();
    }
}
