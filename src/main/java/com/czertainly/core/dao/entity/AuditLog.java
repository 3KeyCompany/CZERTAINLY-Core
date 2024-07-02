package com.czertainly.core.dao.entity;

import com.czertainly.api.model.core.audit.AuditLogDto;
import com.czertainly.api.model.core.audit.ObjectType;
import com.czertainly.api.model.core.audit.OperationStatusEnum;
import com.czertainly.api.model.core.audit.OperationType;
import com.czertainly.core.util.DtoMapper;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
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

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        AuditLog auditLog = (AuditLog) o;
        return getId() != null && Objects.equals(getId(), auditLog.getId());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
