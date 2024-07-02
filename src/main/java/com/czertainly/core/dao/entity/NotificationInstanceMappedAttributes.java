package com.czertainly.core.dao.entity;

import com.czertainly.api.model.core.notification.AttributeMappingDto;
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
@Table(name = "notification_instance_mapped_attributes")
public class NotificationInstanceMappedAttributes extends UniquelyIdentified implements Serializable, DtoMapper<AttributeMappingDto> {

    @Column(name = "notification_instance_ref_uuid")
    private UUID notificationInstanceRefUuid;

    @Column(name = "attribute_definition_uuid")
    private UUID attributeDefinitionUuid;

    @Column(name = "mapping_attribute_uuid")
    private UUID mappingAttributeUuid;

    @Column(name = "mapping_attribute_name")
    private String mappingAttributeName;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "notification_instance_ref_uuid", referencedColumnName = "uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private NotificationInstanceReference notificationInstanceReference;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "attribute_definition_uuid", referencedColumnName = "uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private AttributeDefinition attributeDefinition;

    @Override
    public AttributeMappingDto mapToDto() {
        AttributeMappingDto dto = new AttributeMappingDto();
        dto.setCustomAttributeUuid(this.attributeDefinitionUuid.toString());
        dto.setCustomAttributeLabel(this.getAttributeDefinition().mapToCustomAttributeDefinitionDetailDto().getLabel());
        dto.setMappingAttributeUuid(this.mappingAttributeUuid.toString());
        dto.setMappingAttributeName(this.mappingAttributeName);
        return dto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        NotificationInstanceMappedAttributes that = (NotificationInstanceMappedAttributes) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
