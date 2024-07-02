package com.czertainly.core.dao.entity;

import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.core.notification.NotificationInstanceDto;
import com.czertainly.core.util.DtoMapper;
import com.czertainly.core.util.ObjectAccessControlMapper;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "notification_instance_reference")
public class NotificationInstanceReference extends UniquelyIdentified implements Serializable, DtoMapper<NotificationInstanceDto>, ObjectAccessControlMapper<NameAndUuidDto> {

    @Column(name = "notification_instance_uuid")
    private UUID notificationInstanceUuid;

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "kind")
    private String kind;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "connector_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private Connector connector;

    @Column(name = "connector_uuid")
    private UUID connectorUuid;

    @Column(name = "connector_name")
    private String connectorName;

    @OneToMany(mappedBy = "notificationInstanceReference", fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @ToString.Exclude
    private List<NotificationInstanceMappedAttributes> mappedAttributes;

    public void setConnector(Connector connector) {
        this.connector = connector;
        if (connector != null) this.connectorUuid = connector.getUuid();
        else this.connectorUuid = null;
    }

    @Override
    public NotificationInstanceDto mapToDto() {
        NotificationInstanceDto dto = new NotificationInstanceDto();
        dto.setUuid(this.uuid.toString());
        dto.setName(this.name);
        dto.setDescription(this.description);
        dto.setKind(kind);
        dto.setConnectorName(this.connectorName);
        if (this.connector != null) {
            dto.setConnectorUuid(this.connector.getUuid().toString());
        }
        return dto;
    }

    @Override
    public NameAndUuidDto mapToAccessControlObjects() {
        return new NameAndUuidDto(uuid.toString(), name);
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        NotificationInstanceReference that = (NotificationInstanceReference) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
