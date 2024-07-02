package com.czertainly.core.dao.entity;

import com.czertainly.api.model.connector.compliance.ComplianceGroupsResponseDto;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serializable;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Entity storing the available groups obtained from the Compliance Provider. These entities have relations with the
 * respective connector mapped to the connector table. If the user chooses to associate a group to a compliance profile,
 * a foreign key relation of type manyToMany will be established using the table compliance_group_to_compliance_profile
 */
@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "compliance_group")
public class ComplianceGroup extends UniquelyIdentified implements Serializable {

    @Column(name = "name")
    private String name;

    @Column(name = "kind")
    private String kind;

    @Column(name = "description")
    private String description;

    @Column(name="decommissioned")
    private Boolean decommissioned;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "connector_uuid", nullable = false, insertable = false, updatable = false)
    @ToString.Exclude
    private Connector connector;

    @Column(name = "connector_uuid", nullable = false)
    private UUID connectorUuid;

    @JsonBackReference
    @OneToMany(mappedBy = "group", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<ComplianceRule> rules;

    @JsonBackReference
    @ManyToMany(mappedBy = "groups", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<ComplianceProfile> complianceProfiles;

    public ComplianceGroupsResponseDto mapToGroupResponse(){
        ComplianceGroupsResponseDto dto = new ComplianceGroupsResponseDto();
        dto.setUuid(uuid.toString());
        dto.setName(name);
        dto.setDescription(description);
        return dto;
    }

    public void setConnector(Connector connector) {
        this.connector = connector;
        this.connectorUuid = connector.getUuid();
    }

    public void setConnectorUuidFromString(String connectorUuid) { this.connectorUuid = UUID.fromString(connectorUuid); }


    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        ComplianceGroup that = (ComplianceGroup) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
