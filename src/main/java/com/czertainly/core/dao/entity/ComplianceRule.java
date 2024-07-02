package com.czertainly.core.dao.entity;


import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.connector.compliance.ComplianceRulesResponseDto;
import com.czertainly.api.model.core.certificate.CertificateType;
import com.czertainly.api.model.core.compliance.ComplianceRulesDto;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.core.util.DtoMapper;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Entity containing the list of all discovered rules from a compliance provider. The rules are fetched from the compliance
 * provider, and are stored in the core. They are then used to map the rules for profiles. These rules are also tagged with the
 * group, if they belong to one.
 */
@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "compliance_rule")
public class ComplianceRule extends UniquelyIdentified implements Serializable, DtoMapper<ComplianceRulesDto> {

    @Column(name = "name")
    private String name;

    @Column(name = "kind")
    private String kind;

    @Column(name = "decommissioned")
    private Boolean decommissioned;

    @Enumerated(EnumType.STRING)
    @Column(name = "certificate_type")
    private CertificateType certificateType;

    @Column(name = "attributes")
    private String attributes;

    @Column(name = "description")
    private String description;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "connector_uuid", nullable = false, insertable = false, updatable = false)
    @ToString.Exclude
    private Connector connector;

    @Column(name = "connector_uuid", nullable = false)
    private UUID connectorUuid;

    @ManyToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JoinColumn(name = "group_uuid")
    @ToString.Exclude
    private ComplianceGroup group;

    @Column(name = "group_uuid", insertable = false, updatable = false)
    private UUID groupUuid;

    @JsonBackReference
    @OneToMany(mappedBy = "complianceRule", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<ComplianceProfileRule> rules;

    @Override
    public ComplianceRulesDto mapToDto() {
        ComplianceRulesDto complianceRulesDto = new ComplianceRulesDto();
        complianceRulesDto.setName(name);
        complianceRulesDto.setUuid(uuid.toString());
        complianceRulesDto.setDescription(description);
        complianceRulesDto.setCertificateType(certificateType);
        complianceRulesDto.setAttributes(AttributeDefinitionUtils.getResponseAttributes(getAttributes()));
        return complianceRulesDto;
    }

    public ComplianceRulesResponseDto mapToComplianceResponse() {
        ComplianceRulesResponseDto dto = new ComplianceRulesResponseDto();
        dto.setName(name);
        dto.setUuid(uuid.toString());
        dto.setDescription(description);
        if (group != null) {
            dto.setGroupUuid(group.getUuid().toString());
        }
        dto.setCertificateType(certificateType);
        dto.setAttributes(getAttributes());
        return dto;
    }

    public List<BaseAttribute> getAttributes() {
        return AttributeDefinitionUtils.deserialize(attributes, BaseAttribute.class);
    }

    public void setAttributes(List<BaseAttribute> attributes) {
        this.attributes = AttributeDefinitionUtils.serialize(attributes);
    }

    public void setConnector(Connector connector) {
        this.connector = connector;
        this.connectorUuid = connector.getUuid();
    }

    public void setGroup(ComplianceGroup group) {
        this.group = group;
        if (group != null) this.groupUuid = group.getUuid();
        else this.groupUuid = null;
    }

    public void setConnectorUuidFromString(String connectorUuid) {
        this.connectorUuid = UUID.fromString(connectorUuid);
    }

    public void setGroupUuidFromString(String groupUuid) {
        this.groupUuid = UUID.fromString(groupUuid);
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        ComplianceRule that = (ComplianceRule) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
