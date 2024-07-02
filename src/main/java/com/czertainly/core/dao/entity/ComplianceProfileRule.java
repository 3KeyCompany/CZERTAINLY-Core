package com.czertainly.core.dao.entity;

import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.client.compliance.ComplianceProfileRuleDto;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.core.compliance.ComplianceRulesDto;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.core.util.DtoMapper;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Entity containing the relation between the Compliance Profile and the Rule. This has to be maintained separately
 * considering that each rule can have its own attributes and values. And the values may be different for each compliance
 * profile. This entity frames the relation with the Compliance Profile and the Compliance Rules discovered from the
 * connector. In addition to that, it also stores the attributes needed for the rule
 */
@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "compliance_profile_rule")
public class ComplianceProfileRule extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<ComplianceProfileRuleDto> {

    @ManyToOne(cascade = CascadeType.PERSIST, fetch = FetchType.LAZY)
    @JoinColumn(name = "rule_uuid")
    @ToString.Exclude
    private ComplianceRule complianceRule;

    @Column(name = "rule_uuid", insertable = false, updatable = false)
    private UUID complianceRuleUuid;

    @Column(name = "attributes")
    private String attributes;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "compliance_profile_uuid")
    @ToString.Exclude
    private ComplianceProfile complianceProfile;

    @Column(name = "compliance_profile_uuid", insertable = false, updatable = false)
    private UUID complianceProfileUuid;

    @Override
    public ComplianceProfileRuleDto mapToDto() {
        ComplianceProfileRuleDto dto = new ComplianceProfileRuleDto();
        dto.setName(complianceRule.getName());
        dto.setUuid(complianceRule.getUuid().toString());
        dto.setAttributes(AttributeDefinitionUtils.getResponseAttributes(getFullAttributes()));
        dto.setDescription(complianceRule.getDescription());
        dto.setComplianceProfileName(complianceProfile.getName());
        dto.setComplianceProfileUuid(complianceProfile.getUuid().toString());
        dto.setCertificateType(complianceRule.getCertificateType());
        dto.setConnectorUuid(complianceRule.getConnectorUuid().toString());
        dto.setConnectorName(complianceRule.getConnector().getName());
        dto.setGroupUuid(complianceRule.getGroupUuid() != null ? complianceRule.getGroupUuid().toString() : null);
        return dto;
    }

    public ComplianceRulesDto mapToDtoForProfile() {
        ComplianceRulesDto dto = new ComplianceRulesDto();
        dto.setName(complianceRule.getName());
        dto.setUuid(complianceRule.getUuid().toString());
        dto.setAttributes(AttributeDefinitionUtils.getResponseAttributes(getFullAttributes()));
        dto.setDescription(complianceRule.getDescription());
        return dto;
    }

    public void setComplianceRule(ComplianceRule complianceRule) {
        this.complianceRule = complianceRule;
        if (complianceRule != null) this.complianceRuleUuid = complianceRule.getUuid();
        else this.complianceRuleUuid = null;
    }

    public List<RequestAttributeDto> getAttributes() {
        return AttributeDefinitionUtils.deserializeRequestAttributes(attributes);
    }

    public void setAttributes(List<RequestAttributeDto> attributes) {
        this.attributes = AttributeDefinitionUtils.serializeRequestAttributes(attributes);
    }

    public List<DataAttribute> getFullAttributes() {
        List<BaseAttribute> fullAttribute = complianceRule.getAttributes();
        return AttributeDefinitionUtils.mergeAttributes(fullAttribute, AttributeDefinitionUtils.deserializeRequestAttributes(attributes));
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        ComplianceProfileRule that = (ComplianceProfileRule) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
