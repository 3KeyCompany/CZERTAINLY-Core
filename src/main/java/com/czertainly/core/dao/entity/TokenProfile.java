package com.czertainly.core.dao.entity;

import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.czertainly.api.model.core.cryptography.tokenprofile.TokenProfileDto;
import com.czertainly.core.service.model.Securable;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.core.util.DtoMapper;
import com.czertainly.core.util.ObjectAccessControlMapper;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import java.io.Serializable;
import java.util.UUID;


@Entity
@Table(name = "token_profile")
public class TokenProfile extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<TokenProfileDto>, Securable, ObjectAccessControlMapper<NameAndUuidDto> {

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "token_instance_name")
    private String tokenInstanceName;

    @Column(name = "attributes", length = 4096)
    private String attributes;

    @ManyToOne
    @JoinColumn(name = "token_instance_ref_uuid", insertable = false, updatable = false)
    private TokenInstanceReference tokenInstanceReference;

    @Column(name = "token_instance_ref_uuid")
    private UUID tokenInstanceReferenceUuid;

    @Column(name = "enabled")
    private Boolean enabled;

    @Override
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getTokenInstanceName() {
        return tokenInstanceName;
    }

    public void setTokenInstanceName(String tokenInstanceName) {
        this.tokenInstanceName = tokenInstanceName;
    }

    public String getAttributes() {
        return attributes;
    }

    public void setAttributes(String attributes) {
        this.attributes = attributes;
    }

    public TokenInstanceReference getTokenInstanceReference() {
        return tokenInstanceReference;
    }

    public void setTokenInstanceReference(TokenInstanceReference tokenInstanceReference) {
        this.tokenInstanceReference = tokenInstanceReference;
    }

    public UUID getTokenInstanceReferenceUuid() {
        return tokenInstanceReferenceUuid;
    }

    public void setTokenInstanceReferenceUuid(UUID tokenInstanceReferenceUuid) {
        this.tokenInstanceReferenceUuid = tokenInstanceReferenceUuid;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("name", name)
                .append("description", description)
                .append("tokenInstanceName", tokenInstanceName)
                .append("attributes", attributes)
                .append("tokenInstanceReference", tokenInstanceReference)
                .append("tokenInstanceReferenceUuid", tokenInstanceReferenceUuid)
                .append("enabled", enabled)
                .append("uuid", uuid)
                .toString();
    }

    @Override
    public TokenProfileDto mapToDto() {
        TokenProfileDto dto = new TokenProfileDto();
        dto.setEnabled(enabled);
        dto.setUuid(uuid.toString());
        dto.setName(name);
        dto.setDescription(description);
        dto.setTokenInstanceName(tokenInstanceName);
        dto.setTokenInstanceUuid(tokenInstanceReferenceUuid.toString());
        dto.setTokenInstanceStatus(tokenInstanceReference.getStatus());
        return dto;
    }

    public TokenProfileDetailDto mapToDetailDto() {
        TokenProfileDetailDto dto = new TokenProfileDetailDto();
        dto.setEnabled(enabled);
        dto.setUuid(uuid.toString());
        dto.setName(name);
        dto.setDescription(description);
        dto.setTokenInstanceName(tokenInstanceName);
        dto.setTokenInstanceUuid(tokenInstanceReferenceUuid.toString());
        dto.setTokenInstanceStatus(tokenInstanceReference.getStatus());
        dto.setAttributes(AttributeDefinitionUtils.getResponseAttributes(AttributeDefinitionUtils.deserialize(attributes, DataAttribute.class)));
        // Custom Attributes and Metadata should be set in the service
        return dto;
    }

    @Override
    public NameAndUuidDto mapToAccessControlObjects() {
        return new NameAndUuidDto(uuid.toString(), name);
    }
}