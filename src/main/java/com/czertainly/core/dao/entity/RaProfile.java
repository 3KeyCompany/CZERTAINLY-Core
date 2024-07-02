package com.czertainly.core.dao.entity;

import com.czertainly.api.model.client.raprofile.RaProfileAcmeDetailResponseDto;
import com.czertainly.api.model.client.raprofile.RaProfileCmpDetailResponseDto;
import com.czertainly.api.model.client.raprofile.RaProfileScepDetailResponseDto;
import com.czertainly.api.model.client.raprofile.SimplifiedRaProfileDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.raprofile.RaProfileDto;
import com.czertainly.core.dao.entity.acme.AcmeProfile;
import com.czertainly.core.dao.entity.cmp.CmpProfile;
import com.czertainly.core.dao.entity.scep.ScepProfile;
import com.czertainly.core.service.acme.AcmeConstants;
import com.czertainly.core.service.cmp.CmpConstants;
import com.czertainly.core.service.model.Securable;
import com.czertainly.core.service.scep.impl.ScepServiceImpl;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.core.util.DtoMapper;
import com.czertainly.core.util.ObjectAccessControlMapper;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.io.Serializable;
import java.util.*;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "ra_profile")
public class RaProfile extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<RaProfileDto>, Securable, ObjectAccessControlMapper<NameAndUuidDto> {

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "authority_instance_name")
    private String authorityInstanceName;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "authority_instance_ref_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    @JsonBackReference
    private AuthorityInstanceReference authorityInstanceReference;

    @Column(name = "authority_instance_ref_uuid")
    private UUID authorityInstanceReferenceUuid;

    @Column(name = "enabled")
    private Boolean enabled;

    @Column(name = "authority_certificate_uuid")
    private UUID authorityCertificateUuid;

    @ManyToMany(cascade = {CascadeType.DETACH, CascadeType.MERGE, CascadeType.PERSIST, CascadeType.REFRESH})
    @JoinTable(
            name = "ra_profile_2_compliance_profile",
            joinColumns = @JoinColumn(name = "ra_profile_uuid"),
            inverseJoinColumns = @JoinColumn(name = "compliance_profile_uuid"))
    @ToString.Exclude
    private Set<ComplianceProfile> complianceProfiles;

    @OneToOne(mappedBy = "raProfile", fetch = FetchType.LAZY)
    @ToString.Exclude
    private RaProfileProtocolAttribute protocolAttribute;

    /**
     * Acme related objects for RA Profile
     */
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "acme_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private AcmeProfile acmeProfile;

    @Column(name = "acme_profile_uuid")
    private UUID acmeProfileUuid;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scep_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private ScepProfile scepProfile;

    @Column(name = "scep_profile_uuid")
    private UUID scepProfileUuid;

    /**
     * CMP protocol related objects for RA Profile
     */
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "cmp_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private CmpProfile cmpProfile;

    @Column(name = "cmp_profile_uuid")
    private UUID cmpProfileUuid;

    public RaProfileAcmeDetailResponseDto mapToAcmeDto() {
        RaProfileAcmeDetailResponseDto dto = new RaProfileAcmeDetailResponseDto();
        if (acmeProfile == null) {
            dto.setAcmeAvailable(false);
            return dto;
        }
        dto.setName(acmeProfile.getName());
        dto.setUuid(acmeProfile.getUuid().toString());
        dto.setIssueCertificateAttributes(AttributeDefinitionUtils.getResponseAttributes(AttributeDefinitionUtils.deserialize(protocolAttribute.getAcmeIssueCertificateAttributes(), DataAttribute.class)));
        dto.setRevokeCertificateAttributes(AttributeDefinitionUtils.getResponseAttributes(AttributeDefinitionUtils.deserialize(protocolAttribute.getAcmeRevokeCertificateAttributes(), DataAttribute.class)));
        dto.setDirectoryUrl(ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString()
                + AcmeConstants.ACME_URI_HEADER + "/raProfile/" + name + "/directory");
        dto.setAcmeAvailable(true);
        return dto;
    }

    public RaProfileScepDetailResponseDto mapToScepDto() {
        RaProfileScepDetailResponseDto dto = new RaProfileScepDetailResponseDto();
        if (scepProfile == null) {
            dto.setScepAvailable(false);
            return dto;
        }
        dto.setScepAvailable(true);
        dto.setUrl(ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString()
                + ScepServiceImpl.SCEP_URL_PREFIX + "/raProfile/" + name + "/pkiclient.exe");
        dto.setName(scepProfile.getName());
        dto.setUuid(scepProfile.getUuid().toString());
        dto.setIssueCertificateAttributes(AttributeDefinitionUtils.getResponseAttributes(AttributeDefinitionUtils.deserialize(protocolAttribute.getScepIssueCertificateAttributes(), DataAttribute.class)));
        return dto;
    }

    public RaProfileCmpDetailResponseDto mapToCmpDto() {
        RaProfileCmpDetailResponseDto dto = new RaProfileCmpDetailResponseDto();
        if (cmpProfile == null) {
            dto.setCmpAvailable(false);
            return dto;
        }
        dto.setName(cmpProfile.getName());
        dto.setUuid(cmpProfile.getUuid().toString());
        dto.setIssueCertificateAttributes(
                AttributeDefinitionUtils.getResponseAttributes(
                        AttributeDefinitionUtils.deserialize(
                                protocolAttribute.getCmpIssueCertificateAttributes(),
                                DataAttribute.class)
                )
        );
        dto.setRevokeCertificateAttributes(
                AttributeDefinitionUtils.getResponseAttributes(
                        AttributeDefinitionUtils.deserialize(
                                protocolAttribute.getCmpRevokeCertificateAttributes(),
                                DataAttribute.class)
                )
        );
        dto.setCmpUrl(ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString()
                + CmpConstants.CMP_BASE_CONTEXT + "/raProfile/" + name);
        dto.setCmpAvailable(true);
        return dto;
    }

    public RaProfileDto mapToDtoSimple() {
        RaProfileDto dto = new RaProfileDto();
        dto.setUuid(this.uuid.toString());
        dto.setName(this.name);
        List<String> enabledProtocols = new ArrayList<>();
        if (acmeProfile != null) {
            enabledProtocols.add("ACME");
        }
        if (scepProfile != null) {
            enabledProtocols.add("SCEP");
        }
        if (cmpProfile != null) {
            enabledProtocols.add("CMP");
        }
        dto.setEnabledProtocols(enabledProtocols);
        dto.setDescription(this.description);
        dto.setAuthorityInstanceName(this.authorityInstanceName);
        try {
            dto.setAuthorityInstanceUuid(this.authorityInstanceReference.getUuid().toString());
        } catch (NullPointerException e) {
            dto.setAuthorityInstanceUuid(null);
        }
        dto.setEnabled(this.enabled);

        return dto;
    }

    public SimplifiedRaProfileDto mapToDtoSimplified() {
        SimplifiedRaProfileDto dto = new SimplifiedRaProfileDto();
        dto.setUuid(this.uuid.toString());
        dto.setName(this.name);
        dto.setEnabled(this.enabled);
        try {
            dto.setAuthorityInstanceUuid(this.authorityInstanceReference.getUuid().toString());
        } catch (NullPointerException e) {
            dto.setAuthorityInstanceUuid(null);
        }
        return dto;
    }

    @Override
    @Transient
    public RaProfileDto mapToDto() {
        RaProfileDto dto = new RaProfileDto();
        dto.setUuid(uuid.toString());
        dto.setName(name);
        dto.setDescription(this.description);
        dto.setEnabled(enabled);

        if (authorityInstanceReference != null) {
            dto.setAuthorityInstanceUuid(authorityInstanceReference.getUuid().toString());
            dto.setAuthorityInstanceName(this.authorityInstanceName);
            dto.setLegacyAuthority(authorityInstanceReference.getConnector() == null ? null
                    : authorityInstanceReference.getConnector().getFunctionGroups().stream().anyMatch(fg -> fg.getFunctionGroup().getCode().equals(FunctionGroupCode.LEGACY_AUTHORITY_PROVIDER)));
        }
        return dto;
    }

    @Override
    public NameAndUuidDto mapToAccessControlObjects() {
        return new NameAndUuidDto(uuid.toString(), name);
    }

    public void setAuthorityInstanceReference(AuthorityInstanceReference authorityInstanceReference) {
        this.authorityInstanceReference = authorityInstanceReference;
        if (authorityInstanceReference != null)
            this.authorityInstanceReferenceUuid = authorityInstanceReference.getUuid();
        else this.authorityInstanceReferenceUuid = null;
    }

    public void setAcmeProfile(AcmeProfile acmeProfile) {
        this.acmeProfile = acmeProfile;
        if (acmeProfile != null) this.acmeProfileUuid = acmeProfile.getUuid();
        else this.acmeProfileUuid = null;
    }

    public void setScepProfile(ScepProfile scepProfile) {
        this.scepProfile = scepProfile;
        if (scepProfile != null) this.scepProfileUuid = scepProfile.getUuid();
        else this.scepProfileUuid = null;
    }

    public void setCmpProfile(CmpProfile cmpProfile) {
        this.cmpProfile = cmpProfile;
        if (cmpProfile != null) this.cmpProfileUuid = cmpProfile.getUuid();
        else this.cmpProfileUuid = null;
    }

    public RaProfileProtocolAttribute getProtocolAttribute() {
        if (protocolAttribute == null) {
            return new RaProfileProtocolAttribute();
        }
        return protocolAttribute;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        RaProfile raProfile = (RaProfile) o;
        return getUuid() != null && Objects.equals(getUuid(), raProfile.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
