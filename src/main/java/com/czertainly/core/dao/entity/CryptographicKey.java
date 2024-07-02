package com.czertainly.core.dao.entity;

import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.cryptography.key.*;
import com.czertainly.core.util.DtoMapper;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.NotFound;
import org.hibernate.annotations.NotFoundAction;
import org.hibernate.annotations.SQLJoinTableRestriction;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serializable;
import java.util.*;
import java.util.stream.Collectors;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "cryptographic_key")
public class CryptographicKey extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<KeyDto> {

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "token_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private TokenProfile tokenProfile;

    @Column(name = "token_profile_uuid")
    private UUID tokenProfileUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "token_instance_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private TokenInstanceReference tokenInstanceReference;

    @Column(name = "token_instance_uuid")
    private UUID tokenInstanceReferenceUuid;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "group_association",
            joinColumns = @JoinColumn(name = "object_uuid", referencedColumnName = "uuid", insertable = false, updatable = false),
            inverseJoinColumns = @JoinColumn(name = "group_uuid", insertable = false, updatable = false)
    )
    @SQLJoinTableRestriction("resource = 'CRYPTOGRAPHIC_KEY'")
    @ToString.Exclude
    private Set<Group> groups = new HashSet<>();

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "uuid", referencedColumnName = "object_uuid", insertable = false, updatable = false)
    @SQLRestriction("resource = 'CRYPTOGRAPHIC_KEY'")
    @ToString.Exclude
    private OwnerAssociation owner;

    @JsonBackReference
    @OneToMany(mappedBy = "cryptographicKey", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<CryptographicKeyItem> items = new HashSet<>();

    @JsonBackReference
    @OneToMany(mappedBy = "key", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<Certificate> certificates = new HashSet<>();

    public void setTokenProfile(TokenProfile tokenProfile) {
        this.tokenProfile = tokenProfile;
        if (tokenProfile != null) this.tokenProfileUuid = tokenProfile.getUuid();
    }

    public void setTokenInstanceReference(TokenInstanceReference tokenInstanceReference) {
        this.tokenInstanceReference = tokenInstanceReference;
        if (tokenInstanceReference != null) this.tokenInstanceReferenceUuid = tokenInstanceReference.getUuid();
    }

    // Get the list of items for the key
    public List<KeyItemDetailDto> getKeyItems() {
        return items.stream().map(CryptographicKeyItem::mapToDto).collect(Collectors.toList());
    }

    // Get the list of items for the key
    public List<KeyItemDto> getKeyItemsSummary() {
        return items.stream().map(CryptographicKeyItem::mapToSummaryDto).collect(Collectors.toList());
    }

    @Override
    public KeyDto mapToDto() {
        KeyDto dto = new KeyDto();
        dto.setName(name);
        dto.setUuid(uuid.toString());
        dto.setDescription(description);
        dto.setCreationTime(created);
        if (tokenProfile != null) {
            dto.setTokenProfileName(tokenProfile.getName());
            dto.setTokenProfileUuid(tokenProfile.getUuid().toString());
        }
        dto.setTokenInstanceName(tokenInstanceReference.getName());
        dto.setTokenInstanceUuid(tokenInstanceReferenceUuid.toString());
        if (groups != null) {
            dto.setGroups(groups.stream().map(Group::mapToDto).toList());
        }
        if (owner != null) {
            dto.setOwnerUuid(owner.getOwnerUuid().toString());
            dto.setOwner(owner.getOwnerUsername());
        }
        dto.setItems(getKeyItemsSummary());
        dto.setAssociations((items.size() - 1) + certificates.size());
        return dto;
    }

    public KeyDetailDto mapToDetailDto() {
        KeyDetailDto dto = new KeyDetailDto();
        dto.setName(name);
        dto.setUuid(uuid.toString());
        dto.setDescription(description);
        dto.setCreationTime(created);
        if (tokenProfile != null) {
            dto.setTokenProfileName(tokenProfile.getName());
            dto.setTokenProfileUuid(tokenProfile.getUuid().toString());
        }
        dto.setTokenInstanceName(tokenInstanceReference.getName());
        dto.setTokenInstanceUuid(tokenInstanceReferenceUuid.toString());
        dto.setItems(getKeyItems());
        if (groups != null) {
            dto.setGroups(groups.stream().map(Group::mapToDto).toList());
        }
        if (owner != null) {
            dto.setOwnerUuid(owner.getOwnerUuid().toString());
            dto.setOwner(owner.getOwnerUsername());
        }
        if (certificates != null && !certificates.isEmpty()) {
            dto.setAssociations(certificates.stream().map(e -> {
                KeyAssociationDto keyAssociationDto = new KeyAssociationDto();
                keyAssociationDto.setName(e.getCommonName());
                keyAssociationDto.setUuid(e.getUuid().toString());
                keyAssociationDto.setResource(Resource.CERTIFICATE);
                return keyAssociationDto;
            }).toList());
        }
        return dto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        CryptographicKey that = (CryptographicKey) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
