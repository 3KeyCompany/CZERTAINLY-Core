package com.czertainly.core.dao.entity;

import com.czertainly.api.model.client.cryptography.key.KeyCompromiseReason;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyFormat;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.connector.cryptography.key.value.KeyValue;
import com.czertainly.api.model.core.cryptography.key.KeyItemDetailDto;
import com.czertainly.api.model.core.cryptography.key.KeyItemDto;
import com.czertainly.api.model.core.cryptography.key.KeyState;
import com.czertainly.api.model.core.cryptography.key.KeyUsage;
import com.czertainly.core.util.CryptographicHelper;
import com.czertainly.core.util.DtoMapper;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "cryptographic_key_item")
@EntityListeners(AuditingEntityListener.class)
public class CryptographicKeyItem extends UniquelyIdentified implements Serializable, DtoMapper<KeyItemDetailDto> {

    @Column(name = "name")
    private String name;

    // TODO: change name of the column to key_uuid
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "cryptographic_key_uuid", insertable = false, updatable = false, nullable = false)
    @ToString.Exclude
    private CryptographicKey cryptographicKey;

    // TODO: change name of the column to key_uuid
    @Column(name = "cryptographic_key_uuid")
    private UUID cryptographicKeyUuid;

    @Column(name = "key_reference_uuid")
    private UUID keyReferenceUuid;

    @Column(name = "type")
    @Enumerated(EnumType.STRING)
    private KeyType type;

    // TODO: change name of the column to key_algorithm
    @Column(name = "cryptographic_algorithm")
    @Enumerated(EnumType.STRING)
    private KeyAlgorithm keyAlgorithm;

    @Column(name = "format")
    @Enumerated(EnumType.STRING)
    private KeyFormat format;

    @Column(name = "keyData")
    private String keyData;

    @Column(name = "length")
    private int length;

    @Column(name = "state")
    @Enumerated(EnumType.STRING)
    private KeyState state;

    @Column(name = "usage")
    private String usage;

    @Column(name = "enabled")
    private boolean enabled;

    @Column(name = "fingerprint")
    private String fingerprint;

    @Enumerated(EnumType.STRING)
    @Column(name = "reason")
    private KeyCompromiseReason reason;

    @Column(name = "created_at", nullable = false, updatable = false)
    @CreatedDate
    protected LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    @LastModifiedDate
    protected LocalDateTime updatedAt;

    public void setCryptographicKey(CryptographicKey cryptographicKey) {
        this.cryptographicKey = cryptographicKey;
        if (cryptographicKey != null) this.cryptographicKeyUuid = cryptographicKey.getUuid();
    }

    public void setKeyData(KeyFormat keyFormat, KeyValue value) {
        this.keyData = CryptographicHelper.serializeKeyValue(keyFormat, value);
    }

    public List<KeyUsage> getUsage() {
        if (usage == null) return new ArrayList<>();
        return Arrays.stream(
                usage.split(",")
        ).map(
                i -> KeyUsage.valueOf(
                        Integer.parseInt(i)
                )
        ).collect(Collectors.toList());
    }

    public void setUsage(List<KeyUsage> usage) {
        if (usage == null || usage.isEmpty()) {
            this.usage = null;
            return;
        }

        this.usage = usage.stream().map(
                i -> String.valueOf(
                        i.getBitmask()
                )
        ).collect(
                Collectors.joining(",")
        );
    }


    @Override
    public KeyItemDetailDto mapToDto() {
        KeyItemDetailDto dto = new KeyItemDetailDto();
        dto.setName(name);
        dto.setUuid(uuid.toString());
        dto.setKeyReferenceUuid(keyReferenceUuid.toString());
        dto.setKeyAlgorithm(keyAlgorithm);
        dto.setType(type);
        dto.setLength(length);
        dto.setFormat(format);
        dto.setState(state);
        dto.setEnabled(enabled);
        dto.setUsage(getUsage());
        dto.setReason(reason);
        dto.setKeyData(keyData);
        return dto;
    }

    public KeyItemDto mapToSummaryDto() {
        KeyItemDto dto = new KeyItemDto();
        dto.setName(name);
        dto.setUuid(uuid.toString());
        dto.setKeyReferenceUuid(keyReferenceUuid.toString());
        dto.setKeyAlgorithm(keyAlgorithm);
        dto.setType(type);
        dto.setLength(length);
        dto.setFormat(format);
        dto.setState(state);
        dto.setEnabled(enabled);
        dto.setUsage(getUsage());
        dto.setKeyWrapperUuid(cryptographicKey.getUuid().toString());
        dto.setAssociations((cryptographicKey.getItems().size() - 1) + cryptographicKey.getCertificates().size());
        dto.setDescription(cryptographicKey.getDescription());
        if (cryptographicKey.getGroups() != null) {
            dto.setGroups(cryptographicKey.getGroups().stream().map(Group::mapToDto).toList());
        }
        if (cryptographicKey.getOwner() != null) {
            dto.setOwnerUuid(cryptographicKey.getOwner().getOwnerUuid().toString());
            dto.setOwner(cryptographicKey.getOwner().getOwnerUsername());
        }
        dto.setCreationTime(cryptographicKey.getCreated());
        dto.setTokenInstanceName(cryptographicKey.getTokenInstanceReference().getName());
        dto.setTokenInstanceUuid(cryptographicKey.getTokenInstanceReferenceUuid().toString());
        if (cryptographicKey.getTokenProfile() != null) {
            dto.setTokenProfileName(cryptographicKey.getTokenProfile().getName());
            dto.setTokenProfileUuid(cryptographicKey.getTokenProfile().getUuid().toString());
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
        CryptographicKeyItem that = (CryptographicKeyItem) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
