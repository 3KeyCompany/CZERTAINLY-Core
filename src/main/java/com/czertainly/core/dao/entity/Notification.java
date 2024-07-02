package com.czertainly.core.dao.entity;

import com.czertainly.api.model.client.notification.NotificationDto;
import com.czertainly.api.model.core.auth.Resource;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.util.*;

@Setter
@Getter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "notification")
public class Notification extends UniquelyIdentified {

    @Column(name = "message", nullable = false)
    private String message;

    @Column(name = "detail")
    private String detail;

    @Column(name = "sent_at", nullable = false, columnDefinition = "TIMESTAMP default CURRENT_TIMESTAMP")
    private Date sentAt = new Date();

    @Column(name = "target_object_type")
    @Enumerated(EnumType.STRING)
    private Resource targetObjectType;

    @Column(name = "target_object_identification")
    private String targetObjectIdentification;

    @OneToMany(fetch = FetchType.LAZY, mappedBy = "notification", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    private Set<NotificationRecipient> notificationRecipients;

    public NotificationDto mapToDto() {
        Optional<NotificationRecipient> notificationRecipient = this.notificationRecipients.stream().findFirst();

        NotificationDto dto = new NotificationDto();
        dto.setUuid(this.getUuid());
        dto.setMessage(this.message);
        dto.setDetail(this.detail);
        dto.setSentAt(this.sentAt);
        dto.setTargetObjectType(this.targetObjectType);
        if (this.targetObjectIdentification != null) {
            dto.setTargetObjectIdentification(List.of(this.targetObjectIdentification.split(",")));
        }
        notificationRecipient.ifPresent(recipient -> dto.setReadAt(recipient.getReadAt()));
        return dto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        Notification that = (Notification) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
