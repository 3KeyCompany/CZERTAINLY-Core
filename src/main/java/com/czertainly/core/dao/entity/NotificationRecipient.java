package com.czertainly.core.dao.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.util.Date;
import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "notification_recipient", uniqueConstraints = {@UniqueConstraint(columnNames = {"notification_uuid", "user_uuid"})})
public class NotificationRecipient extends UniquelyIdentified {

    @Column(name = "notification_uuid", nullable = false)
    private UUID notificationUuid;

    @Column(name = "user_uuid", nullable = false)
    private UUID userUuid;

    @Column(name = "read_at")
    private Date readAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "notification_uuid", insertable = false, updatable = false, nullable = false)
    @ToString.Exclude
    private Notification notification;

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        NotificationRecipient that = (NotificationRecipient) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
