package com.czertainly.core.dao.entity.workflows;

import com.czertainly.api.model.core.workflows.TriggerHistoryDto;
import com.czertainly.core.dao.entity.UniquelyIdentified;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "trigger_history")
public class TriggerHistory extends UniquelyIdentified {

    @Column(name = "trigger_uuid", nullable = false)
    private UUID triggerUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "trigger_uuid", nullable = false, insertable = false, updatable = false)
    @ToString.Exclude
    private Trigger trigger;

    @Column(name = "trigger_association_object_uuid")
    private UUID triggerAssociationObjectUuid;

    @Column(name = "object_uuid")
    private UUID objectUuid;

    @Column(name = "reference_object_uuid")
    private UUID referenceObjectUuid;

    @Column(name = "conditions_matched", nullable = false)
    private boolean conditionsMatched;

    @Column(name = "actions_performed", nullable = false)
    private boolean actionsPerformed;

    @Column(name = "triggered_at", nullable = false)
    private OffsetDateTime triggeredAt;

    @Column(name = "message")
    private String message;

    @OneToMany(mappedBy = "triggerHistory", fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @ToString.Exclude
    private List<TriggerHistoryRecord> records = new ArrayList<>();

    public TriggerHistoryDto mapToDto() {
        TriggerHistoryDto triggerHistoryDto = new TriggerHistoryDto();
        triggerHistoryDto.setUuid(String.valueOf(uuid));
        triggerHistoryDto.setConditionsMatched(conditionsMatched);
        triggerHistoryDto.setActionsPerformed(actionsPerformed);
        if (objectUuid != null) triggerHistoryDto.setObjectUuid(objectUuid.toString());
        if (referenceObjectUuid != null) triggerHistoryDto.setReferenceObjectUuid(referenceObjectUuid.toString());
        triggerHistoryDto.setTriggeredAt(triggeredAt);
        triggerHistoryDto.setMessage(message);
        triggerHistoryDto.setRecords(records.stream().map(TriggerHistoryRecord::mapToDto).toList());
        return triggerHistoryDto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        TriggerHistory that = (TriggerHistory) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
