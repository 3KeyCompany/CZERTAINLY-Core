
package com.czertainly.core.dao.entity.workflows;

import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.api.model.core.workflows.TriggerDetailDto;
import com.czertainly.api.model.core.workflows.TriggerDto;
import com.czertainly.api.model.core.workflows.TriggerType;
import com.czertainly.core.dao.entity.UniquelyIdentified;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.util.List;
import java.util.Objects;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "trigger")
public class Trigger extends UniquelyIdentified {
    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "type", nullable = false)
    @Enumerated(EnumType.STRING)
    private TriggerType type;

    @Column(name = "resource", nullable = false)
    @Enumerated(EnumType.STRING)
    private Resource resource;

    @Column(name = "ignore_trigger", nullable = false)
    private boolean ignoreTrigger;

    @Column(name = "event")
    @Enumerated(EnumType.STRING)
    private ResourceEvent event;

    @Column(name = "event_resource")
    @Enumerated(EnumType.STRING)
    private Resource eventResource;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "trigger_2_rule",
            joinColumns = @JoinColumn(name = "trigger_uuid"),
            inverseJoinColumns = @JoinColumn(name = "rule_uuid"))
    @ToString.Exclude
    private List<Rule> rules;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "trigger_2_action",
            joinColumns = @JoinColumn(name = "trigger_uuid"),
            inverseJoinColumns = @JoinColumn(name = "action_uuid"))
    @ToString.Exclude
    private List<Action> actions;

    public TriggerDto mapToDto() {
        TriggerDto triggerDto = new TriggerDto();
        setCommonFields(triggerDto);
        return triggerDto;
    }

    public TriggerDetailDto mapToDetailDto() {
        TriggerDetailDto triggerDetailDto = new TriggerDetailDto();
        setCommonFields(triggerDetailDto);

        if (rules != null) triggerDetailDto.setRules(rules.stream().map(Rule::mapToDto).toList());
        if (actions != null) triggerDetailDto.setActions(actions.stream().map(Action::mapToDto).toList());
        return triggerDetailDto;
    }

    private void setCommonFields(TriggerDto triggerDto) {
        triggerDto.setUuid(uuid.toString());
        triggerDto.setName(name);
        triggerDto.setDescription(description);
        triggerDto.setType(type);
        triggerDto.setResource(resource);
        triggerDto.setIgnoreTrigger(ignoreTrigger);
        triggerDto.setEvent(event);
        triggerDto.setEventResource(eventResource);
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        Trigger trigger = (Trigger) o;
        return getUuid() != null && Objects.equals(getUuid(), trigger.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
