package com.czertainly.core.dao.entity.workflows;

import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.workflows.ConditionItemDto;
import com.czertainly.core.dao.entity.UniquelyIdentified;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.type.SqlTypes;

import java.util.Objects;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "condition_item")
public class ConditionItem extends UniquelyIdentified {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "condition_uuid", nullable = false)
    @ToString.Exclude
    private Condition condition;

    @Column(name = "field_source", nullable = false)
    @Enumerated(EnumType.STRING)
    private FilterFieldSource fieldSource;

    @Column(name = "field_identifier", nullable = false)
    private String fieldIdentifier;

    @Column(name = "operator", nullable = false)
    @Enumerated(EnumType.STRING)
    private FilterConditionOperator operator;

    @Column(name = "value", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private Object value;

    public ConditionItemDto mapToDto() {
        ConditionItemDto conditionItemDto = new ConditionItemDto();
        conditionItemDto.setFieldSource(fieldSource);
        conditionItemDto.setFieldIdentifier(fieldIdentifier);
        conditionItemDto.setOperator(operator);
        conditionItemDto.setValue(value);

        return conditionItemDto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        ConditionItem that = (ConditionItem) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
