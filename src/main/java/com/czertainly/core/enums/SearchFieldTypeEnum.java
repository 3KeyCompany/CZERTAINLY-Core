package com.czertainly.core.enums;

import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.api.model.core.search.FilterFieldType;

import java.util.List;

public enum SearchFieldTypeEnum {

    STRING(FilterFieldType.STRING,
            List.of(FilterConditionOperator.CONTAINS, FilterConditionOperator.NOT_CONTAINS, FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS, FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY, FilterConditionOperator.STARTS_WITH, FilterConditionOperator.ENDS_WITH)
            , false),
    DATE(FilterFieldType.DATE,
            List.of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS, FilterConditionOperator.GREATER, FilterConditionOperator.LESSER, FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY)
            , false),
    DATETIME(FilterFieldType.DATETIME,
            List.of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS, FilterConditionOperator.GREATER, FilterConditionOperator.LESSER, FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY)
            , false),
    NUMBER(FilterFieldType.NUMBER,
            List.of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS, FilterConditionOperator.GREATER, FilterConditionOperator.LESSER, FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY)
            , false),
    LIST(FilterFieldType.LIST,
            List.of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS, FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY)
            , true),
    BOOLEAN(FilterFieldType.BOOLEAN,
         List.of(FilterConditionOperator.EQUALS, FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY)
            , false),
    OTHERS_AS_STRING(FilterFieldType.STRING,
            List.of(FilterConditionOperator.CONTAINS, FilterConditionOperator.NOT_CONTAINS, FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS, FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY, FilterConditionOperator.STARTS_WITH, FilterConditionOperator.ENDS_WITH)
            , false);


    private FilterFieldType fieldType;

    private List<FilterConditionOperator> contitions;

    private boolean multiValue;

    SearchFieldTypeEnum(final FilterFieldType fieldType, final List<FilterConditionOperator> contitions, final boolean multiValue) {
        this.fieldType = fieldType;
        this.contitions = contitions;
        this.multiValue = multiValue;
    }

    public FilterFieldType getFieldType() {
        return fieldType;
    }

    public List<FilterConditionOperator> getContitions() {
        return contitions;
    }

    public boolean isMultiValue() {
        return multiValue;
    }
}
