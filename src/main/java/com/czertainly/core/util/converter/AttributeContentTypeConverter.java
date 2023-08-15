package com.czertainly.core.util.converter;

import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;

import java.beans.PropertyEditorSupport;

public class AttributeContentTypeConverter extends PropertyEditorSupport {
    public void setAsText(final String text) throws IllegalArgumentException {
        setValue(AttributeContentType.fromCode(text));
    }
}