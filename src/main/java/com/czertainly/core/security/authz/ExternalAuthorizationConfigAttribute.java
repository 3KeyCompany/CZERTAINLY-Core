package com.czertainly.core.security.authz;

import org.springframework.security.access.ConfigAttribute;

public class ExternalAuthorizationConfigAttribute implements ConfigAttribute {

    private final String attributeName;
    private final Object attributeValue;

    public ExternalAuthorizationConfigAttribute(String attributeName, Object attributeValue) {
        this.attributeName = attributeName;
        this.attributeValue = attributeValue;
    }

    @Override
    public String getAttribute() {
        return "%s=%s".formatted(this.attributeName, this.attributeValue);
    }

    public String getAttributeName() {
        return attributeName;
    }

    public Object getAttributeValue() {
        return attributeValue;
    }

    public String getAttributeValueAsString() {
        return attributeValue.toString();
    }
}