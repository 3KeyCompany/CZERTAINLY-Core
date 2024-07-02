package com.czertainly.core.config;

import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.ExternalAuthorizationConfigAttribute;
import com.czertainly.core.security.authz.GroupParentUUIDGetter;
import com.czertainly.core.security.authz.NoOpParentUUIDGetter;
import com.czertainly.core.security.authz.ParentUUIDGetter;
import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;

import java.lang.annotation.Annotation;
import java.util.Collection;
import java.util.Objects;

class OpaSecuredAnnotationMetadataExtractorTest {

    OpaSecuredAnnotationMetadataExtractor metadataExtractor = new OpaSecuredAnnotationMetadataExtractor();

    @Test
    void extractsResourceAndAction() {
        // given
        ExternalAuthorization externalAuthorization = new TestExternalAuthorization(Resource.GROUP, ResourceAction.DELETE, NoOpParentUUIDGetter.class);

        // when
        Collection<ExternalAuthorizationConfigAttribute> attributes = metadataExtractor.extractAttributes(externalAuthorization);

        // then
        assertAttributePresent("name", Resource.GROUP.getCode(), attributes);
        assertAttributePresent("action", ResourceAction.DELETE.getCode(), attributes);
    }

    @Test
    void doesNotExtractUUIDGetterWhenNoOpImplementationIsUsed() {
        // given
        ExternalAuthorization externalAuthorization = new TestExternalAuthorization(Resource.GROUP, ResourceAction.DELETE, NoOpParentUUIDGetter.class);

        // when
        Collection<ExternalAuthorizationConfigAttribute> attributes = metadataExtractor.extractAttributes(externalAuthorization);

        // then
        assertAttributeNotPresent("parentUUIDGetter", attributes);
    }

    @Test
    void ExtractsUUIDGetterWhenOtherImplementationThanNoOpIsUsed() {
        // given
        ExternalAuthorization externalAuthorization = new TestExternalAuthorization(Resource.GROUP, ResourceAction.DELETE, GroupParentUUIDGetter.class);

        // when
        Collection<ExternalAuthorizationConfigAttribute> attributes = metadataExtractor.extractAttributes(externalAuthorization);

        // then
        assertAttributePresent("parentUUIDGetter", GroupParentUUIDGetter.class, attributes);
    }

    void assertAttributePresent(String attributeName, Object attributeValue, Collection<ExternalAuthorizationConfigAttribute> attributes) {
        boolean isAttributePresent = attributes.stream()
                .anyMatch(a -> Objects.equals(a.getAttributeName(), attributeName) && Objects.equals(a.getAttributeValue(), attributeValue));
        if (!isAttributePresent) {
            throw new AssertionFailedError(
                    "Config attribute '%s=%s' not found.".formatted(attributeName, attributeValue)
            );
        }
    }

    @SuppressWarnings("SameParameterValue")
    void assertAttributeNotPresent(String attributeName, Collection<ExternalAuthorizationConfigAttribute> attributes) {
        boolean isAttributePresent = attributes.stream()
                .anyMatch(a -> Objects.equals(a.getAttributeName(), attributeName));
        if (isAttributePresent) {
            throw new AssertionFailedError(
                    "Config attribute '%s' should not be present in collection.".formatted(attributeName)
            );
        }
    }


    @SuppressWarnings("ClassExplicitlyAnnotation")
    static class TestExternalAuthorization implements ExternalAuthorization {

        private final Resource resource;
        private final ResourceAction resourceAction;
        private final Resource parentResource;
        private final ResourceAction parentResourceAction;
        private final Class<? extends ParentUUIDGetter> parentUUIDGetterClass;

        public TestExternalAuthorization(Resource resource, ResourceAction resourceAction, Class<? extends ParentUUIDGetter> parentUUIDGetterClass) {
            this.resource = resource;
            this.resourceAction = resourceAction;
            this.parentResource = Resource.NONE;
            this.parentResourceAction = ResourceAction.NONE;
            this.parentUUIDGetterClass = parentUUIDGetterClass;
        }

        public TestExternalAuthorization(Resource resource, ResourceAction resourceAction, Resource parentResource, ResourceAction parentResourceAction, Class<? extends ParentUUIDGetter> parentUUIDGetterClass) {
            this.resource = resource;
            this.resourceAction = resourceAction;
            this.parentResource = parentResource;
            this.parentResourceAction = parentResourceAction;
            this.parentUUIDGetterClass = parentUUIDGetterClass;
        }

        @Override
        public Resource resource() {
            return resource;
        }

        @Override
        public ResourceAction action() {
            return resourceAction;
        }

        @Override
        public Resource parentResource() { return parentResource; }

        @Override
        public ResourceAction parentAction() { return parentResourceAction; }

        @Override
        public Class<? extends ParentUUIDGetter> parentObjectUUIDGetter() {
            return parentUUIDGetterClass;
        }

        @Override
        public Class<? extends Annotation> annotationType() {
            return ExternalAuthorization.class;
        }
    }
}