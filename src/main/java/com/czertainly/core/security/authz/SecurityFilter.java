package com.czertainly.core.security.authz;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public class SecurityFilter {

    /**
     * List of object uuids user can access
     */
    private List<UUID> allowedObjects;

    /**
     * List of object uuids user can not access
     */
    private List<UUID> forbiddenObjects;

    /**
     * Specifies whether the user has access to all objects or only those explicitly allowed.
     * When true, the user can access only objects to which access is explicitly allowed.
     * When false, the user can access all objects except those to which access is explicitly forbidden.
     */
    private boolean areOnlySpecificObjectsAllowed;

    protected SecurityFilter() {
        this(new ArrayList<>(), new ArrayList<>(), false);
    }

    public SecurityFilter(List<String> allowedObjects, List<String> forbiddenObjects, boolean areOnlySpecificObjectsAllowed) {
        this.allowedObjects = allowedObjects.stream().map(UUID::fromString).collect(Collectors.toList());
        this.forbiddenObjects = forbiddenObjects.stream().map(UUID::fromString).collect(Collectors.toList());
        this.areOnlySpecificObjectsAllowed = areOnlySpecificObjectsAllowed;
    }

    public static SecurityFilter create() {
        return new SecurityFilter();
    }

    public List<UUID> getAllowedObjects() {
        return allowedObjects;
    }

    public List<UUID> getForbiddenObjects() {
        return forbiddenObjects;
    }

    public void addAllowedObjects(List<String> objectUUIDs) {
        this.allowedObjects.addAll(objectUUIDs.stream().map(UUID::fromString).collect(Collectors.toList()));
    }

    public void addDeniedObjects(List<String> objectUUIDs) {
        this.forbiddenObjects.addAll(objectUUIDs.stream().map(UUID::fromString).collect(Collectors.toList()));
    }

    public boolean areOnlySpecificObjectsAllowed() {
        return areOnlySpecificObjectsAllowed;
    }

    public void setAreOnlySpecificObjectsAllowed(boolean areOnlySpecificObjectsAllowed) {
        this.areOnlySpecificObjectsAllowed = areOnlySpecificObjectsAllowed;
    }
}
