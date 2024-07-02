package com.czertainly.core.messaging.model;

import com.czertainly.api.model.connector.notification.NotificationType;
import com.czertainly.api.model.core.auth.Resource;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

@Getter
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class NotificationMessage {

    private NotificationType type;

    private Resource resource;

    private UUID resourceUUID;

    private Object data;

    private List<NotificationRecipient> recipients;

    public NotificationMessage(NotificationType type, Resource resource, UUID resourceUUID, List<NotificationRecipient> recipients, Object data) {
        this.type = type;
        this.resource = resource;
        this.resourceUUID = resourceUUID;
        this.recipients = recipients;
        this.data = data;
    }

    @Override
    public String toString() {
        return String.format("NotificationMessage (%s, %s, %s, %s, %s)", type, resource, resourceUUID, recipients, data);
    }
}
