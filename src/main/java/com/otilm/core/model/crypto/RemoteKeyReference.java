package com.otilm.core.model.crypto;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import java.util.List;
import java.util.UUID;

/** Provider-owned key identity, interpreted in the context of its connector and token. */
public sealed interface RemoteKeyReference {

    record UuidReference(UUID uuid) implements RemoteKeyReference {
    }

    /** Opaque durable key handle returned by a stateless provider. */
    record MetadataReference(List<MetadataAttribute> keyMeta) implements RemoteKeyReference {
    }
}
