package com.czertainly.core.util;

import com.czertainly.api.model.core.acme.Identifier;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;

public class AcmeSerializationUtil {
	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	public static String serializeIdentifiers(List<Identifier> identifiers) {
		try {
			return OBJECT_MAPPER.writeValueAsString(identifiers);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	public static List<Identifier> deserializeIdentifiers(String identifier) {
		if (identifier == null || identifier.isEmpty()) {
			return new ArrayList<>();
		}
		try {
			return OBJECT_MAPPER.readValue(identifier, new TypeReference<>() {
			});
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	public static Identifier deserializeIdentifier(String identifier) {
		if (identifier == null || identifier.isEmpty()) {
			return null;
		}
		try {
			return OBJECT_MAPPER.readValue(identifier, new TypeReference<>() {
			});
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	public static String serialize(Object object) {
		try {
			return OBJECT_MAPPER.writeValueAsString(object);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	public static Object deserialize(String object, Class returnType) {
		OBJECT_MAPPER.configure(
				DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		if (object == null || object.isEmpty()) {
			return new ArrayList<>();
		}
		try {
			return OBJECT_MAPPER.readValue(object, returnType);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}



}
