package org.cardanofoundation.metadatatools.core.cip26.model;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.*;
import org.bouncycastle.util.encoders.Hex;
import org.cardanofoundation.metadatatools.core.cip26.ValidationField;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class Metadata {

    private static final List<String> REQUIRED_PROPERTIES = List.of("name", "description");

    private String subject;
    private String policy;
    private Map<String, MetadataProperty<?>> properties;

    public Metadata() {
        this.properties = new HashMap<>();
    }

    public Metadata(final String assetName) throws IOException {
        this.properties = new HashMap<>();
        init(assetName);
    }

    public Metadata(final String assetName, final PolicyScript policyScript) throws IOException {
        this.properties = new HashMap<>();
        init(assetName, policyScript);
    }

    public Metadata(final String assetName, final PolicyScript policyScript, final Map<String, MetadataProperty<?>> properties) throws IOException {
        this.properties = Map.copyOf(properties);
        init(assetName, policyScript);
    }

    public void setSubjectFromAssetNameAndPolicyId(final String assetName, final String policyId) {
        this.subject = policyId + Hex.toHexString(assetName.getBytes(StandardCharsets.UTF_8));
    }

    public void setSubjectFromAssetName(final String assetName) {
        this.subject = Hex.toHexString(assetName.getBytes(StandardCharsets.UTF_8));
    }

    public void init(final String assetName, final PolicyScript policyScript) throws IOException {
        final String policyId;
        if (policyScript != null) {
            policyId = policyScript.computePolicyId();
            this.policy = Hex.toHexString(policyScript.toCbor());
        } else {
            policyId = "";
        }
        this.subject = policyId + Hex.toHexString(assetName.getBytes(StandardCharsets.UTF_8));
    }

    public void init(final String assetName) throws IOException {
        init(assetName, null);
    }

    @JsonAnySetter
    public void setRequiredProperties(final String propertyName, MetadataProperty<?> property) {
        addProperty(propertyName, property);
    }

    @JsonAnyGetter
    public Map<String, MetadataProperty<?>> getProperties() {
        return this.properties;
    }

    public void addProperty(final String propertyName, final MetadataProperty<?> property) {
        if (propertyName == null) {
            throw new IllegalArgumentException("propertyName cannot be null.");
        }

        final String propertyNameSanitized = sanitizePropertyName(propertyName);
        if (propertyNameSanitized.isEmpty()) {
            throw new IllegalArgumentException("propertyName cannot be empty or blank.");
        }

        if (property != null) {
            this.properties.put(propertyNameSanitized, property);
        } else {
            this.properties.remove(propertyNameSanitized);
        }
    }

    /**
     * Adds a property with strongly-typed field enum.
     *
     * @param field the property field (must be a property field like NAME, DESCRIPTION, etc.)
     * @param property the property value
     * @throws IllegalArgumentException if field is null or not a property field
     */
    public void addProperty(final ValidationField field, final MetadataProperty<?> property) {
        if (field == null) {
            throw new IllegalArgumentException("field cannot be null.");
        }
        if (!field.isProperty()) {
            throw new IllegalArgumentException("field must be a property field, but got: " + field);
        }

        if (property != null) {
            this.properties.put(field.getKey(), property);
        } else {
            this.properties.remove(field.getKey());
        }
    }

    /**
     * Gets a property by strongly-typed field enum.
     *
     * @param field the property field
     * @return the property value, or null if not present
     * @throws IllegalArgumentException if field is null or not a property field
     */
    public MetadataProperty<?> getProperty(final ValidationField field) {
        if (field == null) {
            throw new IllegalArgumentException("field cannot be null.");
        }
        if (!field.isProperty()) {
            throw new IllegalArgumentException("field must be a property field, but got: " + field);
        }
        return this.properties.get(field.getKey());
    }

    public void removeProperty(final String propertyName) {
        if (propertyName == null) {
            throw new IllegalArgumentException("propertyName cannot be null");
        }

        final String propertyNameSanitized = propertyName.trim();
        if (propertyNameSanitized.isEmpty()) {
            throw new IllegalArgumentException("propertyName cannot be empty or blank");
        }

        this.properties.remove(propertyNameSanitized);
    }

    /**
     * Removes a property by strongly-typed field enum.
     *
     * @param field the property field
     * @throws IllegalArgumentException if field is null or not a property field
     */
    public void removeProperty(final ValidationField field) {
        if (field == null) {
            throw new IllegalArgumentException("field cannot be null");
        }
        if (!field.isProperty()) {
            throw new IllegalArgumentException("field must be a property field, but got: " + field);
        }
        this.properties.remove(field.getKey());
    }

    public static String sanitizePropertyName(final String propertyName) {
        if (propertyName == null) {
            throw new IllegalArgumentException("propertyName cannot be null.");
        }
        return propertyName.trim();
    }

}
