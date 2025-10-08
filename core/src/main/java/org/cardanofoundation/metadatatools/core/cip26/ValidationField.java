package org.cardanofoundation.metadatatools.core.cip26;

import java.util.Locale;

/**
 * Enumeration of fields that can have validation errors in CIP-26 metadata.
 */
public enum ValidationField {
    /**
     * The name property (required, max 50 characters)
     */
    NAME("name", true),

    /**
     * The description property (required, max 500 characters)
     */
    DESCRIPTION("description", true),

    /**
     * The ticker property (optional, 2-9 characters)
     */
    TICKER("ticker", true),

    /**
     * The decimals property (optional, must be >= 0)
     */
    DECIMALS("decimals", true),

    /**
     * The logo property (optional, max 87400 characters)
     */
    LOGO("logo", true),

    /**
     * The subject field (56-120 hex characters)
     */
    SUBJECT("subject", false),

    /**
     * The policy field
     */
    POLICY("policy", false),

    /**
     * The sequence number field (must be non-null and non-negative)
     */
    SEQUENCE_NUMBER("sequenceNumber", false),

    /**
     * Required properties validation
     */
    REQUIRED_PROPERTIES("requiredProperties", false),

    /**
     * Signature verification errors
     */
    SIGNATURE("signature", false),

    /**
     * General validation errors that don't relate to a specific field
     */
    GENERAL("general", false);

    private final String key;
    private final boolean isProperty;

    ValidationField(final String key, final boolean isProperty) {
        this.key = key;
        this.isProperty = isProperty;
    }

    /**
     * Returns the string key for this field (lowercase, suitable for JSON/map keys).
     *
     * @return the string key
     */
    public String getKey() {
        return key;
    }

    /**
     * Returns whether this field represents a metadata property (vs a validation-only field).
     *
     * @return true if this is a property field (name, description, ticker, decimals, logo)
     */
    public boolean isProperty() {
        return isProperty;
    }

    /**
     * Converts a string property name to a ValidationField enum.
     *
     * @param propertyName the property name (case-insensitive)
     * @return the corresponding ValidationField, or null if not a valid property
     */
    public static ValidationField fromPropertyName(final String propertyName) {
        if (propertyName == null) {
            return null;
        }
        final String normalized = propertyName.trim().toLowerCase(Locale.ROOT);
        for (ValidationField field : values()) {
            if (field.isProperty && field.key.equals(normalized)) {
                return field;
            }
        }
        return null;
    }

    /**
     * Converts a ValidationField to its string key representation.
     * Throws exception if the field is not a property field.
     *
     * @return the string key
     * @throws IllegalStateException if this field is not a property field
     */
    public String toPropertyName() {
        if (!isProperty) {
            throw new IllegalStateException("Cannot convert non-property field " + this + " to property name");
        }
        return key;
    }
}
