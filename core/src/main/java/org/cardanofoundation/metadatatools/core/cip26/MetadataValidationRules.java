package org.cardanofoundation.metadatatools.core.cip26;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.cardanofoundation.metadatatools.core.cip26.model.MetadataProperty;
import org.cardanofoundation.metadatatools.core.cip26.model.PolicyScript;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class MetadataValidationRules {

    private static final int MAX_NAME_LENGTH = 50;
    private static final int MAX_DESCRIPTION_LENGTH = 500;
    private static final int MIN_TICKER_LENGTH = 2;
    private static final int MAX_TICKER_LENGTH = 9;
    private static final int MIN_DECIMALS_VALUE = 0;
    private static final int MAX_LOGO_LENGTH = 87400;
    private static final int MAX_URL_LENGTH = 250;
    private static final int POLICY_ID_SIZE = 28;
    private static final int POLICY_ID_HEX_STRING_LENGTH = POLICY_ID_SIZE * 2;
    private static final int MAX_ASSET_NAME_SIZE = 32;
    private static final int MAX_SUBJECT_LENGTH = POLICY_ID_HEX_STRING_LENGTH + (MAX_ASSET_NAME_SIZE * 2);
    private static final List<String> REQUIRED_PROPERTIES = List.of("name", "description");

    @FunctionalInterface
    interface TokenMetadataValidatorFunction {
        ValidationResult apply(final String propertyName, final MetadataProperty<?> property);
    }

    private static final Map<String, TokenMetadataValidatorFunction> VALIDATION_RULES = Map.ofEntries(
            Map.entry("name", MetadataValidationRules::applyNamePropertyValidationRules),
            Map.entry("description", MetadataValidationRules::applyDescriptionPropertyValidationRules),
            Map.entry("ticker", MetadataValidationRules::applyTickerPropertyValidationRules),
            Map.entry("decimals", MetadataValidationRules::applyDecimalsPropertyValidationRules),
            Map.entry("logo", MetadataValidationRules::applyLogoPropertyValidationRules),
            Map.entry("url", MetadataValidationRules::applyUrlPropertyValidationRules)
    );

    private static ValidationResult applyNamePropertyValidationRules(final String propertyName, final MetadataProperty<?> property) {
        final ValidationResult validationResult = applyDefaultValidationRules(propertyName, property, ValidationField.NAME);

        // Defensive null check: applyDefaultValidationRules has already added a validation error if value is null.
        // This check prevents NullPointerException when calling .getClass() below.
        // Name is a REQUIRED field, so null values are correctly reported as errors by applyDefaultValidationRules.
        if (property.getValue() == null) {
            return validationResult;
        }

        if (!(property.getValue().getClass() == String.class)) {
            validationResult.addValidationError(ValidationField.NAME, String.format("property %s: value is not of expected type String but %s", propertyName, property.getValue().getClass().getName()));
            return validationResult;
        }
        final String value = (String) property.getValue();
        if (value.length() > MAX_NAME_LENGTH) {
            validationResult.addValidationError(ValidationField.NAME, String.format("property %s: only %d characters allow but got %d", propertyName, MAX_NAME_LENGTH, value.length()));
        }
        return validationResult;
    }

    private static ValidationResult applyDescriptionPropertyValidationRules(final String propertyName, final MetadataProperty<?> property) {
        final ValidationResult validationResult = applyDefaultValidationRules(propertyName, property, ValidationField.DESCRIPTION);

        // Defensive null check: applyDefaultValidationRules has already added a validation error if value is null.
        // This check prevents NullPointerException when calling .getClass() below.
        // Description is a REQUIRED field, so null values are correctly reported as errors by applyDefaultValidationRules.
        if (property.getValue() == null) {
            return validationResult;
        }

        if (!(property.getValue().getClass() == String.class)) {
            validationResult.addValidationError(ValidationField.DESCRIPTION, String.format("property %s: value is not of expected type String but %s", propertyName, property.getValue().getClass().getName()));
            return validationResult;
        }
        final String value = (String) property.getValue();
        if (value.length() > MAX_DESCRIPTION_LENGTH) {
            validationResult.addValidationError(ValidationField.DESCRIPTION, String.format("property %s: only %d characters allow but got %d", propertyName, MAX_DESCRIPTION_LENGTH, value.length()));
        }
        return validationResult;
    }

    private static ValidationResult applyTickerPropertyValidationRules(final String propertyName, final MetadataProperty<?> property) {
        final ValidationResult validationResult = applyDefaultValidationRules(propertyName, property, ValidationField.TICKER);

        // Defensive null check: applyDefaultValidationRules has already added a validation error if value is null.
        // This check prevents NullPointerException when calling .getClass() below.
        // Ticker is an OPTIONAL field, but null values are still reported as errors by applyDefaultValidationRules.
        if (property.getValue() == null) {
            return validationResult;
        }

        if (!(property.getValue().getClass() == String.class)) {
            validationResult.addValidationError(ValidationField.TICKER, String.format("property %s: value is not of expected type String but %s", propertyName, property.getValue().getClass().getName()));
            return validationResult;
        }
        final String value = (String) property.getValue();
        if (value.length() < MIN_TICKER_LENGTH || value.length() > MAX_TICKER_LENGTH) {
            validationResult.addValidationError(ValidationField.TICKER, String.format("property %s: ticker length is %d which is not in the allowed interval of [%d, %d] ", propertyName, value.length(), MIN_TICKER_LENGTH, MAX_TICKER_LENGTH));
        }
        return validationResult;
    }

    private static ValidationResult applyDecimalsPropertyValidationRules(final String propertyName, final MetadataProperty<?> property) {
        final ValidationResult validationResult = applyDefaultValidationRules(propertyName, property, ValidationField.DECIMALS);

        // Defensive null check: applyDefaultValidationRules has already added a validation error if value is null.
        // This check prevents NullPointerException when calling .getClass() below.
        // Decimals is an OPTIONAL field, but null values are still reported as errors by applyDefaultValidationRules.
        if (property.getValue() == null) {
            return validationResult;
        }

        if (!(property.getValue().getClass() == Integer.class)) {
            validationResult.addValidationError(ValidationField.DECIMALS, String.format("property %s: value is not of expected type Integer but %s", propertyName, property.getValue().getClass().getName()));
            return validationResult;
        }
        final int value = (int) property.getValue();
        if (value < MIN_DECIMALS_VALUE) {
            validationResult.addValidationError(ValidationField.DECIMALS, String.format("property %s: value %d is not in the expected range of [%d:)", propertyName, value, MIN_DECIMALS_VALUE));
        }
        return validationResult;
    }

    private static ValidationResult applyLogoPropertyValidationRules(final String propertyName, final MetadataProperty<?> property) {
        final ValidationResult validationResult = applyDefaultValidationRules(propertyName, property, ValidationField.LOGO);

        // Defensive null check: applyDefaultValidationRules has already added a validation error if value is null.
        // This check prevents NullPointerException when calling .getClass() below.
        // Logo is an OPTIONAL field, but null values are still reported as errors by applyDefaultValidationRules.
        if (property.getValue() == null) {
            return validationResult;
        }

        if (!(property.getValue().getClass() == String.class)) {
            validationResult.addValidationError(ValidationField.LOGO, String.format("property %s: value is not of expected type String but %s", propertyName, property.getValue().getClass().getName()));
            return validationResult;
        }
        final String value = (String) property.getValue();
        if (value.length() > MAX_LOGO_LENGTH) {
            validationResult.addValidationError(ValidationField.LOGO, String.format("property %s: only %d characters allow but got %d", propertyName, MAX_LOGO_LENGTH, value.length()));
        }
        return validationResult;
    }

    private static ValidationResult applyUrlPropertyValidationRules(final String propertyName, final MetadataProperty<?> property) {
        final ValidationResult validationResult = applyDefaultValidationRules(propertyName, property, ValidationField.URL);

        // Defensive null check: applyDefaultValidationRules has already added a validation error if value is null.
        // This check prevents NullPointerException when calling .getClass() below.
        // URL is an OPTIONAL field, but null values are still reported as errors by applyDefaultValidationRules.
        if (property.getValue() == null) {
            return validationResult;
        }

        if (!(property.getValue().getClass() == String.class)) {
            validationResult.addValidationError(ValidationField.URL, String.format("property %s: value is not of expected type String but %s", propertyName, property.getValue().getClass().getName()));
            return validationResult;
        }
        final String value = (String) property.getValue();
        if (value.length() > MAX_URL_LENGTH) {
            validationResult.addValidationError(ValidationField.URL, String.format("property %s: only %d characters allow but got %d", propertyName, MAX_URL_LENGTH, value.length()));
        }
        return validationResult;
    }

    private static ValidationResult applyDefaultValidationRules(final String propertyName, final MetadataProperty<?> property, final ValidationField field) {
        final ValidationResult validationResult = new ValidationResult();
        if (property.getValue() == null) {
            validationResult.addValidationError(field, String.format("property %s: value is undefined", propertyName));
        }
        if (property.getSequenceNumber() == null) {
            validationResult.addValidationError(ValidationField.SEQUENCE_NUMBER, String.format("property %s: sequenceNumber is undefined", propertyName));
        }
        if (property.getSequenceNumber() != null && property.getSequenceNumber() < 0) {
            validationResult.addValidationError(ValidationField.SEQUENCE_NUMBER, String.format("property %s: sequenceNumber is negative (%d)", propertyName, property.getSequenceNumber()));
        }
        return validationResult;
    }

    public static ValidationResult validateProperty(final String propertyName, final MetadataProperty<?> metadataProperty) {
        return VALIDATION_RULES.getOrDefault(propertyName, (name, prop) -> applyDefaultValidationRules(name, prop, ValidationField.GENERAL))
                .apply(propertyName, metadataProperty);
    }

    /**
     * Validates a property using strongly-typed field enum.
     *
     * @param field the property field
     * @param metadataProperty the property to validate
     * @return validation result
     * @throws IllegalArgumentException if field is null or not a property field
     */
    public static ValidationResult validateProperty(final ValidationField field, final MetadataProperty<?> metadataProperty) {
        if (field == null) {
            throw new IllegalArgumentException("field cannot be null");
        }
        if (!field.isProperty()) {
            throw new IllegalArgumentException("field must be a property field, but got: " + field);
        }
        return validateProperty(field.getKey(), metadataProperty);
    }

    public static void validateHasRequiredProperties(final Set<String> propertyNames, final ValidationResult validationResult) {
        if (!propertyNames.containsAll(REQUIRED_PROPERTIES)) {
            validationResult.addValidationError(ValidationField.REQUIRED_PROPERTIES, String.format("Missing required properties. Required properties are %s", REQUIRED_PROPERTIES));
        }
    }

    public static void validateSubjectAndPolicy(final String subject, final String policy, final ValidationResult validationResult) {
        if (subject == null || subject.isBlank()) {
            validationResult.addValidationError(ValidationField.SUBJECT, "Missing, empty or blank subject.");
        } else {
            try {
                // check if subject is hex
                Hex.decode(subject);
            } catch (final DecoderException e) {
                validationResult.addValidationError(ValidationField.SUBJECT, String.format("Cannot decode hex string representation of subject hash due to %s", e.getMessage()));
            }

            if (subject.length() % 2 != 0) {
                validationResult.addValidationError(ValidationField.SUBJECT, "Number of characters in the subject must be even to represent a complete byte sequence.");
            }

            if (subject.length() < POLICY_ID_HEX_STRING_LENGTH) {
                validationResult.addValidationError(ValidationField.SUBJECT, String.format("Subject must be at least %d characters long.", POLICY_ID_HEX_STRING_LENGTH));
            }

            if (subject.length() > MAX_SUBJECT_LENGTH) {
                validationResult.addValidationError(ValidationField.SUBJECT, String.format("Subject must not exceed %d characters but got %d.", MAX_SUBJECT_LENGTH, subject.length()));
            }

            if (policy != null ) {
                final ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
                try {
                    final PolicyScript policyScript = PolicyScript.fromCborTree(cborMapper.readTree(Hex.decode(policy)));
                    final String policyId = policyScript.computePolicyId();

                    if (policyId.length() % 2 != 0) {
                        validationResult.addValidationError(ValidationField.POLICY, "Number of characters in the policyId must be even to represent a complete byte sequence.");
                    }

                    // check if policy id is hex
                    Hex.decode(policyId);

                    if (!subject.toLowerCase().startsWith(policyId.toLowerCase())) {
                        validationResult.addValidationError(ValidationField.POLICY, "If a policy is given the first 28 bytes of the subject should match the policy id.");
                    }
                } catch (final IOException e) {
                    validationResult.addValidationError(ValidationField.POLICY, "Could not deserialize policy script from policy value due to " + e.getMessage());
                } catch (final DecoderException e) {
                    validationResult.addValidationError(ValidationField.POLICY, String.format("Cannot decode hex string representation of policy hash due to %s", e.getMessage()));
                }
            }
        }
    }
}
