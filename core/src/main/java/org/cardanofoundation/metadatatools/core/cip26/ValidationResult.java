package org.cardanofoundation.metadatatools.core.cip26;

import lombok.*;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Getter(AccessLevel.PUBLIC)
@Setter(AccessLevel.PUBLIC)
@NoArgsConstructor
@ToString
public class ValidationResult {

    private boolean valid = true;
    private final List<ValidationError> validationErrors = new ArrayList<>();

    /**
     * Adds a validation error with the specified field and message.
     *
     * @param field the field that has the validation error
     * @param message the error message
     */
    public void addValidationError(final ValidationField field, final String message) {
        if (field == null) {
            throw new IllegalArgumentException("field cannot be null.");
        }
        if (message == null) {
            throw new IllegalArgumentException("message cannot be null.");
        }
        if (message.isBlank()) {
            throw new IllegalArgumentException("message cannot be empty or blank.");
        }
        this.validationErrors.add(new ValidationError(field, message));
        this.valid = false;
    }

    /**
     * Adds a validation error with the GENERAL field and the specified message.
     * This is a convenience method for backward compatibility.
     *
     * @param error the error message
     * @deprecated Use {@link #addValidationError(ValidationField, String)} instead
     */
    @Deprecated
    public void addValidationError(final String error) {
        addValidationError(ValidationField.GENERAL, error);
    }

    /**
     * Returns a list of error messages (without field information).
     * This method is provided for backward compatibility.
     *
     * @return list of error messages
     * @deprecated Use {@link #getValidationErrors()} and access the field information
     */
    @Deprecated
    public List<String> getValidationErrorMessages() {
        return validationErrors.stream()
                .map(ValidationError::getMessage)
                .collect(Collectors.toList());
    }

    /**
     * Filters validation errors by field.
     *
     * @param field the field to filter by
     * @return list of validation errors for the specified field
     */
    public List<ValidationError> getValidationErrorsForField(final ValidationField field) {
        return validationErrors.stream()
                .filter(error -> error.getField() == field)
                .collect(Collectors.toList());
    }

    public void clearValidationErrors() {
        this.validationErrors.clear();
        this.valid = true;
    }

    public void mergeWith(final ValidationResult otherResult) {
        this.valid = this.valid && otherResult.isValid();
        this.validationErrors.addAll(otherResult.getValidationErrors());
    }

    public static ValidationResult mergeResults(final List<ValidationResult> validationResults) {
        final ValidationResult mergedResult = new ValidationResult();
        if (!validationResults.isEmpty()) {
            for (final ValidationResult result : validationResults) {
                mergedResult.mergeWith(result);
            }
        }
        return mergedResult;
    }

}
