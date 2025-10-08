package org.cardanofoundation.metadatatools.core.cip26;

import lombok.*;

/**
 * Represents a validation error with an associated field and error message.
 */
@Getter(AccessLevel.PUBLIC)
@AllArgsConstructor
@ToString
@EqualsAndHashCode
public class ValidationError {

    /**
     * The field that has the validation error
     */
    private final ValidationField field;

    /**
     * The error message describing the validation failure
     */
    private final String message;
}
