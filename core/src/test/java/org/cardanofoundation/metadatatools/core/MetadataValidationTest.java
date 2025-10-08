package org.cardanofoundation.metadatatools.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.log4j.Log4j2;
import org.bouncycastle.util.encoders.Hex;
import org.cardanofoundation.metadatatools.core.cip26.MetadataCreator;
import org.cardanofoundation.metadatatools.core.cip26.MetadataValidationRules;
import org.cardanofoundation.metadatatools.core.cip26.ValidationField;
import org.cardanofoundation.metadatatools.core.cip26.ValidationResult;
import org.cardanofoundation.metadatatools.core.cip26.model.Metadata;
import org.cardanofoundation.metadatatools.core.cip26.model.MetadataProperty;
import org.cardanofoundation.metadatatools.core.cip26.model.PolicyScript;
import org.cardanofoundation.metadatatools.core.crypto.keys.Key;
import org.cardanofoundation.metadatatools.core.crypto.keys.KeyType;
import org.cardanofoundation.metadatatools.core.cip26.model.KeyTextEnvelope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.assertj.core.api.Assertions.assertThat;

@Log4j2
@DisplayName("Metadata Validation Tests")
public class MetadataValidationTest {

    private final Path RESOURCE_DIRECTORY = Paths.get("src", "test", "resources");

    @Nested
    @DisplayName("Subject Validation")
    class SubjectValidationTests {

        @Nested
        @DisplayName("Positive Tests")
        class PositiveTests {

            @Test
            @DisplayName("Should accept valid subject with minimum length (56 chars)")
            void shouldAcceptValidSubjectWithMinimumLength() {
                final ValidationResult result = new ValidationResult();
                final String validSubject = "a".repeat(56);

                MetadataValidationRules.validateSubjectAndPolicy(validSubject, null, result);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }

            @Test
            @DisplayName("Should accept valid subject with maximum length (120 chars)")
            void shouldAcceptValidSubjectWithMaximumLength() {
                final ValidationResult result = new ValidationResult();
                final String validSubject = "a".repeat(120);

                MetadataValidationRules.validateSubjectAndPolicy(validSubject, null, result);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }

            @Test
            @DisplayName("Should accept valid subject with policy ID and asset name")
            void shouldAcceptValidSubjectWithPolicyAndAsset() {
                final ValidationResult result = new ValidationResult();
                final String policyId = "6ad121cd218e513bdb8ad67afc04d188f859b25d258a694c38269941";
                final String assetName = Hex.toHexString("myasset".getBytes(StandardCharsets.UTF_8));
                final String validSubject = policyId + assetName;

                MetadataValidationRules.validateSubjectAndPolicy(validSubject, null, result);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }
        }

        @Nested
        @DisplayName("Negative Tests")
        class NegativeTests {

            @Test
            @DisplayName("Should reject null subject")
            void shouldRejectNullSubject() {
                final ValidationResult result = new ValidationResult();

                MetadataValidationRules.validateSubjectAndPolicy(null, null, result);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).hasSize(1);
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("Missing, empty or blank subject");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.SUBJECT);
            }

            @Test
            @DisplayName("Should reject empty subject")
            void shouldRejectEmptySubject() {
                final ValidationResult result = new ValidationResult();

                MetadataValidationRules.validateSubjectAndPolicy("", null, result);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).hasSize(1);
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("Missing, empty or blank subject");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.SUBJECT);
            }

            @Test
            @DisplayName("Should reject blank subject")
            void shouldRejectBlankSubject() {
                final ValidationResult result = new ValidationResult();

                MetadataValidationRules.validateSubjectAndPolicy("   ", null, result);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).hasSize(1);
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("Missing, empty or blank subject");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.SUBJECT);
            }

            @Test
            @DisplayName("Should reject subject shorter than 56 characters")
            void shouldRejectSubjectShorterThanMinimum() {
                final ValidationResult result = new ValidationResult();
                final String shortSubject = "a".repeat(54);

                MetadataValidationRules.validateSubjectAndPolicy(shortSubject, null, result);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("Subject must be at least 56 characters long");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.SUBJECT);
            }

            @Test
            @DisplayName("Should reject subject longer than 120 characters")
            void shouldRejectSubjectLongerThanMaximum() {
                final ValidationResult result = new ValidationResult();
                final String longSubject = "a".repeat(122);

                MetadataValidationRules.validateSubjectAndPolicy(longSubject, null, result);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("Subject must not exceed 120 characters");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.SUBJECT);
            }

            @Test
            @DisplayName("Should reject subject with odd length")
            void shouldRejectSubjectWithOddLength() {
                final ValidationResult result = new ValidationResult();
                final String oddLengthSubject = "a".repeat(57);

                MetadataValidationRules.validateSubjectAndPolicy(oddLengthSubject, null, result);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).containsAnyOf(
                    "Number of characters in the subject must be even",
                    "Cannot decode hex string representation of subject hash"
                );
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.SUBJECT);
            }

            @Test
            @DisplayName("Should reject subject with invalid hex characters")
            void shouldRejectSubjectWithInvalidHex() {
                final ValidationResult result = new ValidationResult();
                final String invalidHexSubject = "g".repeat(56);

                MetadataValidationRules.validateSubjectAndPolicy(invalidHexSubject, null, result);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("Cannot decode hex string representation of subject hash");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.SUBJECT);
            }
        }
    }

    @Nested
    @DisplayName("Name Property Validation")
    class NamePropertyValidationTests {

        @Nested
        @DisplayName("Positive Tests")
        class PositiveTests {

            @Test
            @DisplayName("Should accept valid name with single character")
            void shouldAcceptValidNameWithSingleCharacter() {
                final MetadataProperty<String> property = new MetadataProperty<>("A", 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.NAME, property);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }

            @Test
            @DisplayName("Should accept valid name at maximum length (50 chars)")
            void shouldAcceptValidNameAtMaximumLength() {
                final MetadataProperty<String> property = new MetadataProperty<>("A".repeat(50), 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.NAME, property);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }

            @Test
            @DisplayName("Should accept valid name with special characters")
            void shouldAcceptValidNameWithSpecialCharacters() {
                final MetadataProperty<String> property = new MetadataProperty<>("Test Token™ 2024!", 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.NAME, property);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }
        }

        @Nested
        @DisplayName("Negative Tests")
        class NegativeTests {

            @Test
            @DisplayName("Should reject name exceeding maximum length")
            void shouldRejectNameExceedingMaximumLength() {
                final MetadataProperty<String> property = new MetadataProperty<>("A".repeat(51), 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.NAME, property);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("only 50 characters allow but got 51");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.NAME);
            }

            @Test
            @DisplayName("Should reject null name value")
            void shouldRejectNullNameValue() {
                final MetadataProperty<String> property = new MetadataProperty<>(null, 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.NAME, property);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("value is undefined");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.NAME);
            }

            @Test
            @DisplayName("Should reject name with invalid type")
            void shouldRejectNameWithInvalidType() {
                final MetadataProperty<Integer> property = new MetadataProperty<>(123, 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.NAME, property);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("value is not of expected type String");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.NAME);
            }

            @Test
            @DisplayName("Should reject name with null sequence number")
            void shouldRejectNameWithNullSequenceNumber() {
                final MetadataProperty<String> property = new MetadataProperty<>("Valid Name", null, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.NAME, property);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("sequenceNumber is undefined");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.SEQUENCE_NUMBER);
            }

            @Test
            @DisplayName("Should reject name with negative sequence number")
            void shouldRejectNameWithNegativeSequenceNumber() {
                final MetadataProperty<String> property = new MetadataProperty<>("Valid Name", -1, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.NAME, property);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("sequenceNumber is negative");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.SEQUENCE_NUMBER);
            }
        }
    }

    @Nested
    @DisplayName("Description Property Validation")
    class DescriptionPropertyValidationTests {

        @Nested
        @DisplayName("Positive Tests")
        class PositiveTests {

            @Test
            @DisplayName("Should accept valid description at maximum length (500 chars)")
            void shouldAcceptValidDescriptionAtMaximumLength() {
                final MetadataProperty<String> property = new MetadataProperty<>("A".repeat(500), 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.DESCRIPTION, property);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }

            @Test
            @DisplayName("Should accept valid description with multiline text")
            void shouldAcceptValidDescriptionWithMultilineText() {
                final String multilineDescription = "This is a test token.\nIt has multiple lines.\nAnd it's perfectly valid.";
                final MetadataProperty<String> property = new MetadataProperty<>(multilineDescription, 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.DESCRIPTION, property);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }
        }

        @Nested
        @DisplayName("Negative Tests")
        class NegativeTests {

            @Test
            @DisplayName("Should reject description exceeding maximum length")
            void shouldRejectDescriptionExceedingMaximumLength() {
                final MetadataProperty<String> property = new MetadataProperty<>("A".repeat(501), 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.DESCRIPTION, property);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("only 500 characters allow but got 501");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.DESCRIPTION);
            }

            @Test
            @DisplayName("Should reject null description value")
            void shouldRejectNullDescriptionValue() {
                final MetadataProperty<String> property = new MetadataProperty<>(null, 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.DESCRIPTION, property);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("value is undefined");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.DESCRIPTION);
            }

            @Test
            @DisplayName("Should reject description with invalid type")
            void shouldRejectDescriptionWithInvalidType() {
                final MetadataProperty<Integer> property = new MetadataProperty<>(123, 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.DESCRIPTION, property);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("value is not of expected type String");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.DESCRIPTION);
            }
        }
    }

    @Nested
    @DisplayName("Ticker Property Validation")
    class TickerPropertyValidationTests {

        @Nested
        @DisplayName("Positive Tests")
        class PositiveTests {

            @Test
            @DisplayName("Should accept valid ticker at minimum length (2 chars)")
            void shouldAcceptValidTickerAtMinimumLength() {
                final MetadataProperty<String> property = new MetadataProperty<>("AB", 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.TICKER, property);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }

            @Test
            @DisplayName("Should accept valid ticker at maximum length (9 chars)")
            void shouldAcceptValidTickerAtMaximumLength() {
                final MetadataProperty<String> property = new MetadataProperty<>("ABCDEFGHI", 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.TICKER, property);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }
        }

        @Nested
        @DisplayName("Negative Tests")
        class NegativeTests {

            @Test
            @DisplayName("Should reject ticker shorter than minimum length")
            void shouldRejectTickerShorterThanMinimum() {
                final MetadataProperty<String> property = new MetadataProperty<>("A", 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.TICKER, property);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("ticker length is 1 which is not in the allowed interval of [2, 9]");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.TICKER);
            }

            @Test
            @DisplayName("Should reject ticker longer than maximum length")
            void shouldRejectTickerLongerThanMaximum() {
                final MetadataProperty<String> property = new MetadataProperty<>("ABCDEFGHIJ", 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.TICKER, property);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("ticker length is 10 which is not in the allowed interval of [2, 9]");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.TICKER);
            }
        }
    }

    @Nested
    @DisplayName("Decimals Property Validation")
    class DecimalsPropertyValidationTests {

        @Nested
        @DisplayName("Positive Tests")
        class PositiveTests {

            @Test
            @DisplayName("Should accept decimals with zero value")
            void shouldAcceptDecimalsWithZeroValue() {
                final MetadataProperty<Integer> property = new MetadataProperty<>(0, 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.DECIMALS, property);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }

            @Test
            @DisplayName("Should accept decimals with positive value")
            void shouldAcceptDecimalsWithPositiveValue() {
                final MetadataProperty<Integer> property = new MetadataProperty<>(6, 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.DECIMALS, property);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }
        }

        @Nested
        @DisplayName("Negative Tests")
        class NegativeTests {

            @Test
            @DisplayName("Should reject decimals with negative value")
            void shouldRejectDecimalsWithNegativeValue() {
                final MetadataProperty<Integer> property = new MetadataProperty<>(-1, 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.DECIMALS, property);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("value -1 is not in the expected range of [0:)");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.DECIMALS);
            }

            @Test
            @DisplayName("Should reject decimals with invalid type")
            void shouldRejectDecimalsWithInvalidType() {
                final MetadataProperty<String> property = new MetadataProperty<>("6", 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.DECIMALS, property);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("value is not of expected type Integer");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.DECIMALS);
            }
        }
    }

    @Nested
    @DisplayName("Logo Property Validation")
    class LogoPropertyValidationTests {

        @Nested
        @DisplayName("Positive Tests")
        class PositiveTests {

            @Test
            @DisplayName("Should accept valid logo URL")
            void shouldAcceptValidLogoUrl() {
                final MetadataProperty<String> property = new MetadataProperty<>("https://example.com/logo.png", 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.LOGO, property);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }

            @Test
            @DisplayName("Should accept logo with data URI")
            void shouldAcceptLogoWithDataUri() {
                final String dataUri = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
                final MetadataProperty<String> property = new MetadataProperty<>(dataUri, 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.LOGO, property);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }

            @Test
            @DisplayName("Should accept logo at maximum length (87400 chars)")
            void shouldAcceptLogoAtMaximumLength() {
                final MetadataProperty<String> property = new MetadataProperty<>("A".repeat(87400), 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.LOGO, property);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }

            @Test
            @DisplayName("Should accept logo with long data URI")
            void shouldAcceptLogoWithLongDataUri() {
                final String longDataUri = "data:image/png;base64," + "A".repeat(87300);
                final MetadataProperty<String> property = new MetadataProperty<>(longDataUri, 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.LOGO, property);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }
        }

        @Nested
        @DisplayName("Negative Tests")
        class NegativeTests {

            @Test
            @DisplayName("Should reject null logo value")
            void shouldRejectNullLogoValue() {
                final MetadataProperty<String> property = new MetadataProperty<>(null, 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.LOGO, property);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("value is undefined");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.LOGO);
            }

            @Test
            @DisplayName("Should reject logo exceeding maximum length")
            void shouldRejectLogoExceedingMaximumLength() {
                final MetadataProperty<String> property = new MetadataProperty<>("A".repeat(87401), 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.LOGO, property);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("only 87400 characters allow but got 87401");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.LOGO);
            }

            @Test
            @DisplayName("Should reject logo with invalid type")
            void shouldRejectLogoWithInvalidType() {
                final MetadataProperty<Integer> property = new MetadataProperty<>(123, 0, null);

                final ValidationResult result = MetadataValidationRules.validateProperty(ValidationField.LOGO, property);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("value is not of expected type String");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.LOGO);
            }
        }
    }

    @Nested
    @DisplayName("Required Properties Validation")
    class RequiredPropertiesValidationTests {

        @Nested
        @DisplayName("Positive Tests")
        class PositiveTests {

            @Test
            @DisplayName("Should accept metadata with all required properties")
            void shouldAcceptMetadataWithAllRequiredProperties() {
                final Metadata metadata = new Metadata();
                metadata.setSubject("a".repeat(56));
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 0, null));

                final ValidationResult result = new ValidationResult();
                MetadataValidationRules.validateHasRequiredProperties(metadata.getProperties().keySet(), result);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }

            @Test
            @DisplayName("Should accept metadata with required and optional properties")
            void shouldAcceptMetadataWithRequiredAndOptionalProperties() {
                final Metadata metadata = new Metadata();
                metadata.setSubject("a".repeat(56));
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 0, null));
                metadata.addProperty(ValidationField.TICKER, new MetadataProperty<>("TEST", 0, null));
                metadata.addProperty(ValidationField.LOGO, new MetadataProperty<>("https://example.com/logo.png", 0, null));

                final ValidationResult result = new ValidationResult();
                MetadataValidationRules.validateHasRequiredProperties(metadata.getProperties().keySet(), result);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }
        }

        @Nested
        @DisplayName("Negative Tests")
        class NegativeTests {

            @Test
            @DisplayName("Should reject metadata missing name property")
            void shouldRejectMetadataMissingName() {
                final Metadata metadata = new Metadata();
                metadata.setSubject("a".repeat(56));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 0, null));

                final ValidationResult result = new ValidationResult();
                MetadataValidationRules.validateHasRequiredProperties(metadata.getProperties().keySet(), result);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("Missing required properties");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.REQUIRED_PROPERTIES);
            }

            @Test
            @DisplayName("Should reject metadata missing description property")
            void shouldRejectMetadataMissingDescription() {
                final Metadata metadata = new Metadata();
                metadata.setSubject("a".repeat(56));
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));

                final ValidationResult result = new ValidationResult();
                MetadataValidationRules.validateHasRequiredProperties(metadata.getProperties().keySet(), result);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("Missing required properties");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.REQUIRED_PROPERTIES);
            }

            @Test
            @DisplayName("Should reject metadata missing all required properties")
            void shouldRejectMetadataMissingAllRequiredProperties() {
                final Metadata metadata = new Metadata();
                metadata.setSubject("a".repeat(56));

                final ValidationResult result = new ValidationResult();
                MetadataValidationRules.validateHasRequiredProperties(metadata.getProperties().keySet(), result);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("Missing required properties");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.REQUIRED_PROPERTIES);
            }
        }
    }

    @Nested
    @DisplayName("Metadata Creator Validation")
    class MetadataCreatorValidationTests {

        @Nested
        @DisplayName("Full Metadata Validation")
        class FullMetadataValidationTests {

            @Test
            @DisplayName("Should validate complete valid metadata without signatures")
            void shouldValidateCompleteValidMetadataWithoutSignatures() throws IOException {
                final ObjectMapper jsonMapper = new ObjectMapper();
                final String assetName = "TestToken";
                final PolicyScript policyScript = jsonMapper.readValue(RESOURCE_DIRECTORY.resolve("policy.script").toFile(), PolicyScript.class);
                final Metadata metadata = new Metadata(assetName, policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("A test token for validation", 0, null));
                metadata.addProperty(ValidationField.TICKER, new MetadataProperty<>("TEST", 0, null));
                metadata.addProperty(ValidationField.DECIMALS, new MetadataProperty<>(6, 0, null));
                metadata.addProperty(ValidationField.LOGO, new MetadataProperty<>("https://example.com/logo.png", 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }

            @Test
            @DisplayName("Should validate complete valid metadata with signatures")
            void shouldValidateCompleteValidMetadataWithSignatures() throws IOException {
                final ObjectMapper jsonMapper = new ObjectMapper();
                final String assetName = "TestToken";
                final KeyTextEnvelope signingEnvelope = jsonMapper.readValue(RESOURCE_DIRECTORY.resolve("policy.skey").toFile(), KeyTextEnvelope.class);
                final Key signingKey = Key.fromTextEnvelope(signingEnvelope, KeyType.POLICY_SIGNING_KEY_ED25519);
                final Key verificationKey = signingKey.generateVerificationKey();
                final PolicyScript policyScript = jsonMapper.readValue(RESOURCE_DIRECTORY.resolve("policy.script").toFile(), PolicyScript.class);
                final Metadata metadata = new Metadata(assetName, policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("A test token for validation", 0, null));
                metadata.addProperty(ValidationField.TICKER, new MetadataProperty<>("TEST", 0, null));
                metadata.addProperty(ValidationField.DECIMALS, new MetadataProperty<>(6, 0, null));

                MetadataCreator.signMetadata(metadata, signingKey);

                final ValidationResult result = MetadataCreator.validateMetadata(metadata, verificationKey);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }

            @Test
            @DisplayName("Should reject metadata with invalid subject")
            void shouldRejectMetadataWithInvalidSubject() {
                final Metadata metadata = new Metadata();
                metadata.setSubject("tooshort");
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
            }

            @Test
            @DisplayName("Should reject metadata with name exceeding max length")
            void shouldRejectMetadataWithNameExceedingMaxLength() {
                final Metadata metadata = new Metadata();
                metadata.setSubject("a".repeat(56));
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("A".repeat(51), 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("only 50 characters allow");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.NAME);
            }

            @Test
            @DisplayName("Should reject metadata with description exceeding max length")
            void shouldRejectMetadataWithDescriptionExceedingMaxLength() {
                final Metadata metadata = new Metadata();
                metadata.setSubject("a".repeat(56));
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("A".repeat(501), 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("only 500 characters allow");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.DESCRIPTION);
            }

            @Test
            @DisplayName("Should reject metadata missing required properties")
            void shouldRejectMetadataMissingRequiredProperties() {
                final Metadata metadata = new Metadata();
                metadata.setSubject("a".repeat(56));
                metadata.addProperty(ValidationField.TICKER, new MetadataProperty<>("TEST", 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("Missing required properties");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.REQUIRED_PROPERTIES);
            }

            @Test
            @DisplayName("Should reject metadata with invalid ticker length")
            void shouldRejectMetadataWithInvalidTickerLength() {
                final Metadata metadata = new Metadata();
                metadata.setSubject("a".repeat(56));
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 0, null));
                metadata.addProperty(ValidationField.TICKER, new MetadataProperty<>("A", 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("ticker length");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.TICKER);
            }

            @Test
            @DisplayName("Should reject metadata with negative decimals")
            void shouldRejectMetadataWithNegativeDecimals() {
                final Metadata metadata = new Metadata();
                metadata.setSubject("a".repeat(56));
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 0, null));
                metadata.addProperty(ValidationField.DECIMALS, new MetadataProperty<>(-1, 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("is not in the expected range");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.DECIMALS);
            }
        }

        @Nested
        @DisplayName("Metadata Update Validation")
        class MetadataUpdateValidationTests {

            @Test
            @DisplayName("Should accept valid metadata update with increased sequence number")
            void shouldAcceptValidMetadataUpdateWithIncreasedSequenceNumber() throws IOException {
                final ObjectMapper jsonMapper = new ObjectMapper();
                final String assetName = "TestToken";
                final KeyTextEnvelope signingEnvelope = jsonMapper.readValue(RESOURCE_DIRECTORY.resolve("policy.skey").toFile(), KeyTextEnvelope.class);
                final Key signingKey = Key.fromTextEnvelope(signingEnvelope, KeyType.POLICY_SIGNING_KEY_ED25519);
                final Key verificationKey = signingKey.generateVerificationKey();
                final PolicyScript policyScript = jsonMapper.readValue(RESOURCE_DIRECTORY.resolve("policy.script").toFile(), PolicyScript.class);

                final Metadata baseMetadata = new Metadata(assetName, policyScript);
                baseMetadata.addProperty("name", new MetadataProperty<>("Old Name", 0, null));
                baseMetadata.addProperty("description", new MetadataProperty<>("Old Description", 0, null));
                MetadataCreator.signMetadata(baseMetadata, signingKey);

                final Metadata updatedMetadata = new Metadata(assetName, policyScript);
                updatedMetadata.addProperty("name", new MetadataProperty<>("New Name", 1, null));
                updatedMetadata.addProperty("description", new MetadataProperty<>("New Description", 1, null));
                MetadataCreator.signMetadata(updatedMetadata, signingKey);

                final ValidationResult result = MetadataCreator.validateMetadataUpdate(updatedMetadata, verificationKey, baseMetadata);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }

            @Test
            @DisplayName("Should reject metadata update with same sequence number")
            void shouldRejectMetadataUpdateWithSameSequenceNumber() throws IOException {
                final ObjectMapper jsonMapper = new ObjectMapper();
                final String assetName = "TestToken";
                final KeyTextEnvelope signingEnvelope = jsonMapper.readValue(RESOURCE_DIRECTORY.resolve("policy.skey").toFile(), KeyTextEnvelope.class);
                final Key signingKey = Key.fromTextEnvelope(signingEnvelope, KeyType.POLICY_SIGNING_KEY_ED25519);
                final Key verificationKey = signingKey.generateVerificationKey();
                final PolicyScript policyScript = jsonMapper.readValue(RESOURCE_DIRECTORY.resolve("policy.script").toFile(), PolicyScript.class);

                final Metadata baseMetadata = new Metadata(assetName, policyScript);
                baseMetadata.addProperty("name", new MetadataProperty<>("Old Name", 0, null));
                baseMetadata.addProperty("description", new MetadataProperty<>("Old Description", 0, null));
                MetadataCreator.signMetadata(baseMetadata, signingKey);

                final Metadata updatedMetadata = new Metadata(assetName, policyScript);
                updatedMetadata.addProperty("name", new MetadataProperty<>("New Name", 0, null));
                updatedMetadata.addProperty("description", new MetadataProperty<>("New Description", 0, null));
                MetadataCreator.signMetadata(updatedMetadata, signingKey);

                final ValidationResult result = MetadataCreator.validateMetadataUpdate(updatedMetadata, verificationKey, baseMetadata);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().get(0).getMessage()).contains("Sequence number");
                assertThat(result.getValidationErrors().get(0).getField()).isEqualTo(ValidationField.SEQUENCE_NUMBER);
            }
        }
    }
}
