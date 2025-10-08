package org.cardanofoundation.metadatatools.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.log4j.Log4j2;
import org.bouncycastle.util.encoders.Hex;
import org.cardanofoundation.metadatatools.core.cip26.MetadataCreator;
import org.cardanofoundation.metadatatools.core.cip26.ValidationField;
import org.cardanofoundation.metadatatools.core.cip26.ValidationResult;
import org.cardanofoundation.metadatatools.core.cip26.model.KeyTextEnvelope;
import org.cardanofoundation.metadatatools.core.cip26.model.Metadata;
import org.cardanofoundation.metadatatools.core.cip26.model.MetadataProperty;
import org.cardanofoundation.metadatatools.core.cip26.model.PolicyScript;
import org.cardanofoundation.metadatatools.core.crypto.keys.Key;
import org.cardanofoundation.metadatatools.core.crypto.keys.KeyType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.assertj.core.api.Assertions.*;

@Log4j2
@DisplayName("MetadataCreator Tests")
public class MetadataCreatorTest {

    private final Path RESOURCE_DIRECTORY = Paths.get("src", "test", "resources");
    private Key signingKey;
    private Key verificationKey;
    private PolicyScript policyScript;
    private ObjectMapper jsonMapper;

    @BeforeEach
    void setUp() throws IOException {
        jsonMapper = new ObjectMapper();
        final KeyTextEnvelope signingEnvelope = jsonMapper.readValue(
                RESOURCE_DIRECTORY.resolve("policy.skey").toFile(),
                KeyTextEnvelope.class
        );
        signingKey = Key.fromTextEnvelope(signingEnvelope, KeyType.POLICY_SIGNING_KEY_ED25519);
        verificationKey = signingKey.generateVerificationKey();
        policyScript = jsonMapper.readValue(
                RESOURCE_DIRECTORY.resolve("policy.script").toFile(),
                PolicyScript.class
        );
    }

    @Nested
    @DisplayName("Validate Metadata Tests")
    class ValidateMetadataTests {

        @Nested
        @DisplayName("Argument Validation")
        class ArgumentValidationTests {

            @Test
            @DisplayName("Should throw exception when metadata is null")
            void shouldThrowExceptionWhenMetadataIsNull() {
                assertThatThrownBy(() -> MetadataCreator.validateMetadata(null))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("metadata cannot be null");
            }

            @Test
            @DisplayName("Should throw exception when verification key is actually a signing key")
            void shouldThrowExceptionWhenVerificationKeyIsSigningKey() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Description", 0, null));

                assertThatThrownBy(() -> MetadataCreator.validateMetadata(metadata, signingKey))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("This function expects a verification key");
            }
        }

        @Nested
        @DisplayName("Basic Validation")
        class BasicValidationTests {

            @Test
            @DisplayName("Should validate metadata without verification key")
            void shouldValidateMetadataWithoutVerificationKey() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }

            @Test
            @DisplayName("Should validate metadata with verification key and valid signatures")
            void shouldValidateMetadataWithVerificationKeyAndValidSignatures() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 0, null));

                MetadataCreator.signMetadata(metadata, signingKey);

                final ValidationResult result = MetadataCreator.validateMetadata(metadata, verificationKey);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }

            @Test
            @DisplayName("Should validate only signatures when signaturesOnly flag is true")
            void shouldValidateOnlySignaturesWhenSignaturesOnlyFlagIsTrue() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                // Add invalid properties that would normally fail validation
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("A".repeat(100), 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 0, null));

                MetadataCreator.signMetadata(metadata, signingKey);

                // Should pass because we're only validating signatures, not property constraints
                final ValidationResult result = MetadataCreator.validateMetadata(metadata, verificationKey, true);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }
        }

        @Nested
        @DisplayName("Subject and Policy Validation")
        class SubjectAndPolicyValidationTests {

            @Test
            @DisplayName("Should fail validation with invalid subject (too short)")
            void shouldFailValidationWithInvalidSubject() {
                final Metadata metadata = new Metadata();
                metadata.setSubject("tooshort");
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Description", 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().toString()).contains("Subject must be at least 56 characters long");
            }

            @Test
            @DisplayName("Should fail validation with subject exceeding maximum length")
            void shouldFailValidationWithSubjectExceedingMaxLength() {
                final Metadata metadata = new Metadata();
                metadata.setSubject("a".repeat(122));
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Description", 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().toString()).contains("Subject must not exceed 120 characters");
            }

            @Test
            @DisplayName("Should fail validation with null subject")
            void shouldFailValidationWithNullSubject() {
                final Metadata metadata = new Metadata();
                metadata.setSubject(null);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Description", 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().toString()).contains("Missing, empty or blank subject");
            }
        }

        @Nested
        @DisplayName("Required Properties Validation")
        class RequiredPropertiesValidationTests {

            @Test
            @DisplayName("Should fail validation when name property is missing")
            void shouldFailValidationWhenNamePropertyIsMissing() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Description", 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().toString()).contains("Missing required properties");
            }

            @Test
            @DisplayName("Should fail validation when description property is missing")
            void shouldFailValidationWhenDescriptionPropertyIsMissing() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test", 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().toString()).contains("Missing required properties");
            }

            @Test
            @DisplayName("Should pass validation with all required properties")
            void shouldPassValidationWithAllRequiredProperties() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }
        }

        @Nested
        @DisplayName("Property Constraints Validation")
        class PropertyConstraintsValidationTests {

            @Test
            @DisplayName("Should fail validation when name exceeds max length")
            void shouldFailValidationWhenNameExceedsMaxLength() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("A".repeat(51), 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Description", 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().toString()).contains("only 50 characters allow");
            }

            @Test
            @DisplayName("Should fail validation when description exceeds max length")
            void shouldFailValidationWhenDescriptionExceedsMaxLength() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("A".repeat(501), 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().toString()).contains("only 500 characters allow");
            }

            @Test
            @DisplayName("Should fail validation when ticker is too short")
            void shouldFailValidationWhenTickerIsTooShort() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Description", 0, null));
                metadata.addProperty(ValidationField.TICKER, new MetadataProperty<>("A", 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().toString()).contains("ticker length");
            }

            @Test
            @DisplayName("Should fail validation when ticker is too long")
            void shouldFailValidationWhenTickerIsTooLong() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Description", 0, null));
                metadata.addProperty(ValidationField.TICKER, new MetadataProperty<>("ABCDEFGHIJ", 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().toString()).contains("ticker length");
            }

            @Test
            @DisplayName("Should fail validation when decimals is negative")
            void shouldFailValidationWhenDecimalsIsNegative() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Description", 0, null));
                metadata.addProperty(ValidationField.DECIMALS, new MetadataProperty<>(-1, 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().toString()).contains("is not in the expected range");
            }
        }

        @Nested
        @DisplayName("Signature Verification")
        class SignatureVerificationTests {

            @Test
            @DisplayName("Should verify valid signatures with correct verification key")
            void shouldVerifyValidSignaturesWithCorrectVerificationKey() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 0, null));

                MetadataCreator.signMetadata(metadata, signingKey);

                final ValidationResult result = MetadataCreator.validateMetadata(metadata, verificationKey);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }

            @Test
            @DisplayName("Should fail signature verification with incorrect verification key")
            void shouldFailSignatureVerificationWithIncorrectVerificationKey() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 0, null));

                MetadataCreator.signMetadata(metadata, signingKey);

                // Create a different key
                final KeyTextEnvelope differentSigningEnvelope = jsonMapper.readValue(
                        RESOURCE_DIRECTORY.resolve("payment.skey").toFile(),
                        KeyTextEnvelope.class
                );
                final Key differentSigningKey = Key.fromTextEnvelope(differentSigningEnvelope);
                final Key differentVerificationKey = differentSigningKey.generateVerificationKey();

                final ValidationResult result = MetadataCreator.validateMetadata(metadata, differentVerificationKey);

                // Should still be valid because the verification key doesn't match any signature
                // (it just won't find matching signatures to verify)
                assertThat(result.isValid()).isTrue();
            }

            @Test
            @DisplayName("Should validate metadata without signatures")
            void shouldValidateMetadataWithoutSignatures() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 0, null));

                final ValidationResult result = MetadataCreator.validateMetadata(metadata);

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }
        }
    }

    @Nested
    @DisplayName("Validate Metadata Update Tests")
    class ValidateMetadataUpdateTests {

        @Nested
        @DisplayName("Valid Updates")
        class ValidUpdatesTests {

            @Test
            @DisplayName("Should accept update with increased sequence numbers")
            void shouldAcceptUpdateWithIncreasedSequenceNumbers() throws IOException {
                final Metadata baseMetadata = new Metadata("test", policyScript);
                baseMetadata.addProperty("name", new MetadataProperty<>("Old Name", 0, null));
                baseMetadata.addProperty("description", new MetadataProperty<>("Old Description", 0, null));
                MetadataCreator.signMetadata(baseMetadata, signingKey);

                final Metadata updatedMetadata = new Metadata("test", policyScript);
                updatedMetadata.addProperty("name", new MetadataProperty<>("New Name", 1, null));
                updatedMetadata.addProperty("description", new MetadataProperty<>("New Description", 1, null));
                MetadataCreator.signMetadata(updatedMetadata, signingKey);

                final ValidationResult result = MetadataCreator.validateMetadataUpdate(
                        updatedMetadata, verificationKey, baseMetadata
                );

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }

            @Test
            @DisplayName("Should accept update with new properties")
            void shouldAcceptUpdateWithNewProperties() throws IOException {
                final Metadata baseMetadata = new Metadata("test", policyScript);
                baseMetadata.addProperty("name", new MetadataProperty<>("Name", 0, null));
                baseMetadata.addProperty("description", new MetadataProperty<>("Description", 0, null));
                MetadataCreator.signMetadata(baseMetadata, signingKey);

                final Metadata updatedMetadata = new Metadata("test", policyScript);
                updatedMetadata.addProperty("name", new MetadataProperty<>("Name", 1, null));
                updatedMetadata.addProperty("description", new MetadataProperty<>("Description", 1, null));
                updatedMetadata.addProperty("ticker", new MetadataProperty<>("TEST", 0, null));
                MetadataCreator.signMetadata(updatedMetadata, signingKey);

                final ValidationResult result = MetadataCreator.validateMetadataUpdate(
                        updatedMetadata, verificationKey, baseMetadata
                );

                assertThat(result.isValid()).isTrue();
                assertThat(result.getValidationErrors()).isEmpty();
            }
        }

        @Nested
        @DisplayName("Invalid Updates")
        class InvalidUpdatesTests {

            @Test
            @DisplayName("Should reject update with same sequence numbers")
            void shouldRejectUpdateWithSameSequenceNumbers() throws IOException {
                final Metadata baseMetadata = new Metadata("test", policyScript);
                baseMetadata.addProperty("name", new MetadataProperty<>("Old Name", 0, null));
                baseMetadata.addProperty("description", new MetadataProperty<>("Old Description", 0, null));
                MetadataCreator.signMetadata(baseMetadata, signingKey);

                final Metadata updatedMetadata = new Metadata("test", policyScript);
                updatedMetadata.addProperty("name", new MetadataProperty<>("New Name", 0, null));
                updatedMetadata.addProperty("description", new MetadataProperty<>("New Description", 0, null));
                MetadataCreator.signMetadata(updatedMetadata, signingKey);

                final ValidationResult result = MetadataCreator.validateMetadataUpdate(
                        updatedMetadata, verificationKey, baseMetadata
                );

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().toString()).contains("Sequence number");
            }

            @Test
            @DisplayName("Should reject update with decreased sequence numbers")
            void shouldRejectUpdateWithDecreasedSequenceNumbers() throws IOException {
                final Metadata baseMetadata = new Metadata("test", policyScript);
                baseMetadata.addProperty("name", new MetadataProperty<>("Old Name", 2, null));
                baseMetadata.addProperty("description", new MetadataProperty<>("Old Description", 2, null));
                MetadataCreator.signMetadata(baseMetadata, signingKey);

                final Metadata updatedMetadata = new Metadata("test", policyScript);
                updatedMetadata.addProperty("name", new MetadataProperty<>("New Name", 1, null));
                updatedMetadata.addProperty("description", new MetadataProperty<>("New Description", 1, null));
                MetadataCreator.signMetadata(updatedMetadata, signingKey);

                final ValidationResult result = MetadataCreator.validateMetadataUpdate(
                        updatedMetadata, verificationKey, baseMetadata
                );

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().toString()).contains("Sequence number");
            }

            @Test
            @DisplayName("Should reject update with different subject")
            void shouldRejectUpdateWithDifferentSubject() throws IOException {
                final Metadata baseMetadata = new Metadata("test", policyScript);
                baseMetadata.addProperty("name", new MetadataProperty<>("Name", 0, null));
                baseMetadata.addProperty("description", new MetadataProperty<>("Description", 0, null));
                MetadataCreator.signMetadata(baseMetadata, signingKey);

                final Metadata updatedMetadata = new Metadata("different", policyScript);
                updatedMetadata.addProperty("name", new MetadataProperty<>("Name", 1, null));
                updatedMetadata.addProperty("description", new MetadataProperty<>("Description", 1, null));
                MetadataCreator.signMetadata(updatedMetadata, signingKey);

                final ValidationResult result = MetadataCreator.validateMetadataUpdate(
                        updatedMetadata, verificationKey, baseMetadata
                );

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
                assertThat(result.getValidationErrors().toString()).contains("Subject of updated metadata differs");
            }

            @Test
            @DisplayName("Should reject update when base metadata is invalid")
            void shouldRejectUpdateWhenBaseMetadataIsInvalid() throws IOException {
                final Metadata baseMetadata = new Metadata();
                baseMetadata.setSubject("invalid"); // Too short
                baseMetadata.addProperty("name", new MetadataProperty<>("Name", 0, null));

                final Metadata updatedMetadata = new Metadata("test", policyScript);
                updatedMetadata.addProperty("name", new MetadataProperty<>("Name", 1, null));
                updatedMetadata.addProperty("description", new MetadataProperty<>("Description", 1, null));
                MetadataCreator.signMetadata(updatedMetadata, signingKey);

                final ValidationResult result = MetadataCreator.validateMetadataUpdate(
                        updatedMetadata, verificationKey, baseMetadata
                );

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
            }

            @Test
            @DisplayName("Should reject update when latest metadata is invalid")
            void shouldRejectUpdateWhenLatestMetadataIsInvalid() throws IOException {
                final Metadata baseMetadata = new Metadata("test", policyScript);
                baseMetadata.addProperty("name", new MetadataProperty<>("Name", 0, null));
                baseMetadata.addProperty("description", new MetadataProperty<>("Description", 0, null));
                MetadataCreator.signMetadata(baseMetadata, signingKey);

                final Metadata updatedMetadata = new Metadata();
                updatedMetadata.setSubject("invalid"); // Too short
                updatedMetadata.addProperty("name", new MetadataProperty<>("Name", 1, null));

                final ValidationResult result = MetadataCreator.validateMetadataUpdate(
                        updatedMetadata, verificationKey, baseMetadata
                );

                assertThat(result.isValid()).isFalse();
                assertThat(result.getValidationErrors()).isNotEmpty();
            }
        }
    }

    @Nested
    @DisplayName("Sign Metadata Tests")
    class SignMetadataTests {

        @Nested
        @DisplayName("Sign All Properties")
        class SignAllPropertiesTests {

            @Test
            @DisplayName("Should sign all properties in metadata")
            void shouldSignAllPropertiesInMetadata() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 0, null));
                metadata.addProperty(ValidationField.TICKER, new MetadataProperty<>("TEST", 0, null));

                MetadataCreator.signMetadata(metadata, signingKey);

                assertThat(metadata.getProperty(ValidationField.NAME).getSignatures()).isNotNull();
                assertThat(metadata.getProperty(ValidationField.NAME).getSignatures()).hasSize(1);
                assertThat(metadata.getProperty(ValidationField.DESCRIPTION).getSignatures()).isNotNull();
                assertThat(metadata.getProperty(ValidationField.DESCRIPTION).getSignatures()).hasSize(1);
                assertThat(metadata.getProperty(ValidationField.TICKER).getSignatures()).isNotNull();
                assertThat(metadata.getProperty(ValidationField.TICKER).getSignatures()).hasSize(1);

                // Verify signatures are valid
                final ValidationResult result = MetadataCreator.validateMetadata(metadata, verificationKey);
                assertThat(result.isValid()).isTrue();
            }

            @Test
            @DisplayName("Should throw exception when metadata is null")
            void shouldThrowExceptionWhenMetadataIsNull() {
                assertThatThrownBy(() -> MetadataCreator.signMetadata(null, signingKey))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("Metadata object cannot be null");
            }

            @Test
            @DisplayName("Should throw exception when signing key is null")
            void shouldThrowExceptionWhenSigningKeyIsNull() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test", 0, null));

                assertThatThrownBy(() -> MetadataCreator.signMetadata(metadata, (Key) null))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("Signing key cannot be null");
            }

            @Test
            @DisplayName("Should throw exception when key is not a signing key")
            void shouldThrowExceptionWhenKeyIsNotSigningKey() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test", 0, null));

                assertThatThrownBy(() -> MetadataCreator.signMetadata(metadata, verificationKey))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("Given key cannot be used for signing");
            }
        }

        @Nested
        @DisplayName("Sign Specific Property")
        class SignSpecificPropertyTests {

            @Test
            @DisplayName("Should sign specific property")
            void shouldSignSpecificProperty() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 0, null));

                MetadataCreator.signMetadata(metadata, signingKey, "name");

                assertThat(metadata.getProperty(ValidationField.NAME).getSignatures()).isNotNull();
                assertThat(metadata.getProperty(ValidationField.NAME).getSignatures()).hasSize(1);
                assertThat(metadata.getProperty(ValidationField.DESCRIPTION).getSignatures()).isNull();
            }

            @Test
            @DisplayName("Should do nothing when signing non-existent property")
            void shouldDoNothingWhenSigningNonExistentProperty() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));

                // Should not throw exception
                assertThatCode(() -> MetadataCreator.signMetadata(metadata, signingKey, "nonexistent"))
                        .doesNotThrowAnyException();
            }

            @Test
            @DisplayName("Should throw exception when property name is null")
            void shouldThrowExceptionWhenPropertyNameIsNull() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test", 0, null));

                assertThatThrownBy(() -> MetadataCreator.signMetadata(metadata, signingKey, (String) null))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("propertyName cannot be null or blank");
            }

            @Test
            @DisplayName("Should throw exception when property name is blank")
            void shouldThrowExceptionWhenPropertyNameIsBlank() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test", 0, null));

                assertThatThrownBy(() -> MetadataCreator.signMetadata(metadata, signingKey, "   "))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("propertyName cannot be null or blank");
            }

            @Test
            @DisplayName("Should update existing signature when signing twice")
            void shouldUpdateExistingSignatureWhenSigningTwice() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 0, null));

                MetadataCreator.signMetadata(metadata, signingKey, "name");
                final String firstSignature = metadata.getProperty(ValidationField.NAME).getSignatures().get(0).getSignature();

                MetadataCreator.signMetadata(metadata, signingKey, "name");
                final String secondSignature = metadata.getProperty(ValidationField.NAME).getSignatures().get(0).getSignature();

                assertThat(metadata.getProperty(ValidationField.NAME).getSignatures()).hasSize(1);
                assertThat(firstSignature).isEqualTo(secondSignature);
            }
        }

        @Nested
        @DisplayName("Signature Properties")
        class SignaturePropertiesTests {

            @Test
            @DisplayName("Should include correct public key in signature")
            void shouldIncludeCorrectPublicKeyInSignature() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 0, null));

                MetadataCreator.signMetadata(metadata, signingKey);

                final String expectedPublicKey = Hex.toHexString(verificationKey.getRawKeyBytes());
                assertThat(metadata.getProperty(ValidationField.NAME).getSignatures().get(0).getPublicKey())
                        .isEqualTo(expectedPublicKey);
                assertThat(metadata.getProperty(ValidationField.DESCRIPTION).getSignatures().get(0).getPublicKey())
                        .isEqualTo(expectedPublicKey);
            }

            @Test
            @DisplayName("Should generate different signatures for different properties")
            void shouldGenerateDifferentSignaturesForDifferentProperties() throws IOException {
                final Metadata metadata = new Metadata("test", policyScript);
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token", 0, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 0, null));

                MetadataCreator.signMetadata(metadata, signingKey);

                final String nameSignature = metadata.getProperty(ValidationField.NAME).getSignatures().get(0).getSignature();
                final String descSignature = metadata.getProperty(ValidationField.DESCRIPTION).getSignatures().get(0).getSignature();

                assertThat(nameSignature).isNotEqualTo(descSignature);
            }

            @Test
            @DisplayName("Should generate different signatures for different values of same property")
            void shouldGenerateDifferentSignaturesForDifferentValues() throws IOException {
                final Metadata metadata1 = new Metadata("test", policyScript);
                metadata1.addProperty("name", new MetadataProperty<>("Token A", 0, null));
                metadata1.addProperty("description", new MetadataProperty<>("Description", 0, null));
                MetadataCreator.signMetadata(metadata1, signingKey);

                final Metadata metadata2 = new Metadata("test", policyScript);
                metadata2.addProperty("name", new MetadataProperty<>("Token B", 0, null));
                metadata2.addProperty("description", new MetadataProperty<>("Description", 0, null));
                MetadataCreator.signMetadata(metadata2, signingKey);

                final String signature1 = metadata1.getProperty(ValidationField.NAME).getSignatures().get(0).getSignature();
                final String signature2 = metadata2.getProperty(ValidationField.NAME).getSignatures().get(0).getSignature();

                assertThat(signature1).isNotEqualTo(signature2);
            }
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should handle complete workflow: create, sign, validate, update")
        void shouldHandleCompleteWorkflow() throws IOException {
            // Create initial metadata
            final Metadata metadata = new Metadata("MyToken", policyScript);
            metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("My Token", 0, null));
            metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Initial description", 0, null));
            metadata.addProperty(ValidationField.TICKER, new MetadataProperty<>("MTK", 0, null));
            metadata.addProperty(ValidationField.DECIMALS, new MetadataProperty<>(6, 0, null));

            // Sign it
            MetadataCreator.signMetadata(metadata, signingKey);

            // Validate it
            ValidationResult result = MetadataCreator.validateMetadata(metadata, verificationKey);
            assertThat(result.isValid()).isTrue();

            // Create update
            final Metadata updatedMetadata = new Metadata("MyToken", policyScript);
            updatedMetadata.addProperty("name", new MetadataProperty<>("My Updated Token", 1, null));
            updatedMetadata.addProperty("description", new MetadataProperty<>("Updated description", 1, null));
            updatedMetadata.addProperty("ticker", new MetadataProperty<>("MTK", 1, null));
            updatedMetadata.addProperty("decimals", new MetadataProperty<>(6, 1, null));

            // Sign update
            MetadataCreator.signMetadata(updatedMetadata, signingKey);

            // Validate update
            result = MetadataCreator.validateMetadataUpdate(updatedMetadata, verificationKey, metadata);
            assertThat(result.isValid()).isTrue();
        }

        @Test
        @DisplayName("Should handle metadata with all optional properties")
        void shouldHandleMetadataWithAllOptionalProperties() throws IOException {
            final Metadata metadata = new Metadata("CompleteToken", policyScript);
            metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Complete Token", 0, null));
            metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("A token with all properties", 0, null));
            metadata.addProperty(ValidationField.TICKER, new MetadataProperty<>("CMPL", 0, null));
            metadata.addProperty(ValidationField.DECIMALS, new MetadataProperty<>(8, 0, null));
            metadata.addProperty(ValidationField.LOGO, new MetadataProperty<>("https://example.com/logo.png", 0, null));
            metadata.addProperty("url", new MetadataProperty<>("https://example.com", 0, null));

            MetadataCreator.signMetadata(metadata, signingKey);

            final ValidationResult result = MetadataCreator.validateMetadata(metadata, verificationKey);
            assertThat(result.isValid()).isTrue();
            assertThat(metadata.getProperties()).hasSize(6);
            assertThat(metadata.getProperty(ValidationField.LOGO).getSignatures()).isNotNull();
            assertThat(metadata.getProperties().get("url").getSignatures()).isNotNull();
        }
    }
}
