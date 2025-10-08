package org.cardanofoundation.metadatatools.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.util.encoders.Hex;
import org.cardanofoundation.metadatatools.core.cip26.ValidationField;
import org.cardanofoundation.metadatatools.core.cip26.model.Metadata;
import org.cardanofoundation.metadatatools.core.cip26.model.MetadataProperty;
import org.cardanofoundation.metadatatools.core.cip26.model.PolicyScript;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;

@DisplayName("Metadata Model Tests")
class MetadataModelTest {

    private static final String ASSET_NAME = "TestToken";
    private static final String POLICY_ID = "fb864e59bf8620349c3ebe29af5ad0f9ca2e319d39e115eb93aa58a4";

    private String loadResourceAsString(final String resourcePath) throws IOException {
        try (final InputStream is = getClass().getClassLoader().getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new IOException("Resource not found: " + resourcePath);
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create metadata with no-arg constructor")
        void shouldCreateMetadataWithNoArgConstructor() {
            final Metadata metadata = new Metadata();

            assertThat(metadata).isNotNull();
            assertThat(metadata.getSubject()).isNull();
            assertThat(metadata.getPolicy()).isNull();
            assertThat(metadata.getProperties()).isNotNull().isEmpty();
        }

        @Test
        @DisplayName("Should create metadata with asset name only")
        void shouldCreateMetadataWithAssetNameOnly() throws IOException {
            final Metadata metadata = new Metadata(ASSET_NAME);

            assertThat(metadata).isNotNull();
            assertThat(metadata.getSubject()).isEqualTo(Hex.toHexString(ASSET_NAME.getBytes(StandardCharsets.UTF_8)));
            assertThat(metadata.getPolicy()).isNull();
            assertThat(metadata.getProperties()).isNotNull().isEmpty();
        }

        @Test
        @DisplayName("Should create metadata with asset name and null policy script")
        void shouldCreateMetadataWithAssetNameAndNullPolicyScript() throws IOException {
            final Metadata metadata = new Metadata(ASSET_NAME, null);

            assertThat(metadata).isNotNull();
            assertThat(metadata.getSubject()).isEqualTo(Hex.toHexString(ASSET_NAME.getBytes(StandardCharsets.UTF_8)));
            assertThat(metadata.getPolicy()).isNull();
            assertThat(metadata.getProperties()).isNotNull().isEmpty();
        }

        @Test
        @DisplayName("Should create metadata with asset name and policy script")
        void shouldCreateMetadataWithAssetNameAndPolicyScript() throws IOException {
            // Load policy script from resource instead of constructing with private enum
            final String scriptContent = loadResourceAsString("policy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            final Metadata metadata = new Metadata(ASSET_NAME, policyScript);

            assertThat(metadata).isNotNull();
            assertThat(metadata.getSubject()).isNotNull();
            assertThat(metadata.getSubject()).startsWith(policyScript.computePolicyId());
            assertThat(metadata.getSubject()).endsWith(Hex.toHexString(ASSET_NAME.getBytes(StandardCharsets.UTF_8)));
            assertThat(metadata.getPolicy()).isNotNull();
            assertThat(metadata.getProperties()).isNotNull().isEmpty();
        }

        @Test
        @DisplayName("Should create metadata with asset name, policy script, and properties")
        void shouldCreateMetadataWithAssetNamePolicyScriptAndProperties() throws IOException {
            // Load policy script from resource instead of constructing with private enum
            final String scriptContent = loadResourceAsString("policy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            final Map<String, MetadataProperty<?>> properties = new HashMap<>();
            properties.put("name", new MetadataProperty<>("TestToken", 1, null));
            properties.put("description", new MetadataProperty<>("Test Description", 1, null));

            final Metadata metadata = new Metadata(ASSET_NAME, policyScript, properties);

            assertThat(metadata).isNotNull();
            assertThat(metadata.getSubject()).isNotNull();
            assertThat(metadata.getProperties()).hasSize(2);
            assertThat(metadata.getProperties()).containsKeys("name", "description");
        }

        @Test
        @DisplayName("Should create immutable copy of properties in constructor")
        void shouldCreateImmutableCopyOfPropertiesInConstructor() throws IOException {
            final Map<String, MetadataProperty<?>> properties = new HashMap<>();
            properties.put("name", new MetadataProperty<>("TestToken", 1, null));

            final Metadata metadata = new Metadata(ASSET_NAME, null, properties);

            // Modify original map should not affect metadata
            properties.put("description", new MetadataProperty<>("New Description", 1, null));

            assertThat(metadata.getProperties()).hasSize(1);
            assertThat(metadata.getProperties()).containsOnlyKeys("name");
        }
    }

    @Nested
    @DisplayName("Init Method Tests")
    class InitMethodTests {

        @Test
        @DisplayName("Should initialize metadata with asset name only")
        void shouldInitializeWithAssetNameOnly() throws IOException {
            final Metadata metadata = new Metadata();
            metadata.init(ASSET_NAME);

            assertThat(metadata.getSubject()).isEqualTo(Hex.toHexString(ASSET_NAME.getBytes(StandardCharsets.UTF_8)));
            assertThat(metadata.getPolicy()).isNull();
        }

        @Test
        @DisplayName("Should initialize metadata with asset name and null policy script")
        void shouldInitializeWithAssetNameAndNullPolicyScript() throws IOException {
            final Metadata metadata = new Metadata();
            metadata.init(ASSET_NAME, null);

            assertThat(metadata.getSubject()).isEqualTo(Hex.toHexString(ASSET_NAME.getBytes(StandardCharsets.UTF_8)));
            assertThat(metadata.getPolicy()).isNull();
        }

        @Test
        @DisplayName("Should initialize metadata with asset name and policy script")
        void shouldInitializeWithAssetNameAndPolicyScript() throws IOException {
            // Load policy script from resource instead of constructing with private enum
            final String scriptContent = loadResourceAsString("policy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            final Metadata metadata = new Metadata();
            metadata.init(ASSET_NAME, policyScript);

            assertThat(metadata.getSubject()).isNotNull();
            assertThat(metadata.getSubject()).startsWith(policyScript.computePolicyId());
            assertThat(metadata.getSubject()).endsWith(Hex.toHexString(ASSET_NAME.getBytes(StandardCharsets.UTF_8)));
            assertThat(metadata.getPolicy()).isEqualTo(Hex.toHexString(policyScript.toCbor()));
        }

        @Test
        @DisplayName("Should reinitialize metadata and update subject")
        void shouldReinitializeMetadataAndUpdateSubject() throws IOException {
            final Metadata metadata = new Metadata(ASSET_NAME);
            final String firstSubject = metadata.getSubject();

            final String newAssetName = "NewToken";
            metadata.init(newAssetName);

            assertThat(metadata.getSubject()).isNotEqualTo(firstSubject);
            assertThat(metadata.getSubject()).isEqualTo(Hex.toHexString(newAssetName.getBytes(StandardCharsets.UTF_8)));
        }
    }

    @Nested
    @DisplayName("Subject Setting Method Tests")
    class SubjectSettingMethodTests {

        @Test
        @DisplayName("Should set subject from asset name only")
        void shouldSetSubjectFromAssetNameOnly() {
            final Metadata metadata = new Metadata();
            metadata.setSubjectFromAssetName(ASSET_NAME);

            assertThat(metadata.getSubject()).isEqualTo(Hex.toHexString(ASSET_NAME.getBytes(StandardCharsets.UTF_8)));
        }

        @Test
        @DisplayName("Should set subject from asset name and policy id")
        void shouldSetSubjectFromAssetNameAndPolicyId() {
            final Metadata metadata = new Metadata();
            metadata.setSubjectFromAssetNameAndPolicyId(ASSET_NAME, POLICY_ID);

            assertThat(metadata.getSubject()).isEqualTo(POLICY_ID + Hex.toHexString(ASSET_NAME.getBytes(StandardCharsets.UTF_8)));
        }

        @Test
        @DisplayName("Should overwrite existing subject")
        void shouldOverwriteExistingSubject() throws IOException {
            final Metadata metadata = new Metadata(ASSET_NAME);
            final String firstSubject = metadata.getSubject();

            metadata.setSubjectFromAssetNameAndPolicyId(ASSET_NAME, POLICY_ID);

            assertThat(metadata.getSubject()).isNotEqualTo(firstSubject);
            assertThat(metadata.getSubject()).startsWith(POLICY_ID);
        }
    }

    @Nested
    @DisplayName("Property Management Tests")
    class PropertyManagementTests {

        @Nested
        @DisplayName("Add Property Tests")
        class AddPropertyTests {

            @Test
            @DisplayName("Should add property successfully")
            void shouldAddPropertySuccessfully() {
                final Metadata metadata = new Metadata();
                final MetadataProperty<String> property = new MetadataProperty<>("TestToken", 1, null);

                metadata.addProperty("name", property);

                assertThat(metadata.getProperties()).hasSize(1);
                assertThat(metadata.getProperties()).containsKey("name");
                assertThat(metadata.getProperty(ValidationField.NAME)).isEqualTo(property);
            }

            @Test
            @DisplayName("Should add multiple properties")
            void shouldAddMultipleProperties() {
                final Metadata metadata = new Metadata();
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("TestToken", 1, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 1, null));
                metadata.addProperty(ValidationField.TICKER, new MetadataProperty<>("TEST", 1, null));

                assertThat(metadata.getProperties()).hasSize(3);
                assertThat(metadata.getProperties()).containsKeys("name", "description", "ticker");
            }

            @Test
            @DisplayName("Should trim whitespace from property name")
            void shouldTrimWhitespaceFromPropertyName() {
                final Metadata metadata = new Metadata();
                metadata.addProperty("  name  ", new MetadataProperty<>("TestToken", 1, null));

                assertThat(metadata.getProperties()).containsKey("name");
                assertThat(metadata.getProperties()).doesNotContainKey("  name  ");
            }

            @Test
            @DisplayName("Should overwrite existing property with same name")
            void shouldOverwriteExistingPropertyWithSameName() {
                final Metadata metadata = new Metadata();
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("FirstName", 1, null));
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("SecondName", 2, null));

                assertThat(metadata.getProperties()).hasSize(1);
                assertThat(metadata.getProperty(ValidationField.NAME).getValue()).isEqualTo("SecondName");
                assertThat(metadata.getProperty(ValidationField.NAME).getSequenceNumber()).isEqualTo(2);
            }

            @Test
            @DisplayName("Should remove property when value is null")
            void shouldRemovePropertyWhenValueIsNull() {
                final Metadata metadata = new Metadata();
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("TestToken", 1, null));
                metadata.addProperty("name", null);

                assertThat(metadata.getProperties()).isEmpty();
            }

            @Test
            @DisplayName("Should throw exception when property name is null")
            void shouldThrowExceptionWhenPropertyNameIsNull() {
                final Metadata metadata = new Metadata();

                assertThatThrownBy(() -> metadata.addProperty((String) null, new MetadataProperty<>("TestToken", 1, null)))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("propertyName cannot be null");
            }

            @Test
            @DisplayName("Should throw exception when property name is empty string")
            void shouldThrowExceptionWhenPropertyNameIsEmptyString() {
                final Metadata metadata = new Metadata();

                assertThatThrownBy(() -> metadata.addProperty("", new MetadataProperty<>("TestToken", 1, null)))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("propertyName cannot be empty or blank");
            }

            @Test
            @DisplayName("Should throw exception when property name is only whitespace")
            void shouldThrowExceptionWhenPropertyNameIsOnlyWhitespace() {
                final Metadata metadata = new Metadata();

                assertThatThrownBy(() -> metadata.addProperty("   ", new MetadataProperty<>("TestToken", 1, null)))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("propertyName cannot be empty or blank");
            }
        }

        @Nested
        @DisplayName("Remove Property Tests")
        class RemovePropertyTests {

            @Test
            @DisplayName("Should remove existing property")
            void shouldRemoveExistingProperty() {
                final Metadata metadata = new Metadata();
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("TestToken", 1, null));
                metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Test Description", 1, null));

                metadata.removeProperty("name");

                assertThat(metadata.getProperties()).hasSize(1);
                assertThat(metadata.getProperties()).containsOnlyKeys("description");
            }

            @Test
            @DisplayName("Should do nothing when removing non-existent property")
            void shouldDoNothingWhenRemovingNonExistentProperty() {
                final Metadata metadata = new Metadata();
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("TestToken", 1, null));

                metadata.removeProperty("description");

                assertThat(metadata.getProperties()).hasSize(1);
                assertThat(metadata.getProperties()).containsOnlyKeys("name");
            }

            @Test
            @DisplayName("Should trim whitespace from property name before removal")
            void shouldTrimWhitespaceFromPropertyNameBeforeRemoval() {
                final Metadata metadata = new Metadata();
                metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("TestToken", 1, null));

                metadata.removeProperty("  name  ");

                assertThat(metadata.getProperties()).isEmpty();
            }

            @Test
            @DisplayName("Should throw exception when property name is null")
            void shouldThrowExceptionWhenPropertyNameIsNull() {
                final Metadata metadata = new Metadata();

                assertThatThrownBy(() -> metadata.removeProperty((String) null))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("propertyName cannot be null");
            }

            @Test
            @DisplayName("Should throw exception when property name is empty string")
            void shouldThrowExceptionWhenPropertyNameIsEmptyString() {
                final Metadata metadata = new Metadata();

                assertThatThrownBy(() -> metadata.removeProperty(""))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("propertyName cannot be empty or blank");
            }

            @Test
            @DisplayName("Should throw exception when property name is only whitespace")
            void shouldThrowExceptionWhenPropertyNameIsOnlyWhitespace() {
                final Metadata metadata = new Metadata();

                assertThatThrownBy(() -> metadata.removeProperty("   "))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("propertyName cannot be empty or blank");
            }
        }
    }

    @Nested
    @DisplayName("Property Name Sanitization Tests")
    class PropertyNameSanitizationTests {

        @Test
        @DisplayName("Should return same name when no whitespace")
        void shouldReturnSameNameWhenNoWhitespace() {
            final String sanitized = Metadata.sanitizePropertyName("name");

            assertThat(sanitized).isEqualTo("name");
        }

        @Test
        @DisplayName("Should trim leading whitespace")
        void shouldTrimLeadingWhitespace() {
            final String sanitized = Metadata.sanitizePropertyName("  name");

            assertThat(sanitized).isEqualTo("name");
        }

        @Test
        @DisplayName("Should trim trailing whitespace")
        void shouldTrimTrailingWhitespace() {
            final String sanitized = Metadata.sanitizePropertyName("name  ");

            assertThat(sanitized).isEqualTo("name");
        }

        @Test
        @DisplayName("Should trim both leading and trailing whitespace")
        void shouldTrimBothLeadingAndTrailingWhitespace() {
            final String sanitized = Metadata.sanitizePropertyName("  name  ");

            assertThat(sanitized).isEqualTo("name");
        }

        @Test
        @DisplayName("Should preserve internal whitespace")
        void shouldPreserveInternalWhitespace() {
            final String sanitized = Metadata.sanitizePropertyName("first name");

            assertThat(sanitized).isEqualTo("first name");
        }

        @Test
        @DisplayName("Should throw exception when property name is null")
        void shouldThrowExceptionWhenPropertyNameIsNull() {
            assertThatThrownBy(() -> Metadata.sanitizePropertyName(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("propertyName cannot be null");
        }

        @Test
        @DisplayName("Should return empty string when input is only whitespace")
        void shouldReturnEmptyStringWhenInputIsOnlyWhitespace() {
            final String sanitized = Metadata.sanitizePropertyName("   ");

            assertThat(sanitized).isEmpty();
        }
    }

    @Nested
    @DisplayName("Jackson Annotations Tests")
    class JacksonAnnotationsTests {

        @Test
        @DisplayName("Should set property using setRequiredProperties method")
        void shouldSetPropertyUsingSetRequiredPropertiesMethod() {
            final Metadata metadata = new Metadata();
            final MetadataProperty<String> property = new MetadataProperty<>("TestToken", 1, null);

            metadata.setRequiredProperties("name", property);

            assertThat(metadata.getProperties()).hasSize(1);
            assertThat(metadata.getProperties()).containsKey("name");
            assertThat(metadata.getProperty(ValidationField.NAME)).isEqualTo(property);
        }

        @Test
        @DisplayName("Should get properties using getProperties method")
        void shouldGetPropertiesUsingGetPropertiesMethod() {
            final Metadata metadata = new Metadata();
            metadata.addProperty("name", new MetadataProperty<>("TestToken", 1, null));
            metadata.addProperty("description", new MetadataProperty<>("Test Description", 1, null));

            final Map<String, MetadataProperty<?>> properties = metadata.getProperties();

            assertThat(properties).hasSize(2);
            assertThat(properties).containsKeys("name", "description");
        }
    }

    @Nested
    @DisplayName("Edge Cases and Special Scenarios")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle unicode characters in asset name")
        void shouldHandleUnicodeCharactersInAssetName() throws IOException {
            final String unicodeAssetName = "Token🚀";
            final Metadata metadata = new Metadata(unicodeAssetName);

            assertThat(metadata.getSubject()).isEqualTo(Hex.toHexString(unicodeAssetName.getBytes(StandardCharsets.UTF_8)));
        }

        @Test
        @DisplayName("Should handle empty asset name")
        void shouldHandleEmptyAssetName() throws IOException {
            final String emptyAssetName = "";
            final Metadata metadata = new Metadata(emptyAssetName);

            assertThat(metadata.getSubject()).isEmpty();
        }

        @Test
        @DisplayName("Should handle very long asset name")
        void shouldHandleVeryLongAssetName() throws IOException {
            // Max asset name is 32 bytes, create exactly 32 bytes
            final String longAssetName = "a".repeat(32);
            final Metadata metadata = new Metadata(longAssetName);

            assertThat(metadata.getSubject()).hasSize(64); // 32 bytes = 64 hex characters
        }

        @Test
        @DisplayName("Should handle property replacement and removal in sequence")
        void shouldHandlePropertyReplacementAndRemovalInSequence() {
            final Metadata metadata = new Metadata();

            // Add
            metadata.addProperty("name", new MetadataProperty<>("First", 1, null));
            assertThat(metadata.getProperties()).hasSize(1);

            // Replace
            metadata.addProperty("name", new MetadataProperty<>("Second", 2, null));
            assertThat(metadata.getProperties()).hasSize(1);
            assertThat(metadata.getProperty(ValidationField.NAME).getValue()).isEqualTo("Second");

            // Remove
            metadata.removeProperty("name");
            assertThat(metadata.getProperties()).isEmpty();

            // Add again
            metadata.addProperty("name", new MetadataProperty<>("Third", 3, null));
            assertThat(metadata.getProperties()).hasSize(1);
            assertThat(metadata.getProperty(ValidationField.NAME).getValue()).isEqualTo("Third");
        }

        @Test
        @DisplayName("Should maintain separate property collections for different metadata instances")
        void shouldMaintainSeparatePropertyCollectionsForDifferentInstances() {
            final Metadata metadata1 = new Metadata();
            final Metadata metadata2 = new Metadata();

            metadata1.addProperty("name", new MetadataProperty<>("Token1", 1, null));
            metadata2.addProperty("name", new MetadataProperty<>("Token2", 1, null));

            assertThat(metadata1.getProperty(ValidationField.NAME).getValue()).isEqualTo("Token1");
            assertThat(metadata2.getProperty(ValidationField.NAME).getValue()).isEqualTo("Token2");
        }
    }
}
