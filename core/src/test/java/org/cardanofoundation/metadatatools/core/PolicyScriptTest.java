package org.cardanofoundation.metadatatools.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import org.cardanofoundation.metadatatools.core.cip26.model.PolicyScript;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.*;

@DisplayName("PolicyScript Tests")
class PolicyScriptTest {

    private static final String POLICY_ID = "fb864e59bf8620349c3ebe29af5ad0f9ca2e319d39e115eb93aa58a4";

    private String loadResourceAsString(final String resourcePath) throws IOException {
        try (final InputStream is = getClass().getClassLoader().getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new IOException("Resource not found: " + resourcePath);
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private File getResourceFile(final String resourcePath) {
        final ClassLoader classLoader = getClass().getClassLoader();
        final java.net.URL resource = classLoader.getResource(resourcePath);
        if (resource == null) {
            throw new IllegalArgumentException("Resource not found: " + resourcePath);
        }
        return new File(resource.getFile());
    }

    @Nested
    @DisplayName("Loading from Resources Tests")
    class LoadingFromResourcesTests {

        @Test
        @DisplayName("Should load simple policy script from resource file")
        void shouldLoadSimplePolicyScriptFromResourceFile() throws IOException {
            final String scriptContent = loadResourceAsString("policy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            assertThat(policyScript).isNotNull();
            assertThat(policyScript.getType()).isNotNull();
            assertThat(policyScript.getKeyHash()).isEqualTo(POLICY_ID);
        }

        @Test
        @DisplayName("Should load atLeast policy script from resource file")
        void shouldLoadAtLeastPolicyScriptFromResourceFile() throws IOException {
            final String scriptContent = loadResourceAsString("atLeastPolicy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            assertThat(policyScript).isNotNull();
            assertThat(policyScript.getType()).isNotNull();
            assertThat(policyScript.getRequired()).isEqualTo(1);
            assertThat(policyScript.getScripts()).hasSize(3);
        }

        @Test
        @DisplayName("Should verify atLeast policy script structure")
        void shouldVerifyAtLeastPolicyScriptStructure() throws IOException {
            final String scriptContent = loadResourceAsString("atLeastPolicy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            assertThat(policyScript.getScripts()).isNotNull();
            assertThat(policyScript.getScripts()).hasSize(3);

            // First script: before slot 600
            assertThat(policyScript.getScripts().get(0).getSlot()).isEqualTo(600);

            // Second script: signature
            assertThat(policyScript.getScripts().get(1).getKeyHash()).isEqualTo(POLICY_ID);

            // Third script: after slot 500
            assertThat(policyScript.getScripts().get(2).getSlot()).isEqualTo(500);
        }

        @Test
        @DisplayName("Should verify simple script has expected fields")
        void shouldVerifySimpleScriptHasExpectedFields() throws IOException {
            final String scriptContent = loadResourceAsString("policy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            assertThat(policyScript.getType()).isNotNull();
            assertThat(policyScript.getKeyHash()).isNotNull().isEqualTo(POLICY_ID);
            assertThat(policyScript.getScripts()).isNull();
            assertThat(policyScript.getSlot()).isNull();
            assertThat(policyScript.getRequired()).isNull();
        }

        @Test
        @DisplayName("Should verify atLeast script has expected fields")
        void shouldVerifyAtLeastScriptHasExpectedFields() throws IOException {
            final String scriptContent = loadResourceAsString("atLeastPolicy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            assertThat(policyScript.getType()).isNotNull();
            assertThat(policyScript.getRequired()).isEqualTo(1);
            assertThat(policyScript.getScripts()).isNotNull().hasSize(3);
            assertThat(policyScript.getKeyHash()).isNull();
        }
    }

    @Nested
    @DisplayName("Policy ID Computation Tests")
    class PolicyIdComputationTests {

        @Test
        @DisplayName("Should compute policy ID from simple signature script")
        void shouldComputePolicyIdFromSimpleSignatureScript() throws IOException {
            final String scriptContent = loadResourceAsString("policy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            final String computedPolicyId = policyScript.computePolicyId();

            assertThat(computedPolicyId).isNotNull();
            assertThat(computedPolicyId).hasSize(56); // BLAKE2b-224 produces 28 bytes = 56 hex characters
            assertThat(computedPolicyId).matches("^[0-9a-f]+$"); // Hex string
        }

        @Test
        @DisplayName("Should compute policy ID from atLeast script")
        void shouldComputePolicyIdFromAtLeastScript() throws IOException {
            final String scriptContent = loadResourceAsString("atLeastPolicy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            final String computedPolicyId = policyScript.computePolicyId();

            assertThat(computedPolicyId).isNotNull();
            assertThat(computedPolicyId).hasSize(56);
            assertThat(computedPolicyId).matches("^[0-9a-f]+$");
        }

        @Test
        @DisplayName("Should compute policy ID from file using static method")
        void shouldComputePolicyIdFromFileUsingStaticMethod() throws IOException {
            final File policyFile = getResourceFile("policy.script");
            final String computedPolicyId = PolicyScript.computePolicyId(policyFile);

            assertThat(computedPolicyId).isNotNull();
            assertThat(computedPolicyId).hasSize(56);
            assertThat(computedPolicyId).matches("^[0-9a-f]+$");
        }

        @Test
        @DisplayName("Should compute policy ID from string using static method")
        void shouldComputePolicyIdFromStringUsingStaticMethod() throws IOException {
            final String scriptContent = loadResourceAsString("policy.script");
            final String computedPolicyId = PolicyScript.computePolicyId(scriptContent);

            assertThat(computedPolicyId).isNotNull();
            assertThat(computedPolicyId).hasSize(56);
            assertThat(computedPolicyId).matches("^[0-9a-f]+$");
        }

        @Test
        @DisplayName("Should compute same policy ID for same script")
        void shouldComputeSamePolicyIdForSameScript() throws IOException {
            final String scriptContent = loadResourceAsString("policy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            final String policyId1 = policyScript.computePolicyId();
            final String policyId2 = policyScript.computePolicyId();

            assertThat(policyId1).isEqualTo(policyId2);
        }

        @Test
        @DisplayName("Should compute different policy IDs for different scripts")
        void shouldComputeDifferentPolicyIdsForDifferentScripts() throws IOException {
            final String simpleScriptContent = loadResourceAsString("policy.script");
            final String atLeastScriptContent = loadResourceAsString("atLeastPolicy.script");

            final String policyId1 = PolicyScript.computePolicyId(simpleScriptContent);
            final String policyId2 = PolicyScript.computePolicyId(atLeastScriptContent);

            assertThat(policyId1).isNotEqualTo(policyId2);
        }

        @Test
        @DisplayName("Should compute consistent policy ID from different methods")
        void shouldComputeConsistentPolicyIdFromDifferentMethods() throws IOException {
            final String scriptContent = loadResourceAsString("policy.script");

            // Method 1: From string
            final String policyId1 = PolicyScript.computePolicyId(scriptContent);

            // Method 2: From file
            final File policyFile = getResourceFile("policy.script");
            final String policyId2 = PolicyScript.computePolicyId(policyFile);

            // Method 3: From deserialized object
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);
            final String policyId3 = policyScript.computePolicyId();

            assertThat(policyId1).isEqualTo(policyId2);
            assertThat(policyId2).isEqualTo(policyId3);
        }
    }

    @Nested
    @DisplayName("CBOR Serialization Tests")
    class CborSerializationTests {

        @Test
        @DisplayName("Should convert simple script to CBOR")
        void shouldConvertSimpleScriptToCbor() throws IOException {
            final String scriptContent = loadResourceAsString("policy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            final byte[] cbor = policyScript.toCbor();

            assertThat(cbor).isNotNull();
            assertThat(cbor).isNotEmpty();
        }

        @Test
        @DisplayName("Should convert atLeast script to CBOR")
        void shouldConvertAtLeastScriptToCbor() throws IOException {
            final String scriptContent = loadResourceAsString("atLeastPolicy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            final byte[] cbor = policyScript.toCbor();

            assertThat(cbor).isNotNull();
            assertThat(cbor).isNotEmpty();
        }

        @Test
        @DisplayName("Should convert simple script to CBOR tree")
        void shouldConvertSimpleScriptToCborTree() throws IOException {
            final String scriptContent = loadResourceAsString("policy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            final ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
            final JsonNode cborTree = policyScript.toCborTree(cborMapper);

            assertThat(cborTree).isNotNull();
            assertThat(cborTree.isArray()).isTrue();
            assertThat(cborTree.size()).isEqualTo(2); // Root array with 2 elements
        }

        @Test
        @DisplayName("Should convert atLeast script to CBOR tree")
        void shouldConvertAtLeastScriptToCborTree() throws IOException {
            final String scriptContent = loadResourceAsString("atLeastPolicy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            final ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
            final JsonNode cborTree = policyScript.toCborTree(cborMapper);

            assertThat(cborTree).isNotNull();
            assertThat(cborTree.isArray()).isTrue();
        }

        @Test
        @DisplayName("Should produce consistent CBOR for same script")
        void shouldProduceConsistentCborForSameScript() throws IOException {
            final String scriptContent = loadResourceAsString("policy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            final byte[] cbor1 = policyScript.toCbor();
            final byte[] cbor2 = policyScript.toCbor();

            assertThat(cbor1).isEqualTo(cbor2);
        }
    }

    @Nested
    @DisplayName("CBOR Deserialization Tests")
    class CborDeserializationTests {

        @Test
        @DisplayName("Should deserialize simple script from CBOR tree")
        void shouldDeserializeSimpleScriptFromCborTree() throws IOException {
            final String scriptContent = loadResourceAsString("policy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript originalScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            // Serialize to CBOR
            final ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
            final JsonNode cborTree = originalScript.toCborTree(cborMapper);

            // Deserialize from CBOR
            final PolicyScript deserializedScript = PolicyScript.fromCborTree(cborTree);

            assertThat(deserializedScript).isNotNull();
            assertThat(deserializedScript.getType()).isEqualTo(originalScript.getType());
            assertThat(deserializedScript.getKeyHash()).isEqualTo(originalScript.getKeyHash());
        }

        @Test
        @DisplayName("Should deserialize atLeast script from CBOR tree")
        void shouldDeserializeAtLeastScriptFromCborTree() throws IOException {
            final String scriptContent = loadResourceAsString("atLeastPolicy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript originalScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            // Serialize to CBOR
            final ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
            final JsonNode cborTree = originalScript.toCborTree(cborMapper);

            // Deserialize from CBOR
            final PolicyScript deserializedScript = PolicyScript.fromCborTree(cborTree);

            assertThat(deserializedScript).isNotNull();
            assertThat(deserializedScript.getType()).isEqualTo(originalScript.getType());
            assertThat(deserializedScript.getRequired()).isEqualTo(originalScript.getRequired());
            assertThat(deserializedScript.getScripts()).hasSameSizeAs(originalScript.getScripts());
        }

        @Test
        @DisplayName("Should deserialize and compute same policy ID")
        void shouldDeserializeAndComputeSamePolicyId() throws IOException {
            final String scriptContent = loadResourceAsString("policy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript originalScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            final String originalPolicyId = originalScript.computePolicyId();

            // Round trip: serialize to CBOR and deserialize
            final ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
            final JsonNode cborTree = originalScript.toCborTree(cborMapper);
            final PolicyScript deserializedScript = PolicyScript.fromCborTree(cborTree);

            final String deserializedPolicyId = deserializedScript.computePolicyId();

            assertThat(deserializedPolicyId).isEqualTo(originalPolicyId);
        }

        @Test
        @DisplayName("Should preserve nested script structure through deserialization")
        void shouldPreserveNestedScriptStructureThroughDeserialization() throws IOException {
            final String scriptContent = loadResourceAsString("atLeastPolicy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript originalScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            // Serialize to CBOR
            final ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
            final JsonNode cborTree = originalScript.toCborTree(cborMapper);

            // Deserialize from CBOR
            final PolicyScript deserializedScript = PolicyScript.fromCborTree(cborTree);

            assertThat(deserializedScript.getScripts()).hasSize(3);
            assertThat(deserializedScript.getScripts().get(0).getSlot()).isEqualTo(600);
            assertThat(deserializedScript.getScripts().get(1).getKeyHash()).isEqualTo(POLICY_ID);
            assertThat(deserializedScript.getScripts().get(2).getSlot()).isEqualTo(500);
        }
    }

    @Nested
    @DisplayName("CBOR Round-trip Tests")
    class CborRoundTripTests {

        @Test
        @DisplayName("Should round-trip simple signature script through CBOR")
        void shouldRoundTripSimpleSignatureScriptThroughCbor() throws IOException {
            final String scriptContent = loadResourceAsString("policy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript originalScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            // Serialize to CBOR
            final byte[] cborBytes = originalScript.toCbor();

            // Deserialize from CBOR
            final ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
            final JsonNode cborTree = cborMapper.readTree(cborBytes);
            final PolicyScript deserializedScript = PolicyScript.fromCborTree(cborTree);

            // Verify
            assertThat(deserializedScript.getType()).isEqualTo(originalScript.getType());
            assertThat(deserializedScript.getKeyHash()).isEqualTo(originalScript.getKeyHash());
            assertThat(deserializedScript.computePolicyId()).isEqualTo(originalScript.computePolicyId());
        }

        @Test
        @DisplayName("Should round-trip atLeast script through CBOR")
        void shouldRoundTripAtLeastScriptThroughCbor() throws IOException {
            final String scriptContent = loadResourceAsString("atLeastPolicy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript originalScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            // Serialize to CBOR
            final byte[] cborBytes = originalScript.toCbor();

            // Deserialize from CBOR
            final ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
            final JsonNode cborTree = cborMapper.readTree(cborBytes);
            final PolicyScript deserializedScript = PolicyScript.fromCborTree(cborTree);

            // Verify
            assertThat(deserializedScript.getType()).isEqualTo(originalScript.getType());
            assertThat(deserializedScript.getRequired()).isEqualTo(originalScript.getRequired());
            assertThat(deserializedScript.getScripts()).hasSameSizeAs(originalScript.getScripts());
            assertThat(deserializedScript.computePolicyId()).isEqualTo(originalScript.computePolicyId());
        }

        @Test
        @DisplayName("Should preserve all script properties through CBOR round-trip")
        void shouldPreserveAllScriptPropertiesThroughCborRoundTrip() throws IOException {
            final String scriptContent = loadResourceAsString("policy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript originalScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            // Serialize to CBOR
            final byte[] cborBytes = originalScript.toCbor();

            // Deserialize from CBOR
            final ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
            final JsonNode cborTree = cborMapper.readTree(cborBytes);
            final PolicyScript deserializedScript = PolicyScript.fromCborTree(cborTree);

            // Verify all properties
            assertThat(deserializedScript.getType()).isEqualTo(originalScript.getType());
            assertThat(deserializedScript.getKeyHash()).isEqualTo(originalScript.getKeyHash());
            assertThat(deserializedScript.getSlot()).isEqualTo(originalScript.getSlot());
            assertThat(deserializedScript.getRequired()).isEqualTo(originalScript.getRequired());
        }

        @Test
        @DisplayName("Should maintain policy ID consistency across multiple round-trips")
        void shouldMaintainPolicyIdConsistencyAcrossMultipleRoundTrips() throws IOException {
            final String scriptContent = loadResourceAsString("policy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            PolicyScript script = jsonMapper.readValue(scriptContent, PolicyScript.class);

            final String originalPolicyId = script.computePolicyId();

            // Perform 3 round-trips
            final ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
            for (int i = 0; i < 3; i++) {
                final byte[] cborBytes = script.toCbor();
                final JsonNode cborTree = cborMapper.readTree(cborBytes);
                script = PolicyScript.fromCborTree(cborTree);
            }

            assertThat(script.computePolicyId()).isEqualTo(originalPolicyId);
        }
    }

    @Nested
    @DisplayName("Edge Cases and Error Handling")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should throw exception when computing policy ID from invalid JSON")
        void shouldThrowExceptionWhenComputingPolicyIdFromInvalidJson() {
            final String invalidJson = "{ invalid json }";

            assertThatThrownBy(() -> PolicyScript.computePolicyId(invalidJson))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Cannot compute policy id");
        }

        @Test
        @DisplayName("Should throw exception when deserializing invalid CBOR tree")
        void shouldThrowExceptionWhenDeserializingInvalidCborTree() {
            final ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
            final JsonNode invalidNode = cborMapper.createArrayNode(); // Empty array

            assertThatThrownBy(() -> PolicyScript.fromCborTree(invalidNode))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Invalid root node");
        }

        @Test
        @DisplayName("Should handle script with no nested scripts")
        void shouldHandleScriptWithNoNestedScripts() throws IOException {
            final String scriptContent = loadResourceAsString("policy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            assertThat(policyScript.getScripts()).isNull();
            assertThat(policyScript.getKeyHash()).isNotNull();
        }

        @Test
        @DisplayName("Should handle script with multiple nested levels")
        void shouldHandleScriptWithMultipleNestedLevels() throws IOException {
            final String scriptContent = loadResourceAsString("atLeastPolicy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            assertThat(policyScript.getScripts()).isNotNull();
            assertThat(policyScript.getScripts()).hasSize(3);
            assertThat(policyScript.getScripts().get(0)).isNotNull();
            assertThat(policyScript.getScripts().get(1)).isNotNull();
            assertThat(policyScript.getScripts().get(2)).isNotNull();
        }
    }

    @Nested
    @DisplayName("Integration Tests with Metadata")
    class IntegrationTests {

        @Test
        @DisplayName("Should use policy script to compute subject in metadata")
        void shouldUsePolicyScriptToComputeSubjectInMetadata() throws IOException {
            final String scriptContent = loadResourceAsString("policy.script");
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);

            final String policyId = policyScript.computePolicyId();

            assertThat(policyId).isNotNull();
            assertThat(policyId).hasSize(56);

            // Verify that policy script can be used to set policy
            final byte[] policyCbor = policyScript.toCbor();
            assertThat(policyCbor).isNotNull();
            assertThat(policyCbor).isNotEmpty();
        }

        @Test
        @DisplayName("Should compute consistent policy IDs across multiple operations")
        void shouldComputeConsistentPolicyIdsAcrossMultipleOperations() throws IOException {
            final String scriptContent = loadResourceAsString("policy.script");

            // Method 1: Direct from string
            final String policyId1 = PolicyScript.computePolicyId(scriptContent);

            // Method 2: From deserialized object
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(scriptContent, PolicyScript.class);
            final String policyId2 = policyScript.computePolicyId();

            // Method 3: After CBOR round-trip
            final byte[] cbor = policyScript.toCbor();
            final ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
            final JsonNode cborTree = cborMapper.readTree(cbor);
            final PolicyScript deserializedScript = PolicyScript.fromCborTree(cborTree);
            final String policyId3 = deserializedScript.computePolicyId();

            assertThat(policyId1).isEqualTo(policyId2);
            assertThat(policyId2).isEqualTo(policyId3);
        }

        @Test
        @DisplayName("Should verify JSON to CBOR to PolicyID pipeline")
        void shouldVerifyJsonToCborToPolicyIdPipeline() throws IOException {
            // Start with JSON from resource
            final String jsonContent = loadResourceAsString("atLeastPolicy.script");

            // Parse to PolicyScript
            final ObjectMapper jsonMapper = new ObjectMapper();
            final PolicyScript policyScript = jsonMapper.readValue(jsonContent, PolicyScript.class);

            // Convert to CBOR
            final byte[] cborBytes = policyScript.toCbor();
            assertThat(cborBytes).isNotNull().isNotEmpty();

            // Compute policy ID
            final String policyId = policyScript.computePolicyId();
            assertThat(policyId).isNotNull().hasSize(56).matches("^[0-9a-f]+$");

            // Verify round-trip
            final ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
            final JsonNode cborTree = cborMapper.readTree(cborBytes);
            final PolicyScript roundTripScript = PolicyScript.fromCborTree(cborTree);
            assertThat(roundTripScript.computePolicyId()).isEqualTo(policyId);
        }
    }
}
