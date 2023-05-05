package org.cardanofoundation.metadatatools.core;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.java.Log;
import org.cardanofoundation.metadatatools.core.cip26.MetadataCreator;
import org.cardanofoundation.metadatatools.core.cip26.model.Metadata;
import org.cardanofoundation.metadatatools.core.crypto.keys.Key;
import org.cardanofoundation.metadatatools.core.cip26.model.KeyTextEnvelope;
import org.cardanofoundation.metadatatools.core.cip26.model.PolicyScript;
import org.cardanofoundation.metadatatools.core.cip26.model.MetadataProperty;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Map;

import static java.util.Map.entry;


@Log
public class TutorialTests {
    @Test
    public void Should_Succeed_When_UserThinksThisIsANiceExample() throws IOException {
        // This Jackson ObjectMapper instance is used for JSON de/serialization.
        final ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

        // Step 1: Load the signing key from a Cardano json envelope representation containing the key material of the
        // signing key encoded as CBOR represented as a hex string. We load the key from a String but nothing prevents
        // us from loading it from a file directly.
        final KeyTextEnvelope signingKeyEnvelope = objectMapper.readValue("""
                {
                  "type": "PaymentSigningKeyShelley_ed25519",
                  "description": "Payment Signing Key",
                  "cborHex": "58202b1b08bb20487b8dae9dac1445462d96fb9c4244e49e87b5d0785b9a2960a60b"
                }
                """, KeyTextEnvelope.class);
        final Key signingKey = Key.fromTextEnvelope(signingKeyEnvelope);

        // Step 2: Load the monetary policy script used within the token minting operation. We load it from a String.
        // Usually this will be loaded from the same file containing the policy that was used during the minting.
        final String policyJson = """
                {
                  "type": "atLeast",
                  "required": 2,
                  "scripts":
                  [
                    {
                      "type": "before",
                      "slot": 600
                    },
                    {
                      "type": "sig",
                      "keyHash": "c04cc33b367f233e6ef0f15b05e2225b1974f4980611fb5852f6d01e"
                    },
                    {
                      "type": "after",
                      "slot": 500
                    }
                  ]
                }""";
        final PolicyScript policyScript = objectMapper.readValue(policyJson, PolicyScript.class);

        // Step 3: Create the actual metadata providing some properties.
        final Metadata metadata = new Metadata("CfTestCoin", policyScript, Map.ofEntries(
                entry("name", new MetadataProperty<>("CfTestCoin", 0, null)),
                entry("description", new MetadataProperty<>("We test with CfTestCoin.", 0, null)),
                entry("ticker", new MetadataProperty<>("CfTstCn", 0, null)),
                entry("decimals", new MetadataProperty<>(6, 0, null))
        ));

        // Step 4: Sign the metadata with the signing key.
        MetadataCreator.signMetadata(metadata, signingKey);

        // Actually the example is over but usually you want to serialize your metadata to JSON or load metadata from
        // JSON and perform a validation based on a certain verification key or likewise. The next steps are about those
        // things.

        // Step 5: Serialize the metadata to its string representation.
        final String tokenMetadataAsJson = objectMapper.writeValueAsString(metadata);

        // Step 6: Deserialize the metadata from its string representation.
        final Metadata metadataDeserialized = objectMapper.readValue(tokenMetadataAsJson, Metadata.class);

        // Step 7: Load the verification key
        final KeyTextEnvelope verificationKeyEnvelope = objectMapper.readValue("""
                {
                  "type": "PaymentVerificationKeyShelley_ed25519",
                  "description": "Payment Verification Key",
                  "cborHex": "58208f26099728b91992ba5a06d8d91152ea6bd9aa1d944334fa96a4541b583c2634"
                }
                """, KeyTextEnvelope.class);
        final Key verificationKey = Key.fromTextEnvelope(verificationKeyEnvelope);

        // Step 8: Try to validate the metadata given a verification key that must be included in the signatures.
        log.info((MetadataCreator.validateMetadata(metadataDeserialized, verificationKey).isValid())
                ? "verification succeeded"
                : "verification failed");
    }
}
