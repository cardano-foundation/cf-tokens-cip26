package org.cardanofoundation.metadatatools.core;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import lombok.extern.log4j.Log4j2;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.util.encoders.Hex;
import org.cardanofoundation.metadatatools.core.crypto.Hashing;
import org.cardanofoundation.metadatatools.core.crypto.keys.Key;
import org.cardanofoundation.metadatatools.core.model.AttestationSignature;
import org.cardanofoundation.metadatatools.core.model.PolicyScript;
import org.cardanofoundation.metadatatools.core.model.TokenMetadataProperty;
import org.cardanofoundation.metadatatools.core.model.TokenMetadata;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;


@Log4j2
public class TokenMetadataCreator {
    public static ValidationResult validateTokenMetadata(final TokenMetadata metadata) {
        return validateTokenMetadata(metadata, null, false);
    }

    public static ValidationResult validateTokenMetadata(final TokenMetadata metadata, final Key verificationKey) {
        return validateTokenMetadata(metadata, verificationKey, false);
    }

    public static ValidationResult validateTokenMetadata(final TokenMetadata metadata, final Key verificationKey, final boolean signaturesOnly) {
        if (metadata == null) {
            throw new IllegalArgumentException("metadata cannot be null.");
        }
        if (verificationKey != null && verificationKey.getKeyType().isSigningKey()) {
            throw new IllegalArgumentException("This function expects a verification key. Public key derivation from private keys shall be done in client.");
        }

        final ValidationResult validationResult = new ValidationResult();
        try {
            final ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
            final PolicyScript policyScript = PolicyScript.fromCborTree(cborMapper.readTree(Hex.decode(metadata.getPolicy())));
            TokenMetadataValidationRules.validateSubjectAndPolicy(metadata.getSubject(), policyScript.computePolicyId(), validationResult);
        } catch (final IOException e) {
            validationResult.addValidationError("Could not deserialize policy script from policy value due to " + e.getMessage());
        }
        TokenMetadataValidationRules.validateHasRequiredProperties(metadata.getProperties().keySet(), validationResult);

        try {
            for (final Map.Entry<String, TokenMetadataProperty<?>> entry : metadata.getProperties().entrySet()) {
                if (!signaturesOnly) {
                    validationResult.mergeWith(TokenMetadataValidationRules.validateProperty(entry.getKey(), entry.getValue()));
                }
                final ObjectMapper objectMapper = new ObjectMapper(new CBORFactory());
                final byte[] propertyHash = Hashing.blake2b256Digest(List.of(
                        Hashing.blake2b256Digest(objectMapper.writeValueAsBytes(metadata.getSubject())),
                        Hashing.blake2b256Digest(objectMapper.writeValueAsBytes(entry.getKey())),
                        Hashing.blake2b256Digest(objectMapper.writeValueAsBytes(entry.getValue().getValue())),
                        Hashing.blake2b256Digest(objectMapper.writeValueAsBytes(entry.getValue().getSequenceNumber()))));
                for (final AttestationSignature attestationSignature : entry.getValue().getSignatures()) {
                    if (verificationKey != null) {
                        if (attestationSignature.getPublicKey().equals(Hex.toHexString(verificationKey.getRawKeyBytes()))) {
                            final byte[] signatureRaw = Hex.decode(attestationSignature.getSignature());
                            final boolean result = Ed25519.verify(signatureRaw, 0, verificationKey.getRawKeyBytes(), 0, propertyHash, 0, propertyHash.length);
                            if (!result) {
                                validationResult.addValidationError(String.format("property %s: signature verification failed for key %s.", entry.getKey(), attestationSignature.getPublicKey()));
                            }
                            break;
                        }
                    } else {
                        final byte[] signatureRaw = Hex.decode(attestationSignature.getSignature());
                        final boolean result = Ed25519.verify(signatureRaw, 0, Hex.decode(attestationSignature.getPublicKey()), 0, propertyHash, 0, propertyHash.length);
                        if (!result) {
                            validationResult.addValidationError(String.format("property %s: signature verification failed for key %s.", entry.getKey(), attestationSignature.getPublicKey()));
                        }
                    }
                }
            }
        } catch (final IOException e) {
            validationResult.addValidationError("Could not verify due to an internal error: " + e.getMessage());
        }

        return validationResult;
    }

    public static ValidationResult validateTokenMetadataUpdate(final TokenMetadata latest, final Key verificationKey, final TokenMetadata base) {
        final ValidationResult resultForLatest = validateTokenMetadata(latest, verificationKey);
        final ValidationResult resultForBase = validateTokenMetadata(base, verificationKey);
        if (resultForLatest.isValid() && resultForBase.isValid()) {
            final ValidationResult validationResult = new ValidationResult();
            if (!latest.getSubject().equalsIgnoreCase(base.getSubject())) {
                validationResult.addValidationError("Subject of updated metadata differs from subject of base metadata.");
            }
            if (!latest.getPolicy().equalsIgnoreCase(base.getPolicy())) {
                validationResult.addValidationError("Policy of updated metadata differs from policy of base metadata.");
            }
            if (!latest.getProperties().keySet().containsAll(base.getProperties().keySet())) {
                validationResult.addValidationError("Missing properties in updated metadata that were available in previous.");
            }
            latest.getProperties().forEach(new BiConsumer<String, TokenMetadataProperty<?>>() {
                @Override
                public void accept(final String propertyKey, final TokenMetadataProperty<?> propertyValue) {
                    if (base.getProperties().containsKey(propertyKey)) {
                        final TokenMetadataProperty<?> baseProperty = base.getProperties().get(propertyKey);
                        if (baseProperty.getSequenceNumber() >= propertyValue.getSequenceNumber()) {
                            validationResult.addValidationError(String.format(
                                    "Sequence number (%d) for property %s is not greater than the sequence number (%d) of the base property.",
                                    propertyValue.getSequenceNumber(), propertyKey, baseProperty.getSequenceNumber()));
                        }
                    }
                }
            });
            return validationResult;
        } else {
            return ValidationResult.mergeResults(List.of(resultForBase, resultForLatest));
        }
    }

    private static void signMetadataProperty(final TokenMetadataProperty<?> property, final Key signingKey, final Key verificationKey, final byte[] subjectHash, final byte[] propertyNameHash) {
        if (property == null) {
            throw new IllegalArgumentException("property cannot be null.");
        }
        if (signingKey == null) {
            throw new IllegalArgumentException("signing key cannot be null.");
        }
        if (!signingKey.getKeyType().isSigningKey()) {
            throw new IllegalArgumentException("Given signing key is no signing key.");
        }
        if (verificationKey == null) {
            throw new IllegalArgumentException("verification key cannot be null.");
        }
        if (verificationKey.getKeyType().isSigningKey()) {
            throw new IllegalArgumentException("Given verification key is no verification key.");
        }
        if (property.getValue() == null) {
            throw new IllegalArgumentException("property value cannot be null.");
        }
        if (property.getSequenceNumber() == null || property.getSequenceNumber() < 0) {
            throw new IllegalArgumentException("property sequenceNumber cannot be null or less than zero.");
        }
        if (subjectHash.length == 0) {
            log.warn("subject hash should not be empty");
        }
        if (propertyNameHash.length == 0) {
            log.warn("subject hash should not be empty");
        }

        try {
            final ObjectMapper objectMapper = new ObjectMapper(new CBORFactory());
            final byte[] propertyHash = Hashing.blake2b256Digest(List.of(
                    subjectHash,
                    propertyNameHash,
                    Hashing.blake2b256Digest(objectMapper.writeValueAsBytes(property.getValue())),
                    Hashing.blake2b256Digest(objectMapper.writeValueAsBytes(property.getSequenceNumber()))));
            final byte[] signature = signingKey.sign(propertyHash);
            property.addOrUpdateSignature(Hex.toHexString(verificationKey.getRawKeyBytes()), Hex.toHexString(signature));
        } catch (final IOException e) {
            throw new IllegalArgumentException("Cannot serialize property fields into cbor.", e);
        }
    }

    public static void signTokenMetadata(final TokenMetadata input, final Key signingKey, final String propertyName) {
        if (input == null) {
            throw new IllegalArgumentException("TokenMetadata object cannot be null.");
        }
        if (signingKey == null) {
            throw new IllegalArgumentException("Signing key cannot be null.");
        }
        if (!signingKey.getKeyType().isSigningKey()) {
            throw new IllegalArgumentException("Given key cannot be used for signing.");
        }
        if (propertyName == null || propertyName.isBlank()) {
            throw new IllegalArgumentException("propertyName cannot be null or blank");
        }

        final TokenMetadataProperty<?> metadataProperty = input.getProperties().getOrDefault(propertyName, null);
        if (metadataProperty != null) {
            try {
                final ObjectMapper objectMapper = new ObjectMapper(new CBORFactory());
                signMetadataProperty(metadataProperty, signingKey, signingKey.generateVerificationKey(),
                        Hashing.blake2b256Digest(objectMapper.writeValueAsBytes(input.getSubject())),
                        Hashing.blake2b256Digest(objectMapper.writeValueAsBytes(propertyName)));
            } catch (final JsonProcessingException e) {
                throw new IllegalArgumentException("Cannot encode subject into cbor.", e);
            }
        }
    }

    public static void signTokenMetadata(final TokenMetadata input, final Key signingKey) {
        if (input == null) {
            throw new IllegalArgumentException("TokenMetadata object cannot be null.");
        }
        if (signingKey == null) {
            throw new IllegalArgumentException("Signing key cannot be null.");
        }
        if (!signingKey.getKeyType().isSigningKey()) {
            throw new IllegalArgumentException("Given key cannot be used for signing.");
        }

        input.getProperties().forEach((key, value) -> signTokenMetadata(input, signingKey, key));
    }
}
