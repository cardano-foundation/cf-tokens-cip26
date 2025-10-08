package org.cardanofoundation.metadatatools.core.cip26.model;

import lombok.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MetadataProperty<T> {

    private T value;
    private Integer sequenceNumber;
    private List<AttestationSignature> signatures = new ArrayList<>();

    /**
     * Convenience constructor for creating a property with default sequence number (0) and no signatures.
     *
     * @param value the property value
     */
    public MetadataProperty(final T value) {
        this.value = value;
        this.sequenceNumber = 0;
        this.signatures = new ArrayList<>();
    }

    public void addOrUpdateSignature(final String verificationKeyHex,
                                     final String signatureHex) {
        if (verificationKeyHex == null) {
            throw new IllegalArgumentException("verificationKeyHey cannot be null.");
        }
        if (signatureHex == null) {
            throw new IllegalArgumentException("signatureHex cannot be null.");
        }
        final String verificationKeyHexSanitized = verificationKeyHex.toLowerCase(Locale.ROOT).trim();
        if (verificationKeyHexSanitized.isEmpty()) {
            throw new IllegalArgumentException("verificationKeyHex cannot be empty or blank.");
        }
        final String signatureKeyHexSanitized = signatureHex.toLowerCase(Locale.ROOT).trim();
        if (signatureKeyHexSanitized.isEmpty()) {
            throw new IllegalArgumentException("signatureHex cannot be empty or blank.");
        }

        if (signatures != null) {
            for (final AttestationSignature annotatedSignature : signatures) {
                if (annotatedSignature.getPublicKey().equals(verificationKeyHexSanitized)) {
                    annotatedSignature.setSignature(signatureKeyHexSanitized);
                    return;
                }
            }
        } else {
            signatures = new ArrayList<>();
        }
        signatures.add(new AttestationSignature(signatureKeyHexSanitized, verificationKeyHexSanitized));
    }
}
