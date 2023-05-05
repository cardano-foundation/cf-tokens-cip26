package org.cardanofoundation.metadatatools.core.cip26.model;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AttestationSignature {
    private String signature;
    private String publicKey;
}
