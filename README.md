# Verifiable Credential Go SDK

This is an SDK for verifiable credentials written in the Golang language and it conforms to the W3C recommendation for Verifiable Credentials Data Model.  App developers can easily implement verifiable-credential-related Web3 applications or embed verifiable credentials functionalities into existing Web2 applications.

The functionalities provided by this SDK include supporting issuers in their effort to generate verifiable credentials for holders. With the help of the SDK, holders who received verifiable credentials from issuers can verify them and generate different verifiable presentations for diverse proof purposes very well. The verifiers who want to verify holders’ identity or other information can use this SDK to achieve the goals without difficulty.

This SDK is identifier-agnostic. It supports a variety of identifiers, such as the decentralized identifier (DID) methods defined in the W3C DID Specification Registries as well as ENS or other decentralized domain naming systems. It even supports centralized identifiers.  In terms of proof methods, it supports common cryptographic signature algorithms and will support zero-knowledge proofs in the future. More concretely, it will support range proofs and existence proofs to implement selective disclosure, in a sequence, it can greatly protect users’ privacy and data.

This SDK does not deal with the revocation of verifiable credentials. Because the information in a verifiable credential may be changed for some security reason, the statuses of a verifiable credential include “normal” and “revoked” at least. The application developers can issue this problem in their favor. We provide another SDK to record the verifiable credential status in the Ontology blockchain.

Verifiable Credentials can be used in many business scenarios. When applying for a job, Alice can provide a verifiable presentation derived from her verifiable credentials issued by the university and other vocational training institutions. The employer can verifies cryptographically that the presentation is still in good standing by checking both the  presentation itself (such as checking the signature and the period of validity) and the institutions’ revocation services.

## Roles in the Verifiable Credential System

There are three roles in a verifiable credential and presentation system:

- Holder: the credential owner who holds some credentials which are issued by the issuers, generates presentations from the credentials and presents the generated presentations to the verifier;
- Issuer: the credential issuer who recieves credential request from holders and then issues credentials to the holder;
- Verifier: the presentation verifier who recieves a presentation from the holders and then verifies the holder's presentation.
