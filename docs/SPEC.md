***# Titan Gate — Public Verification Specification***



***\*\*Version:\*\* 1.0.0***  

***\*\*Algorithm:\*\* merkle\_v1***  

***\*\*Signing:\*\* hmac-sha256-v1***  

***\*\*Status:\*\* Stable***



***---***



***## Overview***



***Titan Gate is a cryptographic change-control protocol for AI-assisted software engineering. Every code change evaluated by Titan Gate produces a \*\*receipt\*\* — a signed, chained, Merkle-anchored artifact that proves:***



***1. What was evaluated (artifact, scope, provenance)***

***2. What verdict was reached (PASS / WARN / FAIL)***

***3. That the record has not been tampered with***

***4. That it links to the previous receipt in the chain***



***Receipts are stored at `.titan/receipts/{date}/{receipt\_id}.json` and travel with the repository.***



***---***



***## Receipt Schema***

***```json***

