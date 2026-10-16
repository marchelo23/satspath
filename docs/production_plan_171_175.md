# Plan de implementación: issues #171–#175

Estado: PRs de implementación incremental. Una prueba simulada **no** demuestra
interoperabilidad ni autoriza una afirmación de compatibilidad. No cerrar un
issue hasta satisfacer todos sus criterios de aceptación.

## Dependencias y orden

1. **#173 — PaymentIntent (P0)**: base en PR #164 (WalletExecutor). Representación
   canónica, aprobación explícita, límites de red/importe/comisión, revalidación
   del perfil y pruebas adversarias. Pendiente: integrar procedencia autenticada
   en `QuoteResponse` y aprobaciones específicas de BOLT12/Ark/SP. ~1–2 días.
2. **#174 — desacuerdos de resolvers (P1)**: base en `main`. Definir autoridad,
   corroboración, continuidad de claves/secuencias/capacidades y errores
   deterministas; integrar pruebas de transparencia y reportar la procedencia
   al wallet antes de relajar disponibilidad. ~1–2 días.
3. **#172 — fuzz y propiedades (P0)**: base en `main`; ampliar parsers Nostr,
   Merkle, capacidades y firmas. Tras #173, agregar fuzz del PaymentIntent y
   dispatcher; campañas reproducibles y corpus de regresión. ~1–2 días.
4. **#175 — conformidad (P1)**: base en `main`; vectores JSON, CLI y reportes
   legibles/JSON. Tras #173/#174, incorporar vectores positivos y negativos de
   intent, continuidad y desacuerdos y ejecutar implementaciones externas.
   ~2–3 días.
5. **#171 — interop con wallets reales (P0)**: base en #173/#164. Primero
   HTTPS/on-chain/regtest, después Lightning/BIP-353/Nostr, luego BOLT12,
   Silent Payments y Ark cuando PRs #153–#155/#161 estén integrados. Cada
   caso exige recibo del wallet *y* confirmación independiente del receptor.
   Signet y mainnet de bajo importe requieren infraestructura y autorización
   explícitas. ~3–5 días más la disponibilidad de nodos/wallets.

## Puertas de revisión

- `cargo fmt --all -- --check`, `cargo test --workspace`,
  `cargo clippy --workspace --all-targets -- -D warnings` por PR.
- El fallo de firma, expiración, revocación, red, fee o prueba de transparencia
  nunca alcanza un método de pago del host.
- Wallet/LDK/BDK guardan todas las credenciales de gasto; SatsPath solo pasa
  payloads públicos e intent aprobado. No insertar seeds, macaroons ni RPC
  credentials en fixtures.
- La matriz de [interoperabilidad](interop_matrix.md) se actualiza **solo**
  con evidencia de ejecución y confirmación del receptor, no con mocks.
