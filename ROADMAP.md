# Roadmap de SatsPath

> Base de análisis: `main`, commit `51b5f62`.
> Propuesta de ingeniería basada en una revisión estática del repositorio por tres
> agentes: arquitectura/producto, pruebas/operación y pendientes/integraciones.
> No certifica ejecución de tests, CI remota, despliegues ni interoperabilidad.

## Objetivo

Entregar primero un recorrido reproducible y no custodial:

**Alta de identidad → publicación → acreditación del método → resolución →
cotización → aprobación explícita → ejecución por una wallet externa.**

El primer alcance propuesto es on-chain y después BOLT11. BOLT12, Silent
Payments y Ark avanzan por capacidades demostradas, no por la mera existencia
de parsers, conectores o estructuras de handoff.

Este documento complementa el [roadmap v0.2](docs/v02_roadmap.md): organiza el
trabajo pendiente de producto y operación sin dar por completas las
integraciones que aquel describe a nivel de primitivas. No asigna fechas,
responsables, nuevos números de versión ni estados de issues remotas.

## Estado de partida

| Área | Base existente | Brecha que debe cerrar el roadmap |
| --- | --- | --- |
| Identidad | Perfiles firmados, rotación y recuperación con guardianes | Attestation real del alias; alta/claims sin verificadores mock |
| Resolución | HTTPS, Nostr y BIP-353 con validación DNSSEC nativa | Consumo remoto con evidencia suficiente en daemon; cerrar diferencias de WASM |
| Routing | Cotización on-chain verificada; CLI puede obtener BOLT11 validado | Integrar pruebas de ownership y recorrido positivo del daemon |
| Transparencia | Log, mapa de estado, anclajes regtest y primitivas witness/gossip | Integrar cosignatures/quorum en el servicio y operarlo entre autoridades independientes |
| Wallets | `PaymentIntent` y bridges de referencia | Integraciones externas reproducibles con aprobación y ejecución host |
| Calidad | CI Rust/JS, fuzzing, conformance incremental y E2E del daemon | Probar configuraciones y artefactos distribuidos, WASM real y ejemplos compilables |
| Operación | Docker, métricas, logs, alertas y guías | Despliegue canónico, packaging verificable y recuperación ensayada |

**Distinción clave:** perfil firmado ≠ control del alias ≠ control del método ≠
handoff pagable ≠ pago ejecutado. El dashboard y la documentación deben mostrar
estos estados por separado.

La evidencia regtest registrada muestra recepción BIP-21 y anclajes, pero
`send/quote/pay` devuelven `no_route` para métodos sin prueba de ownership.
Eso no demuestra todavía el recorrido positivo completo del producto.

Fuentes: [README](README.md#what-works-today-what-is-experimental-and-what-has-not-been-audited),
[resultados E2E](docs/daemon_e2e_results.md),
[pruebas del daemon](crates/satspathd/tests/e2e_daemon_flow.rs).

## Prioridades y dependencias

- **P0:** bloqueos del recorrido básico y de una distribución preview verificable.
- **P1:** ampliación del producto e integración operativa.
- **P2:** capacidades experimentales que no bloquean el núcleo inicial.

Secuencia principal: **H0 → H1 → H2 → H4 → H5**.
H3 puede avanzar en paralelo desde H0; H6 necesita H2 y se apoya en H3.
H7 necesita H3 y H6, y también H4/H5 para las capacidades que se anuncien.
H8 es una línea independiente, con gates propios.

### H0 · P0 — Alinear el contrato de capacidades

- [ ] Publicar una matriz CLI/daemon/WASM/dashboard que distinga descubrimiento,
  recepción sin importe, cotización pagable, aprobación y ejecución externa.
- [ ] Corregir ejemplos SDK que omiten `PaymentIntent`, nombres/rutas de bridges
  obsoletos y afirmaciones que confunden primitivas con interoperabilidad.
- [ ] Inventariar tests ignorados: motivo, capacidad cubierta y comando/job que
  los ejecuta. Regtest ignorado pero invocado en CI no cuenta como cobertura ausente.

**Aceptación:** cada capacidad anunciada enlaza a una prueba o evidencia
reproducible; previews y stubs quedan identificados explícitamente.

Evidencia: [roadmap anterior](docs/v02_roadmap.md),
[quickstart](docs/SDK_QUICKSTART.md), [contrato PaymentIntent](docs/payment_intent.md),
[CI E2E](.github/workflows/daemon-e2e.yml).

### H1 · P0 — Alta y acreditación de métodos utilizables

- [ ] Elegir e implementar un primer mecanismo real de control del alias,
  enlazado al registro y al evento autorizado; no usar la invitación como prueba.
- [ ] Sustituir la URL placeholder de claim por un destino configurable y funcional.
- [ ] Integrar incorporación y renovación de pruebas de ownership en el daemon.
- [ ] Definir preservación de pruebas ante ediciones no relacionadas e invalidación
  cuando cambia el método acreditado.

**Aceptación:** alta y claim sin flags mock; rechazos de alias incorrecto,
expiración y reutilización sin mutaciones; método acreditado resoluble como tal.

Evidencia: [claim](crates/satspathd/src/handlers/claim.rs),
[perfiles](crates/satspathd/src/handlers/profile.rs),
[herramientas de proofs](crates/satspath-cli/src/commands/proofs.rs).

### H2 · P0 — Recorrido on-chain positivo de extremo a extremo

- [ ] Automatizar perfil → ownership → resolución → `quote/pay/send` → BIP-21
  con importe y red exactos.
- [ ] Conectar el handoff a una wallet externa en regtest, con aprobación explícita.
- [ ] Verificar persistencia y continuidad después de reiniciar el daemon.
- [ ] Mantener rechazos de métodos no acreditados y destinos/importe/red alterados.

**Aceptación:** fixture reproducible sin bypass de ownership; evidencia separada
de cotización, aprobación, transacción firmada por la wallet y confirmación regtest.
El daemon no firma ni ejecuta pagos del usuario.

Evidencia: [quote](crates/satspathd/src/handlers/quote.rs),
[gates de handoff](crates/satspath-router/src/quote_response.rs),
[E2E actuales](crates/satspathd/tests/e2e_daemon_flow.rs).

### H3 · P0 — Packaging y despliegue preview reproducibles

- [ ] Definir el grafo de paquetes distribuibles, sus versiones y dependencias;
  validar `cargo package` y `cargo publish --dry-run` antes de publicar.
- [ ] Fijar entradas de build y una política de lockfiles para aplicaciones;
  condicionar releases a checks del mismo SHA.
- [ ] Construir, escanear y probar la imagen daemon; usar su referencia real en
  un Compose canónico con permisos de volumen y configuración TLS documentados.
- [ ] Implementar `server init/check` o identificarlos como stubs que no validan
  un despliegue real.

**Aceptación:** instalación desde artefactos en entorno limpio, arranque con
volumen vacío, reinicio con estado conservado y smoke por proxy. Documentación,
imagen publicada y opciones de contenedor coinciden.

Evidencia: [publicación](.github/workflows/publish.yml),
[Docker CI](.github/workflows/docker.yml), [deploy](deploy/README.md),
[comandos server](crates/satspath-cli/src/commands/server.rs).

### H4 · P1 — SDK/WASM y conformance consumibles

- [ ] Corregir o delimitar registro local, Nostr, serialización y BIP-353 en WASM;
  probar compatibilidad con los contratos del resolver nativo donde corresponda.
- [ ] Compilar el quickstart TypeScript contra declaraciones generadas e instalar
  el paquete resultante en un proyecto limpio; no documentar paquetes inexistentes.
- [ ] Añadir build wasm32 y smoke browser de resolve→quote antes de publicación.
- [ ] Ejecutar tests documentales en CI y ampliar conformance con rotación positiva,
  `PaymentIntent`, handoff y conflictos autenticados, sin convertir SKIP en PASS.

**Aceptación:** ejemplos Rust/TypeScript compilables, prueba real del artefacto WASM
y matriz explícita de diferencias nativo/browser, incluida la evidencia DNSSEC.

Evidencia: [resolver WASM](crates/satspath-wasm/src/resolver.rs),
[router WASM](crates/satspath-wasm/src/router.rs),
[conformance](crates/satspath-conformance/README.md), [CI](.github/workflows/ci.yml).

### H5 · P1 — Lightning y wallets host integradas

- [ ] Llevar al daemon la obtención de BOLT11 ligada al payee autenticado,
  importe, red y expiración, reutilizando las validaciones existentes.
- [ ] Integrar una wallet on-chain y otra Lightning con callbacks reales,
  `PaymentIntent`, confirmación del usuario y límites de comisión.
- [ ] Alinear dashboard con estados reales: alias, ownership, recepción, preview
  y pago; no anunciar invitaciones mock como claims de producción.

**Aceptación:** recorrido BOLT11 reproducible en red de prueba y matriz de wallets
con versiones/resultados; rechazos de modificaciones posteriores a la aprobación.
Las pruebas con mocks se registran aparte de interoperabilidad externa.

Evidencia: [handoff](crates/satspath-router/src/handoff.rs),
[wallet executor](crates/satspath-router/src/wallet_executor.rs),
[dashboard](crates/satspathd/src/index.html).

### H6 · P1 — Quorum integrado y operación multioperador

- [ ] Conectar checkpoints, witnesses y recopilación/consumo de cosignatures;
  servir evidencia suficiente para resolución remota y continuidad.
- [ ] Definir contratos distintos de liveness, readiness del servicio y readiness
  S2S; no presentar el health actual como prueba de quorum integrado.
- [ ] Probar operadores independientes, reinicio, pérdida de quorum y desacuerdo.
- [ ] Verificar frescura de métricas, reglas con `promtool`, recepción real de
  alertas y runbooks para fallos de dependencias.

**Aceptación:** demo multioperador repetible con firmas verificadas, estado durable
y fallos visibles; consumidores no aceptan evidencia insuficiente.

Evidencia: [resolve](crates/satspathd/src/handlers/resolve.rs),
[health/routing](crates/satspathd/src/router.rs),
[witness](crates/satspath-witness/src/lib.rs),
[guía de witnesses](docs/s2s/witness-deployment.md), [monitoring](monitoring/).

### H7 · P1 — Piloto recuperable y gates de release

- [ ] Ensayar backup consistente, restauración en volumen nuevo y upgrade;
  comparar identidad del log, secuencias, perfiles, eventos, checkpoints y pins.
- [ ] Documentar límites de rollback, inventario de secretos/estado y objetivos
  RPO/RTO medidos; probar caída abrupta y disco lleno en laboratorio descartable.
- [ ] Probar defaults y all-features, además de las imágenes y paquetes finales;
  registrar carga, latencia y crecimiento del almacenamiento.
- [ ] Publicar manifiesto de artefactos, checksums, compatibilidad y limitaciones.
- [ ] Completar la revisión externa independiente requerida antes de recomendar
  uso con fondos reales; registrar alcance y resolución de hallazgos.

**Aceptación:** checklist de release trazable a evidencia del mismo commit,
restauración ensayada y piloto con alertas operativas. Una preview delimitada no
necesita habilitar todos los raíles experimentales.

Evidencia: [persistencia](crates/satspath-core/src/transparency/database.rs),
[operación Docker](docs/docker.md),
[revisión externa requerida](docs/audit/EXTERNAL_CRYPTO_REVIEW_SPEC.md).

### H8 · P2 — Promover capacidades experimentales por separado

| Capacidad | Próximo resultado verificable |
| --- | --- |
| BOLT12 | Conservar recepción sin importe ya cubierta; unificar contrato WASM/proxy, sustituir invoice dummy e integrar backend CLN/LDK real antes de habilitar pago |
| Silent Payments | Persistir descriptor de recepción, validar red y URI interoperable, activar aceptación pendiente y probar wallet host; ECDH privado permanece en la wallet |
| Ark | Sustituir URI privada por recepción interoperable, activar aceptación pendiente y probar ASP/wallet identificados antes de habilitar ejecución |
| Swaps | Matriz por tipo/script/red; completar o rechazar anticipadamente claims no implementados y probar claim/refund/recuperación en testnet/regtest |
| PQC | Mantener línea de investigación separada, sin promesas de madurez productiva |

**Aceptación por capacidad:** test automatizado + ejemplo reproducible + evidencia
externa cuando corresponda + documentación de límites. Retirar únicamente el gate
demostrado, sin habilitar otros raíles por efecto colateral. La evidencia en redes
de prueba no se presenta como validación mainnet.

Evidencia: [aceptaciones existentes](crates/satspathd/tests/e2e_daemon_flow.rs),
[proxy BOLT12](proxy-workers/bolt12/src/index.ts),
[cliente BOLT12 WASM](crates/satspath-wasm/src/bolt12.rs),
[chain swaps](crates/satspath-swaps/src/chain_swap.rs),
[reverse swaps](crates/satspath-swaps/src/reverse.rs).

## Límites que el roadmap no debe eliminar accidentalmente

- La wallet host conserva claves de gasto, firma y ejecución; SatsPath no recibe
  seeds ni `xprv`/`tprv`. Las claves de identidad son una categoría distinta.
- El anclaje activo actual es regtest y del operador; no ampliar a mainnet ni
  usar fondos reales como consecuencia de completar otro hito.
- Mantener swaps mainnet deshabilitados y handoffs experimentales cerrados hasta
  cumplir sus criterios específicos.
- El quorum mejora consistencia, pero no autentica por sí solo el vínculo inicial
  alias→clave. No ocultar TOFU ni dependencia de autoridades de namespace.
- P2P es descubrimiento opcional, no autoridad para importar perfiles ciegamente.

Referencia: [mainnet safety](docs/mainnet_safety.md).

## Regla de seguimiento

Cada hito se convierte en tareas con responsable y evidencia antes de planificar
fechas. Marcar una casilla solo cuando su criterio sea reproducible; actualizar
la matriz de capacidades y este documento al cerrar el hito.

**Primer incremento recomendado:** H0, mecanismo de alias elegido para H1 y un
fixture positivo de H2. En paralelo, ensayar packaging de H3 sin publicar nada.
