# ADR 0018 — Frontière entre synchronisation et autorisation, ancrage de la genèse

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte

`hirzla-sync` valide et fusionne les opérations (`sync-protocol.md` § 6, § 8). La décision
« l'auteur avait-il le droit ? » relève de l'état d'autorisation du § 9.4 : rôles, ancienneté,
quorum, révocations, quarantaine. C'est le métier de `hirzla-access`, écrit en parallèle.
Trois points ne sont pas tranchés par la spécification ni par un ADR :

1. **Où passe la frontière.** `CLAUDE.md` dessine `access ← sync`, ce qui supposerait que
   `sync` appelle `access`. Mais `access` a besoin des opérations décodées, du graphe causal et
   des corps de contrôle, que `sync` produit. Une dépendance dans un sens ou dans l'autre fige
   l'ordre de développement des deux caisses.
2. **Quelle genèse.** Un relais malveillant, ou un membre d'un autre casier, peut injecter une
   deuxième `LockerCreate` avec le même `locker_id`. Le § 6 ne dit pas laquelle vaut.
3. **Pour quelle époque sont les enveloppes** de `Grant`, `DeviceAdd` et `EnvelopeAdd`.

## Décision

### 1. Un trait d'autorisation défini par `hirzla-sync`

`hirzla-sync` définit le trait `Authorizer` (module `authz`) et ne dépend pas de
`hirzla-access`. `hirzla-access` l'implémente (ou `hirzla-core` l'adapte). Le sens des
dépendances devient `crypto ← vault ← sync ← access ← core` ; le schéma de `CLAUDE.md` est à
corriger par le responsable du projet.

```rust
pub enum DataKind { SecretPut, LockerMetaPut }
pub enum OpBody { Control(ControlBody), Data(DataKind) }
pub struct VerifiedApproval { pub member: Id16, pub device: Id16, pub cert: DeviceCert }
pub struct OpFacts {
    pub op_id: OpId, pub opref: OpRef, pub lamport: u64, pub epoch: OpRef,
    pub creates_epoch: bool, pub body: OpBody, pub author_cert: DeviceCert,
    pub author_member_key: [u8; 48], pub approvals: Vec<VerifiedApproval>,
    pub forked: bool, pub pruned: bool,
}
pub struct AuthzInput<'a> {
    pub locker_id: Id16, pub genesis: OpId,
    pub ops: &'a [OpFacts], pub causality: &'a Causality,
}
pub enum Verdict { Accepted, Quarantined, Rejected, Pending }
pub trait AuthorizationState {
    fn verdict(&self, op: &OpId) -> Verdict;
    fn current_epoch(&self) -> Option<OpRef>;
    fn role(&self, member: &Id16) -> Option<RoleCode>;
    fn reader_devices(&self) -> Vec<DeviceCert>;
    fn device_active(&self, member: &Id16, device: &Id16) -> bool;
}
pub trait Authorizer {
    type State: AuthorizationState;
    fn evaluate(&self, input: &AuthzInput<'_>) -> Self::State;
}
```

Le contrat, détaillé dans la documentation du module :

- **Entrée** : toutes les opérations qui ont passé les étapes 1 à 8 du § 6, en ordre total
  (signature, certificat vérifié sous une clé de membre du journal, contenu descellé,
  dépendances, `prev`, `lamport`, structure du type, signatures des accords). Le graphe
  causal couvre aussi les opérations refusées à l'étape 8 et les souches.
- **Pureté** : `evaluate` est une fonction déterministe de l'ensemble reçu. Ni horloge, ni
  heure de réception, ni aléa. C'est ce qui fait converger les postes (§ 1.5).
- **Ce que l'autorisation décide** : tout le § 7.3, le § 7.4 (époque courante), le § 9
  (quarantaine, retraits concurrents, bifurcations, retrait d'appareil), les décisions de
  quarantaine.
- **Plancher tenu par la réplique**, quel que soit le verdict : une opération de contrôle
  bifurquée n'est jamais appliquée ; une `Compact` dont la liste n'est pas élaguable
  (§ 10.1) est rejetée.

`hirzla-sync` fournit une implémentation de référence en mémoire (`testing::MemoryAuthorizer`,
fonctionnalité `test-support`), qui suit le § 9.4 et sert d'oracle aux tests de convergence.

### 2. Ancrage de la genèse

- La réplique d'un casier est ouverte avec la genèse attendue (`op_id` de la `LockerCreate`)
  quand elle est connue : par l'invitation (`Grant` reçu hors bande, enrôlement § 14) ou par
  le casier personnel.
- Sinon, une seule `LockerCreate` reçue est ancrée d'office. Deux ou plus rendent la genèse
  **ambiguë** : tout reste en attente (statut 0) jusqu'à ce que la genèse soit fixée.
- Une opération qui est, ou descend d'une `LockerCreate` autre que la genèse ancrée, est
  rejetée (`ForeignGenesis`). Une opération qui ne descend pas de la genèse est rejetée aussi,
  sauf à travers une souche listée par une `Compact` signée (ADR 0017).

### 3. Époque des enveloppes

Les enveloppes d'une opération sont toujours pour l'époque de l'opération (`epoch`) : la
nouvelle époque pour `Revoke`, `Rotate`, `DeviceRemove` (scellées sous elle-même) ; l'époque
courante de l'auteur pour `Grant`, `DeviceAdd` et `EnvelopeAdd`. Seule l'opération qui crée
une époque en certifie la clé ; une clé reçue autrement reste une candidate.

## Conséquences

- Les deux caisses avancent en parallèle. `hirzla-access` peut reprendre l'implémentation de
  référence et ses tests.
- Toute la logique de rôles est derrière un seul appel par recalcul : l'implémentation doit
  rester rapide sur des milliers d'opérations (l'implémentation de référence rejoue l'état
  pour chaque opération, ce qui est quadratique).
- L'état d'autorisation exposé est celui de toutes les opérations appliquées ; un état « au
  passé de o » reste interne à l'implémentation.
- Une erreur de déterminisme dans l'implémentation casse la convergence sans erreur visible :
  les tests par propriétés de `hirzla-sync` doivent tourner aussi avec l'implémentation de
  `hirzla-access`.

## Alternatives écartées

- **`hirzla-sync` dépend de `hirzla-access`** : interdit par la consigne de l'étape 9, et
  impose qu'`access` connaisse les types de journal avant qu'ils existent.
- **Trait placé dans `hirzla-vault`** : le coffre ne connaît ni le graphe causal ni les
  corps de contrôle ; il faudrait y déplacer une grande part de `sync`.
- **Première `LockerCreate` reçue retenue** : dépend de l'ordre d'arrivée, donc pas de
  convergence, et un relais choisit la genèse.
- **Plus petit `op_id` retenu parmi plusieurs `LockerCreate`** : déterministe, mais un
  attaquant peut fabriquer une genèse de plus petit identifiant et capturer le casier.

## Décision du mainteneur (2026-11-15)

Accepté. Les opérations de contrôle et le calcul d'autorisation (§ 9.4) ont aussi été écrits
dans `hirzla-access` (étape 10). Le lot d'intégration garde une seule définition de
`ControlBody`, dans `hirzla-access`, que `hirzla-sync` réutilise ; `hirzla-sync` dépend
donc de `hirzla-access`, conformément au sens des dépendances de `CLAUDE.md`, et le trait
`Authorizer` est implémenté par un adaptateur au-dessus de `hirzla_access::authz`.
