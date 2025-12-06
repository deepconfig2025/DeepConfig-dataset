# DeepConfig-dataset

## Intent List and Scoring Rules

### Table 1 – Intent Definitions

| ID  | Category                        | Informal Intent (What should hold)                                                                 | What the Verifier Checks (Pass condition)                                                                                          | Instance Scope                                                |
|-----|---------------------------------|-----------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------|
| I1  | Underlay reachability           | All P/PE loopbacks must be reachable over ISISv6 (no broken underlay links).                        | For all P/PE nodes x,y, SPF on ISISv6 has a path from loop(x) to loop(y); all P–PE links in `underlay.txt` are bidirectionally up. | All P/PE loopback pairs in each topology.                     |
| I2  | Intra-VPN CE–CE connectivity    | Any two CEs in the **same VPN** (e.g., CustA, CustB, …) can reach each other’s loopback.           | For each VPN v and any c1,c2 ∈ CE(v), data-plane reachability from loop(c1) to loop(c2) exists via their attached PEs.            | All unordered CE pairs within each VPN.                       |
| I3  | Inter-VPN isolation             | CEs belonging to **different VPNs** must not reach each other (no cross-VPN leakage).              | For v1 ≠ v2, any c1 ∈ CE(v1), c2 ∈ CE(v2): no forwarding path from loop(c1) to loop(c2); no FIB/RIB entry leaks prefixes across.  | All ordered CE pairs across different VPNs.                   |
| I4  | BGP VPN policy (RD/RT & VRF)    | RD/RT and VRFs are configured so that prefixes are visible only in the correct VPN and all sites.  | For each VPN v and CE c ∈ CE(v), every PE ∈ PE(v) has a VRF route to loop(c) with RT(v); no PE in any other VPN imports loop(c). | Each CE prefix on each PE VRF (visibility + non-leak).        |
| I5  | SRv6 TE path compliance         | For TE-enabled PE pairs (PEᵢ,PEⱼ), traffic must follow the SRv6 TE policy via the designated spine. | On PEᵢ, TE-PEᵢ-PEⱼ exists with endpoint=loop(PEⱼ), correct color and segment list [SID_Pm,SID_PEⱼ]; data paths CEᵢ→CEⱼ traverse Pm and match this SID order. | All TE-enabled PE pairs and their attached CE pairs.          |
| I6  | No blackholes for “reachable” CE | Any CE prefix that is declared reachable must not hit a data-plane blackhole.                      | For every CE-to-CE connectivity intent marked reachable by control-plane, step-by-step FIB simulation never encounters invalid next hops / missing interfaces. | All intra-VPN CE–CE intents that are expected to be reachable.|

---

### Table 2 – Scoring / Accuracy

| Metric                 | Definition                                                                                                      | Notes                                                                                                     |
|------------------------|-----------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| `pass(I)`              | For an intent instance I (of type I1–I6), `pass(I) = 1` if **all** relevant checks in Table 1 succeed, else 0. | “Relevant” = only the rule for that intent type (and any structural pre-checks like basic interface up). |
| `Accuracy`             | \\( \text{Accuracy} = \sum\_{I \in \mathcal{I}} \text{pass}(I) \, / \, |\mathcal{I}| \\)                        | 𝓘 = set of all instantiated intents (I1–I6) for a given topology and configuration.                      |
| `Accuracy_intra`       | Accuracy restricted to intents of type I2 (intra-VPN CE–CE connectivity).                                      | Optional per-category metric used in breakdown plots.                                                    |
| `Accuracy_inter`       | Accuracy restricted to intents of type I3 (inter-VPN isolation).                                               | Optional.                                                                                                |
| `Accuracy_TE`          | Accuracy restricted to intents of type I5 (SRv6 TE path compliance).                                           | Optional.                                                                                                |
| `Accuracy_BGP`         | Accuracy restricted to intents of type I4 (BGP VPN policy).                                                    | Optional.                                                                                                |
| `Accuracy_underlay`    | Accuracy restricted to intents of type I1 and I6 (underlay reachability + no blackholes).                     | Optional.                                                                                                |

**Ground truth.**  
All intents are instantiated from the hand-designed `overlay.txt`, `tunnel.txt`, `underlay.txt`, and the corresponding `parameter_list_*.yaml` files for each topology size (4/6, 10/20, 15/35, 20/55, 25/75). These files specify:

- which CE attaches to which PE and VPN (overlay),  
- which PE–PE pairs are TE-enabled and which spine they must traverse (tunnel),  
- underlay links between P/PE (underlay),  
- concrete IPs, RDs, RTs, SIDs, colors, and interfaces (parameter lists).

Accuracy measures how often a generated configuration reproduces this **known-correct behavior**.
