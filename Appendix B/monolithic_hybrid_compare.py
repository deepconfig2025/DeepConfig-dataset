import json
import os
import ipaddress
import time
import traceback
from z3 import *

# ==========================================
# [Global Definitions] Z3 Types and Predicates
# ==========================================
RouterSort = DeclareSort('Router')
RTSort = DeclareSort('RT')
IPSort = IntSort()  # Using IntSort for integer optimization, significantly faster than BitVec

Ibgp_Neighbor = Function('Ibgp_Neighbor', RouterSort, RouterSort, BoolSort())
Has_Import_RT = Function('Has_Import_RT', RouterSort, RTSort, BoolSort())
Has_Export_RT = Function('Has_Export_RT', RouterSort, RTSort, BoolSort())

# Global predicate specifically for Monolithic Mode
Is_Prefix_Denied_Global = Function('Is_Prefix_Denied_Global', RouterSort, IPSort, BoolSort())


# ==========================================
# Helper Functions
# ==========================================
def ip_str_to_int(ip_str):
    if '/' in ip_str: ip_str = ip_str.split('/')[0]
    return int(ipaddress.IPv4Address(ip_str))


def get_ip_interval(prefix_str, mask_len):
    ip_int = ip_str_to_int(prefix_str)
    mask_bit = (0xFFFFFFFF << (32 - mask_len)) & 0xFFFFFFFF
    start_ip = ip_int & mask_bit
    size = 1 << (32 - mask_len)
    end_ip = start_ip + size - 1
    return start_ip, end_ip


def build_acl_logic(ip_var, rules):
    if not rules: return BoolVal(False)
    rule = rules[0]

    # Parse rule prefix and mask
    raw_prefix = rule.get('prefix', '0.0.0.0')
    if '/' in raw_prefix:
        p_str, m_str = raw_prefix.split('/')
        mask = int(m_str)
    else:
        p_str = raw_prefix
        mask = int(rule.get('mask', 32))

    start, end = get_ip_interval(p_str, mask)
    action_deny = (rule.get('action', 'permit') == 'deny')
    match_cond = And(ip_var >= start, ip_var <= end)

    # Recursive construction of nested If-Then-Else logic
    return If(match_cond, BoolVal(action_deny), build_acl_logic(ip_var, rules[1:]))


# ==========================================
# Base Constraint Loading (Topology & Config)
# ==========================================
def load_base_constraints(topo_file, config_file):
    print(f"[Init] Loading files...")
    with open(topo_file, 'r') as f:
        topo = json.load(f)
    with open(config_file, 'r') as f:
        conf = json.load(f)

    solver = Solver()
    r_map = {}
    all_routers = []

    # 1. Topology Nodes
    for node in topo['nodes']:
        nid = node['id']
        const = Const(nid, RouterSort)
        r_map[nid] = const
        all_routers.append(const)
    solver.add(Distinct(all_routers))

    # 2. Neighbor Relationships
    true_pairs = set()
    if 'ibgp_pe_mesh' in topo.get('bgp_sessions', {}):
        for s in topo['bgp_sessions']['ibgp_pe_mesh']:
            n1, n2 = s['nodes']
            if n1 in r_map and n2 in r_map:
                u, v = r_map[n1], r_map[n2]
                true_pairs.add((u, v));
                true_pairs.add((v, u))

    for r1 in all_routers:
        for r2 in all_routers:
            cond = (r1, r2) in true_pairs
            solver.add(Ibgp_Neighbor(r1, r2) == cond)

    # 3. VPN RT Configurations
    all_rt_strs = set()
    pe_conf_map = {}
    acl_db = {}  # Store raw ACL rules in Python dict

    for intent in conf['vpn_network_intents']:
        pe_id = intent['pe_id']
        pe_conf_map[pe_id] = intent
        for rt in intent.get('export_rt', []): all_rt_strs.add(rt)
        for rt in intent.get('import_rt', []): all_rt_strs.add(rt)
        # Store ACLs
        raw_filters = intent.get('import_route_filters', [])
        acl_db[pe_id] = sorted(raw_filters, key=lambda x: x.get('index', 0))

    rt_z3_map = {s: Const(f"rt_{s.replace(':', '_')}", RTSort) for s in all_rt_strs}
    if rt_z3_map: solver.add(Distinct(list(rt_z3_map.values())))

    for nid, r_const in r_map.items():
        if nid in pe_conf_map:
            c = pe_conf_map[nid]
            my_im = set(c.get('import_rt', []))
            my_ex = set(c.get('export_rt', []))
            for rt_str, rt_const in rt_z3_map.items():
                solver.add(Has_Import_RT(r_const, rt_const) == (rt_str in my_im))
                solver.add(Has_Export_RT(r_const, rt_const) == (rt_str in my_ex))
        else:
            acl_db[nid] = []  # No ACLs for nodes without config
            for rt_const in rt_z3_map.values():
                solver.add(Has_Import_RT(r_const, rt_const) == False)
                solver.add(Has_Export_RT(r_const, rt_const) == False)

    return solver, r_map, rt_z3_map, acl_db


# ==========================================
# Mode A: Monolithic Verification
# ==========================================
def run_monolithic_benchmark(base_solver, r_map, rt_map, acl_db):
    print("\n" + "=" * 60)
    print("   [Mode A] Monolithic Encoding (Full ACL Injection)")
    print("=" * 60)

    # Deep copy solver to avoid side effects
    s = base_solver.translate(base_solver.ctx)
    rt_val = Const('rt_val', RTSort)
    target_ip_var = Int('target_ip_var')
    s.add(target_ip_var >= 0, target_ip_var <= 4294967295)

    # --- 1. Inject ALL ACLs into Solver (Bottleneck!) ---
    t_start_inject = time.time()

    sym_ip = Const('sym_ip', IPSort)

    # Iterate all routers, burn ACL logic into global predicate Is_Prefix_Denied_Global
    count = 0
    for nid, rules in acl_db.items():
        r_const = r_map[nid]
        # Build logic tree
        acl_expr = build_acl_logic(sym_ip, rules)
        # Add Quantified Constraint (ForAll)
        s.add(ForAll([sym_ip], Is_Prefix_Denied_Global(r_const, sym_ip) == acl_expr))
        count += len(rules)

    t_end_inject = time.time()
    print(f"ACL Injection Time: {t_end_inject - t_start_inject:.4f} s (Total Rules: {count})")
    print(f"Current Constraint Count: {len(s.assertions())}")

    # --- 2. Execute Queries ---
    def check_mono(src_id, dst_id, ip_str):
        print(f"  Check {src_id}->{dst_id} IP={ip_str} ... ", end="", flush=True)
        s.push()
        src, dst = r_map[src_id], r_map[dst_id]
        ip_val = ip_str_to_int(ip_str)

        # Constraint: Target specific IP
        s.add(target_ip_var == ip_val)

        # Axiom: Call global predicate
        can_propagate = And(
            Ibgp_Neighbor(src, dst),
            Has_Export_RT(src, rt_val),
            Has_Import_RT(dst, rt_val),
            Not(Is_Prefix_Denied_Global(dst, target_ip_var))  # Global Call
        )
        s.add(can_propagate)

        t0 = time.time()
        res = s.check()
        dt = (time.time() - t0) * 1000
        print(f"{res} ({dt:.2f} ms)")
        s.pop()
        return dt

    total_time = 0
    if "PE1" in r_map and "PE2" in r_map:
        total_time += check_mono("PE1", "PE2", "192.168.1.1")  # Permit
        total_time += check_mono("PE2", "PE1", "10.0.1.100")   # Deny
        total_time += check_mono("PE2", "PE1", "10.0.99.1")    # Permit

    return total_time


# ==========================================
# Mode B: Hybrid/On-Demand Verification
# ==========================================
def run_hybrid_benchmark(base_solver, r_map, rt_map, acl_db):
    print("\n" + "=" * 60)
    print("   [Mode B] Hybrid/On-Demand Encoding (Lazy Injection)")
    print("=" * 60)

    s = base_solver.translate(base_solver.ctx)
    rt_val = Const('rt_val', RTSort)
    target_ip_var = Int('target_ip_var')
    s.add(target_ip_var >= 0, target_ip_var <= 4294967295)

    # Note: No global ACL injection here!
    print("Skipping global ACL injection...")

    # --- Execute Queries ---
    def check_hybrid(src_id, dst_id, ip_str):
        print(f"  Check {src_id}->{dst_id} IP={ip_str} ... ", end="", flush=True)
        s.push()
        src, dst = r_map[src_id], r_map[dst_id]
        ip_val = ip_str_to_int(ip_str)
        s.add(target_ip_var == ip_val)

        # Key Difference: Dynamically generate local logic, avoid global predicates
        rules = acl_db.get(dst_id, [])

        if rules:
            print(f"[Inject {len(rules)} ACLs] ... ", end="", flush=True)
        else:
            print(f"[No ACLs] ... ", end="", flush=True)

        # is_denied_expr is a temporary expression tree
        is_denied_expr = build_acl_logic(target_ip_var, rules)

        can_propagate = And(
            Ibgp_Neighbor(src, dst),
            Has_Export_RT(src, rt_val),
            Has_Import_RT(dst, rt_val),
            Not(is_denied_expr)  # Embed logic tree directly
        )
        s.add(can_propagate)

        t0 = time.time()
        res = s.check()
        dt = (time.time() - t0) * 1000
        print(f"{res} ({dt:.2f} ms)")
        s.pop()
        return dt

    total_time = 0
    if "PE1" in r_map and "PE2" in r_map:
        total_time += check_hybrid("PE2", "PE1", "192.168.1.1")
        total_time += check_hybrid("PE2", "PE1", "10.0.10.100")
        total_time += check_hybrid("PE2", "PE1", "10.0.99.1")

    return total_time


# ==========================================
# Main Execution
# ==========================================
if __name__ == "__main__":
    topo_file = "topo_10.txt"
    config_file = "config_10_30.txt"  # Ensure this file exists

    try:
        # 1. Prepare Base Environment (Topology + RT)
        s_base, r_map, rt_map, acl_db = load_base_constraints(topo_file, config_file)

        # 3. Run Hybrid Benchmark
        t_hybrid = run_hybrid_benchmark(s_base, r_map, rt_map, acl_db)

        # 2. Run Monolithic Benchmark
        t_mono = run_monolithic_benchmark(s_base, r_map, rt_map, acl_db)

        # 4. Results Comparison
        print("\n" + "=" * 60)
        print("       Performance Summary (Total time for 3 queries)")
        print("=" * 60)
        print(f"Monolithic (Full Injection) : {t_mono:.2f} ms")
        print(f"Hybrid     (On-Demand)      : {t_hybrid:.2f} ms")

        if t_hybrid > 0:
            speedup = t_mono / t_hybrid
            print(f"Speedup Factor              : {speedup:.2f} x")
        else:
            print("Hybrid is too fast to measure speedup factor.")

    except Exception as e:
        traceback.print_exc()
        print(f"\nExecution Error: {e}")